package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/dockerports"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker bindings and gateway probes provide evidence of publication. A failed
// gateway probe alone is inconclusive because hairpin NAT may be unavailable.
const (
	probeIPEnv = "NODE64_PROXY_PROBE_IP"
	probePath   = "/.well-known/node64-probe/" // Port 80: Pfad mit Pruefwert
	probeSuffix = ".probe.node64.invalid"      // Port 443: Pruefwert als SNI-Name
	probeTTL    = time.Minute                  // Ergebnis so lange wiederverwenden (Seitenaufrufe)
	probeWait   = 3 * time.Second
)

// Tests: feste Werte statt der Erkennung im Container.
var (
	bridgeNet     = localnet.Bridge
	bridgeGateway = localnet.Gateway
)

// Published ist das Ergebnis der Pruefung.
type Published struct {
	Bridge   bool             `json:"bridge"`            // Container im Bridge-Netz (sonst ist nichts zu pruefen)
	Gateway  string           `json:"gateway,omitempty"` // Docker-Host
	Verified []ListenerStatus `json:"verified,omitempty"`
	Unknown  []ListenerStatus `json:"unknown,omitempty"`
	Missing  []ListenerStatus `json:"missing,omitempty"` // laufende Dienste (http, https), deren Port auf dem Host fehlt
	H3Port   int              `json:"h3_port,omitempty"` // HTTP/3 laeuft (UDP, nur fuer das Beispiel)
	At       time.Time        `json:"at"`
}

// MissingPort: der TCP-Port des Eingangs ist auf dem Host nicht veroeffentlicht.
func (p Published) MissingPort(port int) bool {
	for _, l := range p.Missing {
		if l.Port == port {
			return true
		}
	}
	return false
}

// Publication returns the status of a checked TCP port, or an empty string if
// the port was outside the scope of the check.
func (p Published) Publication(port int) string {
	if p.MissingPort(port) {
		return "no"
	}
	for _, l := range p.Verified {
		if l.Port == port {
			return "yes"
		}
	}
	for _, l := range p.Unknown {
		if l.Port == port {
			return "unknown"
		}
	}
	return ""
}

// PortList: die fehlenden Ports fuer den Text ("80 und 443" als "80, 443").
func (p Published) PortList() string {
	out := make([]string, len(p.Missing))
	for i, l := range p.Missing {
		out[i] = strconv.Itoa(l.Port)
	}
	return strings.Join(out, ", ")
}

// publish: die Portangaben fuer docker run bzw. compose (fehlende TCP-Ports, dazu HTTP/3 per UDP).
func (p Published) publish() []string {
	var out []string
	for _, l := range p.Missing {
		out = append(out, strconv.Itoa(l.Port)+":"+strconv.Itoa(l.Port))
	}
	if p.H3Port > 0 && len(p.Missing) > 0 {
		out = append(out, strconv.Itoa(p.H3Port)+":"+strconv.Itoa(p.H3Port)+"/udp")
	}
	return out
}

// RunArgs: "-p 80:80 -p 443:443 -p 443:443/udp" fuer docker run.
func (p Published) RunArgs() string {
	var b strings.Builder
	for i, a := range p.publish() {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("-p " + a)
	}
	return b.String()
}

// Compose: der ports-Abschnitt fuer docker-compose.yml.
func (p Published) Compose() string {
	b := "    ports:\n"
	for _, a := range p.publish() {
		b += "      - \"" + a + "\"\n"
	}
	return strings.TrimSuffix(b, "\n")
}

type pubCache struct {
	key string
	res Published
}

// Published prueft (hoechstens einmal je Minute bei gleichen Ports), ob HTTP- und HTTPS-Port des Eingangs auf dem
// Docker-Host veroeffentlicht sind. Ausserhalb des Bridge-Netzes leer.
func (e *Edge) Published(ctx context.Context) Published {
	if !bridgeNet() {
		return Published{}
	}
	gw := bridgeGateway()
	probeIP, _ := netip.ParseAddr(strings.TrimSpace(os.Getenv(probeIPEnv)))
	override := probeIP.IsValid() && !probeIP.IsUnspecified() && !probeIP.IsMulticast() && probeIP.Zone() == ""
	if !override {
		probeIP = gw
	}
	st := e.Status()
	key := gw.String() + " " + probeIP.String() + " " + strconv.FormatBool(override)
	var run []ListenerStatus
	h3 := 0
	for _, l := range st.Listeners {
		if !l.Running {
			continue
		}
		if l.Name == "http3" {
			h3 = l.Port
			continue
		}
		run = append(run, l)
		key += " " + l.Name + ":" + strconv.Itoa(l.Port)
	}
	pub := st.Config.publicPort()
	key += " " + strconv.Itoa(pub) + " " + strconv.Itoa(h3)
	if c := e.pub.Load(); c != nil && c.key == key && time.Since(c.res.At) < probeTTL {
		return c.res
	}
	res := Published{Bridge: true, H3Port: h3, At: time.Now()}
	if gw.IsValid() {
		res.Gateway = gw.String()
	}
	if len(run) > 0 {
		var binds dockerports.Bindings
		if self, err := os.Hostname(); err == nil {
			binds = dockerports.Read(ctx, proxmox.DefaultDockerHost(), self)
		}
		verified := make([]bool, len(run))
		var wg sync.WaitGroup
		for i, l := range run {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := strconv.Itoa(l.Port) + "/tcp"
				alternate := l.Name == "https" && pub != l.Port
				verified[i] = binds.Has(key, l.Port) || (alternate && binds.Has(key, pub))
				if override {
					port := l.Port
					if l.Name == "https" {
						port = pub
					}
					verified[i] = e.probe(ctx, probeIP, l.Name, port) || verified[i]
				} else if !verified[i] && probeIP.IsValid() {
					verified[i] = e.probe(ctx, probeIP, l.Name, l.Port) || (alternate && e.probe(ctx, probeIP, l.Name, pub))
				}
			}()
		}
		wg.Wait()
		for i, l := range run {
			switch {
			case verified[i]:
				res.Verified = append(res.Verified, l)
			case binds != nil:
				res.Missing = append(res.Missing, l)
			default:
				res.Unknown = append(res.Unknown, l)
			}
		}
		sort.Slice(res.Missing, func(i, j int) bool { return res.Missing[i].Port < res.Missing[j].Port })
	}
	if ctx.Err() != nil {
		return res
	}
	e.pub.Store(&pubCache{key: key, res: res})
	return res
}

// probe schickt eine Pruefanfrage an gw:port und meldet, ob sie beim eigenen Listener ankam.
func (e *Edge) probe(ctx context.Context, gw netip.Addr, name string, port int) bool {
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	e.probes.Store(nonce, false)
	defer e.probes.Delete(nonce)
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	addr := net.JoinHostPort(gw.String(), strconv.Itoa(port))
	if name == "http" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+probePath+nonce, nil)
		if err != nil {
			return false
		}
		req.Host = "probe" + probeSuffix
		cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if resp, err := cl.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	} else {
		d := tls.Dialer{Config: &tls.Config{ServerName: nonce + probeSuffix, InsecureSkipVerify: true}} // nur der Name zaehlt
		if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	v, _ := e.probes.Load(nonce)
	return v == true
}

// probeHit vermerkt eine angekommene Pruefanfrage (false = kein offener Pruefwert).
func (e *Edge) probeHit(nonce string) bool {
	return e.probes.CompareAndSwap(nonce, false, true)
}

// BridgeForTest setzt Erkennung und Gateway fuer Tests anderer Pakete; restore stellt beides wieder her.
func BridgeForTest(bridge bool, gw netip.Addr) (restore func()) {
	oldNet, oldGw := bridgeNet, bridgeGateway
	bridgeNet, bridgeGateway = func() bool { return bridge }, func() netip.Addr { return gw }
	return func() { bridgeNet, bridgeGateway = oldNet, oldGw }
}
