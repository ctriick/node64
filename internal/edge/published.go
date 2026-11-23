package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker-Bridge-Netz: Lauschen im Container reicht fuer PROXY64 nicht, HTTP- und HTTPS-Port muessen auf dem
// Docker-Host veroeffentlicht sein (-p 80:80 -p 443:443 bzw. ports: in compose). Die Pruefung schickt eine Anfrage mit
// Pruefwert ueber das Gateway (den Docker-Host) an denselben Port; kommt sie beim eigenen Listener an, ist der Port
// veroeffentlicht (Hairpin, siehe localnet.Gateway). Ein anderes Programm auf dem Host antwortet nicht mit dem
// Pruefwert und zaehlt deshalb nicht.
// Nicht jeder Docker-Host leitet Anfragen aus dem Bridge-Netz ueber das Gateway zurueck (UFW auf dem Host, DNAT nur
// fuer fremde Schnittstellen, #243). Kommt die Pruefanfrage nicht an, entscheiden die Port-Bindings des eigenen
// Containers (Docker-API, falls erreichbar). Ohne Docker-API fehlt ein Port nur, wenn der Host die Verbindung abgelehnt
// oder ein anderes Programm geantwortet hat; eine Zeitueberschreitung beweist nichts - der Port gilt dann als nicht
// pruefbar (Unknown, keine Warnung).
const (
	probePath   = "/.well-known/node64-probe/"
	probeSuffix = ".probe.node64.invalid"
	probeTTL    = time.Minute
	probeWait   = 3 * time.Second
)

// Tests: feste Werte statt der Erkennung im Container.
var (
	bridgeNet     = localnet.Bridge
	bridgeGateway = localnet.Gateway
)

// Published ist das Ergebnis der Pruefung.
type Published struct {
	Bridge  bool             `json:"bridge"`
	Gateway string           `json:"gateway,omitempty"`
	Missing []ListenerStatus `json:"missing,omitempty"`
	Unknown []ListenerStatus `json:"unknown,omitempty"`
	Found   []int            `json:"found,omitempty"`
	H3Port  int              `json:"h3_port,omitempty"`
	At      time.Time        `json:"at"`
}

// PortState: Ergebnis fuer einen TCP-Port des Eingangs.
func (p Published) PortState(port int) string {
	if p.MissingPort(port) {
		return "no"
	}
	for _, l := range p.Unknown {
		if l.Port == port {
			return "unknown"
		}
	}
	for _, f := range p.Found {
		if f == port {
			return "yes"
		}
	}
	return ""
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

// PortList: die fehlenden Ports fuer den Text ("80 und 443" als "80, 443").
func (p Published) PortList() string {
	out := make([]string, len(p.Missing))
	for i, l := range p.Missing {
		out[i] = strconv.Itoa(l.Port)
	}
	return strings.Join(out, ", ")
}

// publish: die Portangaben fuer docker run bzw. compose.
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
	key        string
	res        Published
	refreshing bool // Background-Aktualisierung fuer diesen Cache-Eintrag laeuft.
}

type probeResult int

const (
	probeVague probeResult = iota
	probeHit
	probeOther
)

var (
	pubDockerHost = proxmox.DefaultDockerHost
	pubSelf       = os.Hostname
)

type pubBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// pubBindings liest die Port-Bindings des eigenen Containers; nil, wenn Docker-API nicht erreichbar.
func pubBindings(ctx context.Context) map[string][]pubBinding {
	self, err := pubSelf()
	if err != nil || self == "" {
		return nil
	}
	hc, base, err := proxmox.DockerClient(pubDockerHost())
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/containers/"+url.PathEscape(self)+"/json", nil)
	if err != nil {
		return nil
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var in struct {
		NetworkSettings struct {
			Ports map[string][]pubBinding `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&in) != nil {
		return nil
	}
	if in.NetworkSettings.Ports == nil {
		return map[string][]pubBinding{}
	}
	return in.NetworkSettings.Ports
}

// pubBound: Port des Containers ist laut Binding auf dem Host unter einer der Nummern veroeffentlicht.
func pubBound(b map[string][]pubBinding, port int, hostPorts ...int) bool {
	for _, x := range b[strconv.Itoa(port)+"/tcp"] {
		if a, err := netip.ParseAddr(x.HostIP); err == nil && a.Unmap().IsLoopback() {
			continue
		}
		for _, hp := range hostPorts {
			if x.HostPort == strconv.Itoa(hp) {
				return true
			}
		}
	}
	return false
}

// Published liefert den letzten bekannten Status sofort und aktualisiert abgelaufene Ergebnisse
// im Hintergrund. Auch beim ersten Aufruf wird nicht auf Gateway-Probes gewartet.
func (e *Edge) Published(_ context.Context) Published {
	if !bridgeNet() {
		return Published{}
	}
	gw := bridgeGateway()
	st := e.Status()
	key := gw.String()
	h3 := 0
	for _, l := range st.Listeners {
		if !l.Running {
			continue
		}
		if l.Name == "http3" {
			h3 = l.Port
			continue
		}
		key += " " + l.Name + ":" + strconv.Itoa(l.Port)
	}
	key += " " + strconv.Itoa(st.Config.publicPort())

	for {
		previous := e.pub.Load()
		if previous != nil && previous.key == key {
			if previous.refreshing || (!previous.res.At.IsZero() && time.Since(previous.res.At) < probeTTL) {
				return previous.res
			}
		}

		// Bei Konfigurationsaenderung keine alten Portwarnungen anzeigen.
		res := Published{Bridge: true, H3Port: h3}
		if gw.IsValid() {
			res.Gateway = gw.String()
		}
		if previous != nil && previous.key == key {
			res = previous.res
		}
		busy := &pubCache{key: key, res: res, refreshing: true}
		if !e.pub.CompareAndSwap(previous, busy) {
			continue
		}

		go func(expected *pubCache) {
			// Unabhaengig von der HTTP-Anfrage; bricht spaetestens nach 12 Sekunden ab.
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			fresh := e.publishedCheck(ctx, gw, st.Listeners, st.Config.publicPort(), h3)
			// Ergebnis nur uebernehmen, wenn nicht inzwischen eine neue Konfiguration aktiv ist.
			e.pub.CompareAndSwap(expected, &pubCache{key: key, res: fresh})
		}(busy)
		return res
	}
}

// publishedCheck prueft Gateway und Docker-Bindings ohne den Seitenaufruf zu blockieren.
func (e *Edge) publishedCheck(ctx context.Context, gw netip.Addr, listeners []ListenerStatus, pub int, h3 int) Published {
	var run []ListenerStatus
	for _, l := range listeners {
		if !l.Running {
			continue
		}
		if l.Name == "http3" {
			continue
		}
		run = append(run, l)
	}
	res := Published{Bridge: true, H3Port: h3}
	if gw.IsValid() {
		res.Gateway = gw.String()
	}
	out := make([]probeResult, len(run))
	var wg sync.WaitGroup
	for i, l := range run {
		if !gw.IsValid() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = e.probe(ctx, gw, l.Name, l.Port)
			if out[i] != probeHit && l.Name == "https" && pub != l.Port {
				if r := e.probe(ctx, gw, l.Name, pub); r != probeOther {
					out[i] = r
				}
			}
		}()
	}
	wg.Wait()
	var binds map[string][]pubBinding
	loaded := false
	for i, l := range run {
		if out[i] != probeHit {
			if !loaded {
				binds, loaded = pubBindings(ctx), true
			}
			switch {
			case pubBound(binds, l.Port, l.Port, pub):
				out[i] = probeHit
			case binds != nil:
				out[i] = probeOther
			}
		}
		switch out[i] {
		case probeHit:
			res.Found = append(res.Found, l.Port)
		case probeOther:
			res.Missing = append(res.Missing, l)
		default:
			res.Unknown = append(res.Unknown, l)
		}
	}
	sort.Slice(res.Missing, func(i, j int) bool { return res.Missing[i].Port < res.Missing[j].Port })
	res.At = time.Now()
	return res
}

// probe schickt eine Pruefanfrage an gw:port und meldet, ob sie beim eigenen Listener ankam.
func (e *Edge) probe(ctx context.Context, gw netip.Addr, name string, port int) probeResult {
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	e.probes.Store(nonce, false)
	defer e.probes.Delete(nonce)
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	addr := net.JoinHostPort(gw.String(), strconv.Itoa(port))
	var err error
	if name == "http" {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+probePath+nonce, nil)
		if rerr != nil {
			return probeVague
		}
		req.Host = "probe" + probeSuffix
		cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var resp *http.Response
		if resp, err = cl.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	} else {
		d := tls.Dialer{Config: &tls.Config{ServerName: nonce + probeSuffix, InsecureSkipVerify: true}}
		var c net.Conn
		if c, err = d.DialContext(ctx, "tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	if v, _ := e.probes.Load(nonce); v == true {
		return probeHit
	}
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		return probeOther
	}
	return probeVague
}

// probeHit vermerkt eine angekommene Pruefanfrage.
func (e *Edge) probeHit(nonce string) bool { return e.probes.CompareAndSwap(nonce, false, true) }

// BridgeForTest setzt Erkennung und Gateway fuer Tests anderer Pakete.
func BridgeForTest(bridge bool, gw netip.Addr) (restore func()) {
	oldNet, oldGw := bridgeNet, bridgeGateway
	bridgeNet, bridgeGateway = func() bool { return bridge }, func() netip.Addr { return gw }
	return func() { bridgeNet, bridgeGateway = oldNet, oldGw }
}
