package edge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Docker-Bridge-Netz: HTTP- und HTTPS-Port gelten als veroeffentlicht, wenn die Pruefanfrage ueber das Gateway beim
// eigenen Eingang ankommt; ein anderes Programm am Port des Hosts zaehlt nicht.
func TestPublished(t *testing.T) {
	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: http.NotFoundHandler(), HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE64_DOCKER_HOST", "unavailable")
	t.Setenv(probeIPEnv, "")
	oldNet, oldGw := bridgeNet, bridgeGateway
	defer func() { bridgeNet, bridgeGateway = oldNet, oldGw }()
	gw := netip.MustParseAddr("127.0.0.1")
	bridgeGateway = func() netip.Addr { return gw }
	ctx := context.Background()

	bridgeNet = func() bool { return false }
	if p := e.Published(ctx); p.Bridge || len(p.Missing) != 0 {
		t.Fatalf("host network: %+v", p)
	}
	bridgeNet = func() bool { return true }
	if p := e.Published(ctx); !p.Bridge || p.Publication(cfg.HTTPPort) != "yes" || p.Publication(cfg.HTTPSPort) != "yes" || p.Gateway != "127.0.0.1" {
		t.Fatalf("published: %+v", p)
	}

	// The gateway cannot reach the listeners and the Docker API is unavailable.
	gw = netip.MustParseAddr("127.0.0.2")
	p := e.Published(ctx)
	if len(p.Missing) != 0 || p.Publication(cfg.HTTPPort) != "unknown" || p.Publication(cfg.HTTPSPort) != "unknown" || p.RunArgs() != "" {
		t.Fatalf("unknown publication: %+v", p)
	}

	// An explicit target reaches the listeners even when the gateway cannot.
	t.Setenv(probeIPEnv, "127.0.0.1")
	p = e.Published(ctx)
	if p.Publication(cfg.HTTPPort) != "yes" || p.Publication(cfg.HTTPSPort) != "yes" || p.Gateway != gw.String() {
		t.Fatalf("explicit probe target: %+v", p)
	}
	t.Setenv(probeIPEnv, "")

	cfg.PublicPort = cfg.HTTPSPort%65535 + 1
	if err := e.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	var empty atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if empty.Load() {
			fmt.Fprint(w, `{"NetworkSettings":{"Ports":{}}}`)
			return
		}
		fmt.Fprintf(w, `{"NetworkSettings":{"Ports":{"%d/tcp":[{"HostIp":"0.0.0.0","HostPort":"%d"}],"%d/tcp":[{"HostIp":"192.168.1.3","HostPort":"%d"}]}}}`,
			cfg.HTTPPort, cfg.HTTPPort, cfg.HTTPSPort, cfg.publicPort())
	}))
	defer srv.Close()
	t.Setenv("NODE64_DOCKER_HOST", srv.URL)
	e.pub.Store(nil)
	p = e.Published(ctx)
	if p.Publication(cfg.HTTPPort) != "yes" || p.Publication(cfg.HTTPSPort) != "yes" || len(p.Missing) != 0 {
		t.Fatalf("Docker mappings without gateway access: %+v", p)
	}

	empty.Store(true)
	e.pub.Store(nil)
	p = e.Published(ctx)
	if len(p.Missing) != 2 || !p.MissingPort(cfg.HTTPPort) || !p.MissingPort(cfg.HTTPSPort) {
		t.Fatalf("not published: %+v", p)
	}
	h, s := strconv.Itoa(cfg.HTTPPort), strconv.Itoa(cfg.HTTPSPort)
	want := "-p " + h + ":" + h + " -p " + s + ":" + s // nach Port sortiert
	if cfg.HTTPSPort < cfg.HTTPPort {
		want = "-p " + s + ":" + s + " -p " + h + ":" + h
	}
	if a := p.RunArgs(); a != want+" -p "+s+":"+s+"/udp" {
		t.Fatalf("run args: %q", a)
	}
	if c := p.Compose(); !strings.HasPrefix(c, "    ports:\n") || !strings.Contains(c, "      - \""+h+":"+h+"\"\n") || !strings.HasSuffix(c, "/udp\"") {
		t.Fatalf("compose: %q", c)
	}
	// unbekannter Pruefwert: normale Antwort des Eingangs
	resp, err := http.Get("http://127.0.0.1:" + h + probePath + "0123")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("unknown probe answered as hit")
	}
}
