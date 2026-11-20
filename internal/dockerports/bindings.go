package dockerports

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

type Binding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// Bindings maps container ports (e.g. "53/udp") to their host bindings.
type Bindings map[string][]Binding

// Read inspects the given container. A nil result means the bindings could not be verified.
func Read(ctx context.Context, host, self string) Bindings {
	if self == "" {
		return nil
	}
	hc, base, err := proxmox.DockerClient(host)
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
			Ports map[string][]Binding `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&in) != nil {
		return nil
	}
	return in.NetworkSettings.Ports
}

// Has reports a binding on hostPort that is not restricted to loopback.
func (b Bindings) Has(key string, hostPort int) bool {
	for _, binding := range b[key] {
		if addr, err := netip.ParseAddr(binding.HostIP); err == nil && addr.Unmap().IsLoopback() {
			continue
		}
		if binding.HostPort == strconv.Itoa(hostPort) {
			return true
		}
	}
	return false
}
