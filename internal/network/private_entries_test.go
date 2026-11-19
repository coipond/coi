package network

import (
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestBlockedPrivateEntries(t *testing.T) {
	tuples := []staticTuple{
		{CIDR: "192.168.1.50/32", Ports: []portRange{{Lo: 5000, Hi: 5000}}}, // private IP
		{CIDR: "172.16.0.0/16"},      // private CIDR
		{CIDR: "10.0.0.0/7"},         // partly private
		{CIDR: "172.0.0.0/8"},        // starts outside 172.16.0.0/12
		{CIDR: "169.254.169.254/32"}, // link-local only
		{CIDR: "1.2.3.4/32"},         // public
		{CIDR: "11.0.0.0/8"},         // public, next to 10/8
		{CIDR: "192.168.1.10/32", Ports: []portRange{{Lo: 8080, Hi: 8080}}}, // skipped
	}
	want := []blockedEntry{
		{Entry: "192.168.1.50", RFC1918: true},
		{Entry: "172.16.0.0/16", RFC1918: true},
		{Entry: "10.0.0.0/7", RFC1918: true},
		{Entry: "172.0.0.0/8", RFC1918: true},
		{Entry: "169.254.169.254"},
	}
	if got := blockedPrivateEntries(tuples, map[string]bool{"192.168.1.10": true}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestAllowlistPrivateWarnings(t *testing.T) {
	stubHostAddrs(t, "192.168.1.10")
	on := true
	cfg := func() *config.NetworkConfig {
		return &config.NetworkConfig{
			Mode: config.NetworkModeAllowlist,
			AllowedDomains: []string{
				"192.168.1.50:5000", "10.0.0.0/7", "169.254.169.254", "1.2.3.4:443", "github.com",
				"192.168.1.10:8080", // host address
				"192.168.1.60:5000", // opened by [[network.hosts]]
				"192.168.1.70:5000", // [[network.hosts]] opens other ports
				"192.168.1.80",      // all ports; [[network.hosts]] opens one
			},
			Hosts: []config.HostEntry{
				{IP: "192.168.1.60", Hostnames: []string{"svc"}, Ports: []int{5000}},
				{IP: "192.168.1.60", Hostnames: []string{"svc2"}, Ports: []int{22}},
				{IP: "192.168.1.70", Hostnames: []string{"other"}, Ports: []int{22}},
				{IP: "192.168.1.80", Hostnames: []string{"one"}, Ports: []int{443}},
			},
		}
	}

	got := AllowlistPrivateWarnings(cfg())
	if len(got) != 5 {
		t.Fatalf("want 5 warnings, got %d: %q", len(got), got)
	}
	for i, entry := range []string{"192.168.1.50", "10.0.0.0/7", "", "192.168.1.70", "192.168.1.80"} {
		if entry == "" {
			continue
		}
		if !strings.Contains(got[i], "entry "+entry+" ") ||
			!strings.Contains(got[i], "allow_local_network_access = true") ||
			!strings.Contains(got[i], "[[network.hosts]]") {
			t.Errorf("warning %d: %q", i, got[i])
		}
	}
	// [[network.hosts]] refuses 169.254.0.0/16 in allowlist mode.
	if !strings.Contains(got[2], "entry 169.254.169.254 ") ||
		!strings.Contains(got[2], "allow_local_network_access = true") ||
		strings.Contains(got[2], "network.hosts") {
		t.Errorf("link-local warning: %q", got[2])
	}

	c := cfg()
	c.AllowLocalNetworkAccess = &on
	if got := AllowlistPrivateWarnings(c); len(got) != 0 {
		t.Errorf("allow_local_network_access: want no warning, got %q", got)
	}
	// allowed_ports is what both sides inherit when they name no ports.
	c = cfg()
	c.AllowedPorts = []int{443}
	c.AllowedDomains = []string{"192.168.1.80"}
	if got := AllowlistPrivateWarnings(c); len(got) != 0 {
		t.Errorf("entry on allowed_ports opened by [[network.hosts]]: want no warning, got %q", got)
	}
	c.Hosts = []config.HostEntry{{IP: "192.168.1.80", Hostnames: []string{"one"}}}
	if got := AllowlistPrivateWarnings(c); len(got) != 0 {
		t.Errorf("both on allowed_ports: want no warning, got %q", got)
	}

	c = cfg()
	c.Mode = config.NetworkModeRestricted
	if got := AllowlistPrivateWarnings(c); len(got) != 0 {
		t.Errorf("restricted mode: want no warning, got %q", got)
	}
	c = cfg()
	c.AllowedDomains = append(c.AllowedDomains, "*.example.com")
	if got := AllowlistPrivateWarnings(c); len(got) != 0 {
		t.Errorf("invalid allowed_domains: want no warning, got %q", got)
	}
}

func TestPortsCover(t *testing.T) {
	have := []portRange{{Lo: 8000, Hi: 8100}, {Lo: 22, Hi: 22}, {Lo: 8101, Hi: 8200}}
	for _, tc := range []struct {
		want []portRange
		ok   bool
	}{
		{[]portRange{{Lo: 22, Hi: 22}}, true},
		{[]portRange{{Lo: 8050, Hi: 8150}}, true}, // spans two adjacent ranges
		{[]portRange{{Lo: 22, Hi: 23}}, false},
		{[]portRange{{Lo: 22, Hi: 22}, {Lo: 443, Hi: 443}}, false},
		{allPortsRange(), false},
	} {
		if got := portsCover(have, tc.want); got != tc.ok {
			t.Errorf("portsCover(%v) = %v, want %v", tc.want, got, tc.ok)
		}
	}
	// Out of order: 8101-8200 comes first, so only a second pass over have
	// reaches it.
	if !portsCover([]portRange{{Lo: 8101, Hi: 8200}, {Lo: 8000, Hi: 8100}}, []portRange{{Lo: 8050, Hi: 8150}}) {
		t.Error("ranges out of order cover 8050-8150")
	}
	if !portsCover(allPortsRange(), []portRange{{Lo: 65535, Hi: 65535}}) {
		t.Error("all ports cover 65535")
	}
}
