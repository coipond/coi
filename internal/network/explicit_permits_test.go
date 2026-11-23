package network

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestExplicitPortPermits(t *testing.T) {
	policy, err := NewAllowPolicy([]string{
		"203.0.113.10:8080",
		"198.51.100.0/24:1230-1240",
		"203.0.113.20",
		"proxy.example.com:3128",
		"api.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved := map[string][]string{
		"proxy.example.com": {"203.0.113.30"},
		"api.example.com":   {"203.0.113.40"},
	}
	hosts := []config.HostEntry{
		{IP: "192.168.1.50", Ports: []int{8080}},
		{IP: "192.168.1.60"},
	}
	p := NewExplicitPortPermits("c", hosts, policy, resolved)
	for _, tc := range []struct {
		proto string
		ip    string
		port  int
		want  bool
	}{
		{"tcp", "192.168.1.50", 8080, true},   // host entry with ports
		{"TCP", "192.168.1.50", 8080, true},   // nft logs upper case
		{"udp6", "192.168.1.50", 8080, true},  // procfs udp6 socket
		{"tcp", "192.168.1.50", 4444, false},  // another port on that host
		{"tcp", "192.168.1.60", 8080, false},  // host entry without ports
		{"tcp", "192.168.1.70", 8080, false},  // unlisted host
		{"icmp", "192.168.1.50", 8080, false}, // no ports outside TCP/UDP
		{"tcp", "203.0.113.10", 8080, true},   // allowed_domains address:port
		{"tcp", "203.0.113.10", 5555, false},  // another port on it
		{"tcp", "198.51.100.7", 1234, true},   // CIDR with a port range
		{"tcp", "198.51.100.7", 4444, false},  // outside the range
		{"tcp", "203.0.113.20", 8080, false},  // entry without :ports
		{"tcp", "203.0.113.30", 3128, true},   // name:port, resolved
		{"tcp", "203.0.113.30", 8080, false},  // another port on the name
		{"tcp", "203.0.113.40", 8080, false},  // name without :ports
		{"tcp", "not-an-ip", 8080, false},     // unparsable address
		{"tcp", "2001:db8::1", 8080, false},   // IPv6
	} {
		if got := p.Permits(tc.proto, tc.ip, tc.port); got != tc.want {
			t.Errorf("Permits(%q, %q, %d) = %t, want %t", tc.proto, tc.ip, tc.port, got, tc.want)
		}
	}
}

// Outside allowlist mode there is no policy; only host entries count.
func TestExplicitPortPermits_NoPolicy(t *testing.T) {
	p := NewExplicitPortPermits("c", []config.HostEntry{{IP: "10.0.0.5", Ports: []int{8080}}}, nil, nil)
	if !p.Permits("tcp", "10.0.0.5", 8080) {
		t.Error("host entry with ports should permit its port")
	}
	if p.Permits("tcp", "10.0.0.5", 8081) {
		t.Error("another port must not be permitted")
	}
	if NewExplicitPortPermits("c", nil, nil, nil).Permits("tcp", "10.0.0.5", 8080) {
		t.Error("no entries must permit nothing")
	}
}

// stubRefreshSources replaces what refresh reads for the test.
func stubRefreshSources(t *testing.T, domains map[string][]string, runtime string) {
	t.Helper()
	origLoad, origRead := loadNameAddresses, readRuntimeHostPorts
	t.Cleanup(func() { loadNameAddresses, readRuntimeHostPorts = origLoad, origRead })
	loadNameAddresses = func(string) (map[string][]string, error) { return domains, nil }
	readRuntimeHostPorts = func(string) (string, error) { return runtime, nil }
}

// A name permit follows the addresses the firewall installs for the name, also
// when the monitor's own lookup at start failed. Addresses seen earlier stay
// permitted (the firewall keeps them for a grace period).
func TestExplicitPortPermits_NameFollowsFirewallAddresses(t *testing.T) {
	policy, err := NewAllowPolicy([]string{"proxy.example.com:8080", "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	p := NewExplicitPortPermits("c", nil, policy, map[string][]string{"proxy.example.com": {"203.0.113.30"}})
	if p.Permits("tcp", "203.0.113.31", 8080) {
		t.Fatal("an address the firewall has not installed yet must not be permitted")
	}
	stubRefreshSources(t, map[string][]string{
		"proxy.example.com": {"203.0.113.31"},
		"api.example.com":   {"203.0.113.40"},
	}, "")
	p.refresh()
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"203.0.113.31", 8080, true},  // the new answer
		{"203.0.113.30", 8080, true},  // the earlier answer
		{"203.0.113.31", 4444, false}, // another port
		{"203.0.113.40", 8080, false}, // a name without :ports
	} {
		if got := p.Permits("tcp", tc.ip, tc.port); got != tc.want {
			t.Errorf("%s:%d = %t, want %t", tc.ip, tc.port, got, tc.want)
		}
	}

	failedAtStart := NewExplicitPortPermits("c", nil, policy, nil)
	failedAtStart.refresh()
	if !failedAtStart.Permits("tcp", "203.0.113.31", 8080) {
		t.Error("a lookup failed at monitor start must not drop the permit once the firewall's addresses are read")
	}
}

// `coi hosts add --ports` permits are read from the container at refresh.
func TestExplicitPortPermits_RuntimeHosts(t *testing.T) {
	p := NewExplicitPortPermits("c", nil, nil, nil)
	stubRefreshSources(t, nil, "10.0.0.9=8080,443 bad 10.0.0.10=x 10.0.0.11=")
	if p.Permits("tcp", "10.0.0.9", 8080) {
		t.Fatal("nothing is permitted before the first read")
	}
	p.refresh()
	for _, tc := range []struct {
		ip   string
		port int
		want bool
	}{
		{"10.0.0.9", 8080, true},
		{"10.0.0.9", 443, true},
		{"10.0.0.9", 4444, false},
		{"10.0.0.10", 8080, false},
		{"10.0.0.11", 8080, false},
	} {
		if got := p.Permits("tcp", tc.ip, tc.port); got != tc.want {
			t.Errorf("%s:%d = %t, want %t", tc.ip, tc.port, got, tc.want)
		}
	}
	readRuntimeHostPorts = func(string) (string, error) { return "", errors.New("incus down") }
	p.refresh()
	if !p.Permits("tcp", "10.0.0.9", 8080) {
		t.Error("a failed read must keep the last good permits")
	}
}

func TestRuntimeHostPorts_RoundTrip(t *testing.T) {
	entries := []config.HostEntry{
		{IP: "10.0.0.9", Ports: []int{8080, 443}},
		{IP: "10.0.0.10"},
		{IP: "192.168.1.5", Ports: []int{22}},
	}
	value := formatRuntimeHostPorts(entries)
	if value != "10.0.0.9=8080,443 192.168.1.5=22" {
		t.Errorf("format = %q", value)
	}
	got := parseRuntimeHostPorts(value)
	if len(got) != 2 || got[0].IP != "10.0.0.9" || len(got[0].Ports) != 2 || got[1].IP != "192.168.1.5" || got[1].Ports[0] != 22 {
		t.Errorf("parse = %+v", got)
	}
}
