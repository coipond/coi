package network

import (
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
	p := NewExplicitPortPermits(hosts, policy, resolved)
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
	p := NewExplicitPortPermits([]config.HostEntry{{IP: "10.0.0.5", Ports: []int{8080}}}, nil, nil)
	if !p.Permits("tcp", "10.0.0.5", 8080) {
		t.Error("host entry with ports should permit its port")
	}
	if p.Permits("tcp", "10.0.0.5", 8081) {
		t.Error("another port must not be permitted")
	}
	if NewExplicitPortPermits(nil, nil, nil).Permits("tcp", "10.0.0.5", 8080) {
		t.Error("no entries must permit nothing")
	}
}
