package config

import (
	"strings"
	"testing"
)

func TestValidateNetworkHosts(t *testing.T) {
	ok := []HostEntry{
		{IP: "10.0.0.5", Hostnames: []string{"db.internal", "cache.internal"}},
		{IP: "1.2.3.4", Hostnames: []string{"api.example.com"}},
		{IP: "192.168.1.50", Hostnames: []string{"redmine.local"}, Ports: []int{443}},
		{IP: "192.168.1.51", Hostnames: []string{"svc.local"}, Ports: []int{80, 443, 8080}},
	}
	if err := ValidateNetworkHosts(ok); err != nil {
		t.Errorf("valid hosts rejected: %v", err)
	}

	bad := map[string][]HostEntry{
		"not an IP":       {{IP: "nope", Hostnames: []string{"x"}}},
		"IPv6":            {{IP: "2001:db8::1", Hostnames: []string{"x"}}},
		"no hostnames":    {{IP: "10.0.0.5", Hostnames: nil}},
		"bad hostname":    {{IP: "10.0.0.5", Hostnames: []string{"bad host name"}}},
		"hostname dash":   {{IP: "10.0.0.5", Hostnames: []string{"-leading"}}},
		"port zero":       {{IP: "10.0.0.5", Hostnames: []string{"x"}, Ports: []int{0}}},
		"port over max":   {{IP: "10.0.0.5", Hostnames: []string{"x"}, Ports: []int{70000}}},
		"port negative":   {{IP: "10.0.0.5", Hostnames: []string{"x"}, Ports: []int{-1}}},
		"one bad in list": {{IP: "10.0.0.5", Hostnames: []string{"x"}, Ports: []int{443, 99999}}},
	}
	for name, entries := range bad {
		if err := ValidateNetworkHosts(entries); err == nil {
			t.Errorf("%s: expected a validation error, got nil", name)
		}
	}
}

// An untrusted (project-scoped) config must not be able to inject host entries:
// a name→IP mapping is a spoofing primitive and reachability punches a firewall
// hole, so network.hosts is stripped before merge.
func TestSanitizeStripsUntrustedNetworkHosts(t *testing.T) {
	fileCfg := &Config{}
	fileCfg.Network.Hosts = []HostEntry{{IP: "6.6.6.6", Hostnames: []string{"api.anthropic.com"}}}

	sanitizeUntrustedNetwork(&fileCfg.Network, "/repo/.coi/config.toml")

	if fileCfg.Network.Hosts != nil {
		t.Errorf("untrusted network.hosts must be stripped, got %+v", fileCfg.Network.Hosts)
	}
}

// A profile with a single invalid [[network.hosts]] entry is rejected by
// ProfileConfig.Validate — validation must not only kick in for 2+ entries.
func TestProfileValidate_SingleInvalidNetworkHost(t *testing.T) {
	p := &ProfileConfig{Network: &NetworkConfig{Hosts: []HostEntry{{IP: "not-an-ip", Hostnames: []string{"db"}}}}}
	err := p.Validate("test")
	if err == nil || !strings.Contains(err.Error(), "not a valid IPv4 address") {
		t.Errorf("a single invalid host entry must be rejected, got %v", err)
	}
	ok := &ProfileConfig{Network: &NetworkConfig{Hosts: []HostEntry{{IP: "10.0.0.5", Hostnames: []string{"db"}}}}}
	if err := ok.Validate("test"); err != nil {
		t.Errorf("a single valid host entry should pass, got %v", err)
	}
}
