package config

import (
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

// A [network] block with the new egress keys must decode from TOML into the
// right typed fields (a full round-trip through the real decoder, not a
// hand-built struct).
func TestNetworkConfig_TOMLRoundTrip(t *testing.T) {
	const src = `
[network]
mode = "restricted"
dns_servers = ["192.168.1.2", "192.168.1.3"]
allowed_ports = [53, 80, 443]
`
	var cfg struct {
		Network NetworkConfig `toml:"network"`
	}
	if _, err := toml.Decode(src, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(cfg.Network.DNSServers, []string{"192.168.1.2", "192.168.1.3"}) {
		t.Errorf("dns_servers = %v", cfg.Network.DNSServers)
	}
	if !reflect.DeepEqual(cfg.Network.AllowedPorts, []int{53, 80, 443}) {
		t.Errorf("allowed_ports = %v", cfg.Network.AllowedPorts)
	}
}

// Omitting the keys must leave them nil (not empty), so downstream code can
// distinguish "unset" (keep default / all ports) from "explicitly empty".
func TestNetworkConfig_TOMLOmittedKeysAreNil(t *testing.T) {
	const src = `
[network]
mode = "restricted"
`
	var cfg struct {
		Network NetworkConfig `toml:"network"`
	}
	if _, err := toml.Decode(src, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.Network.DNSServers != nil {
		t.Errorf("expected nil dns_servers when omitted, got %v", cfg.Network.DNSServers)
	}
	if cfg.Network.AllowedPorts != nil {
		t.Errorf("expected nil allowed_ports when omitted, got %v", cfg.Network.AllowedPorts)
	}
}

// mergeNetworkInto must carry the new egress-policy keys, so a trusted config or
// profile can set dns_servers / allowed_ports and have them survive the merge.
func TestMergeNetworkInto_CarriesEgressKeys(t *testing.T) {
	base := GetDefaultConfig()
	base.Merge(&Config{Network: NetworkConfig{
		Mode:         NetworkModeRestricted,
		DNSServers:   []string{"192.168.1.2"},
		AllowedPorts: []int{80, 443},
	}})

	if !reflect.DeepEqual(base.Network.DNSServers, []string{"192.168.1.2"}) {
		t.Errorf("dns_servers not merged, got %v", base.Network.DNSServers)
	}
	if !reflect.DeepEqual(base.Network.AllowedPorts, []int{80, 443}) {
		t.Errorf("allowed_ports not merged, got %v", base.Network.AllowedPorts)
	}
}

// A later merge with the keys unset must not clobber values an earlier layer set
// (nil source = "no opinion"), matching how the other network slices behave.
func TestMergeNetworkInto_UnsetDoesNotClobber(t *testing.T) {
	base := GetDefaultConfig()
	base.Network.DNSServers = []string{"192.168.1.2"}
	base.Network.AllowedPorts = []int{443}

	base.Merge(&Config{Network: NetworkConfig{Mode: NetworkModeRestricted}})

	if !reflect.DeepEqual(base.Network.DNSServers, []string{"192.168.1.2"}) {
		t.Errorf("dns_servers clobbered by unset merge, got %v", base.Network.DNSServers)
	}
	if !reflect.DeepEqual(base.Network.AllowedPorts, []int{443}) {
		t.Errorf("allowed_ports clobbered by unset merge, got %v", base.Network.AllowedPorts)
	}
}

// A later layer that DOES set the keys must fully replace the earlier value
// (slice replace, not append) — matching allowed_domains / hosts semantics.
func TestMergeNetworkInto_SetReplaces(t *testing.T) {
	base := GetDefaultConfig()
	base.Network.DNSServers = []string{"192.168.1.2"}
	base.Network.AllowedPorts = []int{443}

	base.Merge(&Config{Network: NetworkConfig{
		DNSServers:   []string{"10.0.0.53"},
		AllowedPorts: []int{80},
	}})

	if !reflect.DeepEqual(base.Network.DNSServers, []string{"10.0.0.53"}) {
		t.Errorf("dns_servers should be replaced, got %v", base.Network.DNSServers)
	}
	if !reflect.DeepEqual(base.Network.AllowedPorts, []int{80}) {
		t.Errorf("allowed_ports should be replaced, got %v", base.Network.AllowedPorts)
	}
}

// synthesizeDefaultProfile must deep-copy the egress slices so mutating the
// derived profile cannot write back into the source Config (aliasing bug class).
func TestSynthesizeDefaultProfile_ClonesEgressSlices(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Network.DNSServers = []string{"192.168.1.2"}
	cfg.Network.AllowedPorts = []int{443}

	p := synthesizeDefaultProfile(cfg)
	if p.Network == nil {
		t.Fatal("synthesized profile has nil Network")
	}

	// Mutate the profile's copies; the source Config must be untouched.
	p.Network.DNSServers[0] = "6.6.6.6"
	p.Network.AllowedPorts[0] = 9999

	if cfg.Network.DNSServers[0] != "192.168.1.2" {
		t.Errorf("dns_servers aliased: source mutated to %v", cfg.Network.DNSServers)
	}
	if cfg.Network.AllowedPorts[0] != 443 {
		t.Errorf("allowed_ports aliased: source mutated to %v", cfg.Network.AllowedPorts)
	}
}

// A profile inheriting from a parent that sets the egress keys must receive them
// through the profile inheritance path (mergeStructPtr → mergeNetworkInto).
func TestProfileInheritance_CarriesEgressKeys(t *testing.T) {
	parent := ProfileConfig{
		Network: &NetworkConfig{
			Mode:         NetworkModeRestricted,
			DNSServers:   []string{"192.168.1.2"},
			AllowedPorts: []int{80, 443},
		},
	}
	child := ProfileConfig{
		Inherits: "parent",
		Network:  &NetworkConfig{Mode: NetworkModeRestricted},
	}

	merged := mergeProfiles(parent, child)
	if merged.Network == nil {
		t.Fatal("merged profile has nil Network")
	}
	if !reflect.DeepEqual(merged.Network.DNSServers, []string{"192.168.1.2"}) {
		t.Errorf("child did not inherit dns_servers, got %v", merged.Network.DNSServers)
	}
	if !reflect.DeepEqual(merged.Network.AllowedPorts, []int{80, 443}) {
		t.Errorf("child did not inherit allowed_ports, got %v", merged.Network.AllowedPorts)
	}
}

// refresh_interval_minutes = 0 disables refreshing (schema + manager), so an
// explicit 0 from a config file or profile must override the default 30 rather
// than read as "unset".
func TestMergeNetworkInto_RefreshIntervalZeroOverridesDefault(t *testing.T) {
	var file Config
	if _, err := toml.Decode("[network]\nrefresh_interval_minutes = 0\n", &file); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg := GetDefaultConfig()
	if got := IntVal(cfg.Network.RefreshIntervalMinutes); got != 30 {
		t.Fatalf("default refresh interval = %d, want 30", got)
	}
	cfg.Merge(&file)
	if got := IntVal(cfg.Network.RefreshIntervalMinutes); got != 0 {
		t.Errorf("after merging an explicit 0, refresh interval = %d, want 0", got)
	}

	cfg = GetDefaultConfig()
	cfg.Merge(&Config{}) // a file without the key keeps the default
	if got := IntVal(cfg.Network.RefreshIntervalMinutes); got != 30 {
		t.Errorf("after merging an empty config, refresh interval = %d, want 30", got)
	}

	cfg = GetDefaultConfig()
	zero := 0
	cfg.Profiles = map[string]ProfileConfig{"pinned": {Network: &NetworkConfig{RefreshIntervalMinutes: &zero}}}
	if err := cfg.ApplyProfile("pinned"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if got := IntVal(cfg.Network.RefreshIntervalMinutes); got != 0 {
		t.Errorf("after a profile's explicit 0, refresh interval = %d, want 0", got)
	}
}
