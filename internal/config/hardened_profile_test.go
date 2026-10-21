package config

import (
	"testing"
)

// The built-in "hardened" profile must be available without any disk config and,
// when applied, must harden the resolved config — overriding even a base config
// that was deliberately weakened (open network, SSH agent forwarding, persistent).
func TestHardenedProfile_HardensResolvedConfig(t *testing.T) {
	cfg := GetDefaultConfig()
	// Deliberately weakened / risky base settings the preset must override.
	yes := true
	cfg.Network.Mode = NetworkModeOpen
	cfg.SSH.ForwardAgent = &yes
	cfg.Container.Persistent = &yes
	cfg.Security.SecretPaths = []string{"custom.secret"} // user's own — must be kept (union)

	cfg.Profiles["hardened"] = synthesizeHardenedProfile()
	if err := cfg.ApplyProfile("hardened"); err != nil {
		t.Fatalf("ApplyProfile(hardened): %v", err)
	}

	if cfg.Network.Mode != NetworkModeRestricted {
		t.Errorf("network mode = %q, want restricted (override open)", cfg.Network.Mode)
	}
	if !BoolVal(cfg.Network.BlockMetadataEndpoint) {
		t.Error("block_metadata_endpoint should be true")
	}
	if cfg.Network.AllowLocalNetworkAccess == nil || *cfg.Network.AllowLocalNetworkAccess {
		t.Error("allow_local_network_access should be false")
	}
	if cfg.SSH.ForwardAgent == nil || *cfg.SSH.ForwardAgent {
		t.Error("ssh.forward_agent should be forced false for an untrusted repo")
	}
	if cfg.Container.Persistent == nil || *cfg.Container.Persistent {
		t.Error("container should be ephemeral (persistent=false)")
	}
	if !cfg.Security.IsHostImmutableEnabled() {
		t.Error("host_immutable should be true")
	}
	if !BoolVal(cfg.Monitoring.Enabled) || !BoolVal(cfg.Monitoring.NFT.Enabled) {
		t.Error("monitoring + nft monitoring should be enabled")
	}
	if !cfg.Security.IsReduceKernelSurfaceEnabled() {
		t.Error("reduce_kernel_surface should be true")
	}
	if cfg.Limits.Runtime.MaxDuration != "4h" {
		t.Errorf("hardened profile should bound the session (max_duration=4h), got %q", cfg.Limits.Runtime.MaxDuration)
	}
	// The hardened profile expresses docker-off through reduce_kernel_surface
	// (the single hardening switch), not an explicit docker flag — so the raw
	// [container] docker stays unset while effective docker resolves to off.
	if effectiveDocker := cfg.Container.IsDockerEnabled() && !cfg.Security.IsReduceKernelSurfaceEnabled(); effectiveDocker {
		t.Error("effective docker should resolve to off under the hardened profile")
	}

	// secret_paths must be a UNION: the user's own entry kept, plus the preset's.
	have := make(map[string]bool)
	for _, p := range cfg.Security.SecretPaths {
		have[p] = true
	}
	if !have["custom.secret"] {
		t.Error("user's secret_paths entry must be preserved (union merge)")
	}
	for _, want := range HardenedProfileSecretPaths {
		if !have[want] {
			t.Errorf("preset secret path %q missing from merged secret_paths", want)
		}
	}
}

// The preset must be injected as a built-in (no disk profile required), like "default".
func TestHardenedProfile_InjectedAsBuiltin(t *testing.T) {
	p := synthesizeHardenedProfile()
	if p.Source != "(built-in)" {
		t.Errorf("hardened profile Source = %q, want (built-in)", p.Source)
	}
	if p.Network == nil || p.Network.Mode != NetworkModeRestricted {
		t.Fatal("hardened profile must pin restricted network mode")
	}
}

func TestIsBuiltinProfile(t *testing.T) {
	for _, name := range []string{"default", "hardened"} {
		if !IsBuiltinProfile(name) {
			t.Errorf("IsBuiltinProfile(%q) = false, want true", name)
		}
	}
	if IsBuiltinProfile("rust-dev") {
		t.Error(`IsBuiltinProfile("rust-dev") = true, want false`)
	}
	for name, synthesize := range builtinProfiles {
		if p := synthesize(GetDefaultConfig()); p.Source != "(built-in)" {
			t.Errorf("built-in profile %q Source = %q, want (built-in)", name, p.Source)
		}
	}
}
