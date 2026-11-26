package config

import (
	"os"
	"path/filepath"
	"slices"
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

	if cfg.Network.Mode != NetworkModeAllowlist {
		t.Errorf("network mode = %q, want allowlist (override open)", cfg.Network.Mode)
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
	if p.Network == nil || p.Network.Mode != NetworkModeAllowlist {
		t.Fatal("hardened profile must pin allowlist network mode")
	}
}

// The hardened allowlist is the package/code hosts plus the configured tool's
// api_domains; it replaces the allowed_domains set before the profile is
// applied. A later workspace overlay is undone by ReapplyProfileNetwork.
func TestHardenedProfile_AllowedDomains(t *testing.T) {
	tests := []struct {
		tool  string
		extra []string
	}{
		{"claude", []string{"api.anthropic.com", "platform.claude.com"}},
		{"codex", []string{"api.openai.com", "auth.openai.com", "chatgpt.com"}},
		{"opencode", nil},
		{"no-such-tool", nil},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			cfg := GetDefaultConfig()
			cfg.Tool.Name = tt.tool
			cfg.Network.AllowedDomains = []string{"attacker.example"}
			cfg.Profiles["hardened"] = synthesizeHardenedProfile()
			if err := cfg.ApplyProfile("hardened"); err != nil {
				t.Fatalf("ApplyProfile(hardened): %v", err)
			}
			want := append(cloneSlice(HardenedProfileAllowedDomains), tt.extra...)
			if !slices.Equal(cfg.Network.AllowedDomains, want) {
				t.Errorf("allowed_domains = %v, want %v", cfg.Network.AllowedDomains, want)
			}
		})
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

// The tool API hosts follow the tool the session runs: a profile inheriting
// hardened that sets its own [tool] gets that tool's hosts, not the config's.
func TestHardenedProfile_AllowedDomainsFollowProfileTool(t *testing.T) {
	cfg := loadWithConfigs(t, "", "", map[string]string{
		"hardened-codex": "inherits = \"hardened\"\n\n[tool]\nname = \"codex\"\n",
	})
	if err := cfg.ApplyProfile("hardened-codex"); err != nil {
		t.Fatalf("ApplyProfile(hardened-codex): %v", err)
	}
	want := append(cloneSlice(HardenedProfileAllowedDomains), ToolAPIDomains("codex")...)
	if !slices.Equal(cfg.Network.AllowedDomains, want) {
		t.Errorf("allowed_domains = %v, want %v", cfg.Network.AllowedDomains, want)
	}
	p := cfg.Profiles["hardened-codex"]
	if got := p.AllowedDomainsFor("codex"); !slices.Equal(got, want) {
		t.Errorf("AllowedDomainsFor(codex) = %v, want %v", got, want)
	}
}

// A workspace overlay (alias launch) that changes the tool after the profile is
// applied swaps the tool API hosts and keeps the ones the user listed.
func TestHardenedProfile_AllowedDomainsFollowOverlayTool(t *testing.T) {
	cfg := loadWithConfigs(t, "", "", map[string]string{
		"hardened-own": "inherits = \"hardened\"\n\n[network]\n" +
			"allowed_domains = [\"example.com\", \"api.openai.com\"]\n",
	})
	if err := cfg.ApplyProfile("hardened-own"); err != nil {
		t.Fatalf("ApplyProfile(hardened-own): %v", err)
	}
	want := []string{"example.com", "api.openai.com", "api.anthropic.com", "platform.claude.com"}
	if !slices.Equal(cfg.Network.AllowedDomains, want) {
		t.Fatalf("allowed_domains = %v, want %v", cfg.Network.AllowedDomains, want)
	}

	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := []byte("[tool]\nname = \"codex\"\n")
	if err := os.WriteFile(filepath.Join(workspace, ".coi", "config.toml"), project, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverlayProjectConfig(workspace); err != nil {
		t.Fatalf("OverlayProjectConfig: %v", err)
	}
	want = []string{"example.com", "api.openai.com", "auth.openai.com", "chatgpt.com"}
	if !slices.Equal(cfg.Network.AllowedDomains, want) {
		t.Errorf("allowed_domains = %v, want %v", cfg.Network.AllowedDomains, want)
	}
}

// ReapplyProfileNetwork undoes a workspace overlay that turns hardened back to
// restricted mode with its own allowlist, and keeps the tool API hosts.
func TestReapplyProfileNetwork_UndoesWeakeningOverlay(t *testing.T) {
	cfg := loadWithConfigs(t, "", "", nil)
	if err := cfg.ApplyProfile("hardened"); err != nil {
		t.Fatalf("ApplyProfile(hardened): %v", err)
	}
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := []byte("[network]\nmode = \"restricted\"\nallowed_domains = [\"attacker.example\"]\n")
	if err := os.WriteFile(filepath.Join(workspace, ".coi", "config.toml"), project, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cfg.OverlayProjectConfig(workspace); err != nil {
		t.Fatalf("OverlayProjectConfig: %v", err)
	}
	if err := cfg.ReapplyProfileNetwork("hardened"); err != nil {
		t.Fatalf("ReapplyProfileNetwork: %v", err)
	}
	if cfg.Network.Mode != NetworkModeAllowlist {
		t.Errorf("network mode = %q, want %q", cfg.Network.Mode, NetworkModeAllowlist)
	}
	want := append(cloneSlice(HardenedProfileAllowedDomains), ToolAPIDomains(cfg.Tool.Name)...)
	if !slices.Equal(cfg.Network.AllowedDomains, want) {
		t.Errorf("allowed_domains = %v, want %v", cfg.Network.AllowedDomains, want)
	}
	if err := cfg.ReapplyProfileNetwork("missing"); err == nil {
		t.Error("ReapplyProfileNetwork(missing): want an error")
	}
}
