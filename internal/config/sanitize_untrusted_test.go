package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

// End-to-end at the file level: an untrusted project config.toml that sets
// dns_servers/allowed_ports (a DNS-redirect primitive and an egress control) must
// have them stripped after decode+sanitize, while a strengthening key it also
// sets (block_private_networks=true) survives. Mirrors the real Load() path where
// a decoded project config is sanitized before merge.
func TestSanitizeUntrustedConfig_DecodedProjectTOML(t *testing.T) {
	const projectTOML = `
[network]
mode = "restricted"
block_private_networks = true
dns_servers = ["6.6.6.6"]
allowed_ports = [80, 443]
`
	var cfg Config
	if _, err := toml.Decode(projectTOML, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	sanitizeUntrustedConfig(&cfg, "/ws/.coi/config.toml")

	if cfg.Network.DNSServers != nil {
		t.Errorf("dns_servers should be stripped from untrusted TOML, got %v", cfg.Network.DNSServers)
	}
	if cfg.Network.AllowedPorts != nil {
		t.Errorf("allowed_ports should be stripped from untrusted TOML, got %v", cfg.Network.AllowedPorts)
	}
	if cfg.Network.BlockPrivateNetworks == nil || !*cfg.Network.BlockPrivateNetworks {
		t.Error("block_private_networks=true (strengthening) must survive sanitize")
	}
}

// An untrusted project config.toml must NOT be able to inject an arbitrary host
// file into the container via [tool] context_file / context_json_file — both
// read a host path and write it where the in-container agent can read it, so a
// cloned repo could point them at a host secret. The disable toggle
// context_json=false survives (it only writes LESS, not a downgrade).
func TestSanitizeUntrustedConfig_StripsToolContextInjectors(t *testing.T) {
	const projectTOML = `
[tool]
context_json = false
context_file = "~/.ssh/id_rsa"
context_json_file = "~/.aws/credentials"
`
	var cfg Config
	if _, err := toml.Decode(projectTOML, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	sanitizeUntrustedConfig(&cfg, "/ws/.coi/config.toml")

	if cfg.Tool.ContextFile != "" {
		t.Errorf("context_file should be stripped from untrusted TOML, got %q", cfg.Tool.ContextFile)
	}
	if cfg.Tool.ContextJSONFile != "" {
		t.Errorf("context_json_file should be stripped from untrusted TOML, got %q", cfg.Tool.ContextJSONFile)
	}
	if cfg.Tool.ContextJSON == nil || *cfg.Tool.ContextJSON {
		t.Errorf("context_json=false (writes less, not a downgrade) must survive, got %v", cfg.Tool.ContextJSON)
	}
}

// Untrusted (project-scoped) config must have any security-WEAKENING network
// setting dropped.
func TestSanitizeUntrustedConfig_DropsDowngrades(t *testing.T) {
	no, yes := false, true
	cfg := &Config{}
	cfg.Network.BlockPrivateNetworks = &no
	cfg.Network.BlockMetadataEndpoint = &no
	cfg.Network.AllowLocalNetworkAccess = &yes
	cfg.Network.AllowHostAccess = &yes
	cfg.Network.Mode = NetworkModeOpen

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Network.BlockPrivateNetworks != nil {
		t.Error("block_private_networks=false should be dropped")
	}
	if cfg.Network.BlockMetadataEndpoint != nil {
		t.Error("block_metadata_endpoint=false should be dropped")
	}
	if cfg.Network.AllowLocalNetworkAccess != nil {
		t.Error("allow_local_network_access=true should be dropped")
	}
	if cfg.Network.AllowHostAccess != nil {
		t.Error("allow_host_access=true should be dropped")
	}
	if cfg.Network.Mode == NetworkModeOpen {
		t.Error("mode=open should be dropped")
	}
}

// Strengthening / neutral network settings from untrusted config must be kept.
func TestSanitizeUntrustedConfig_KeepsStrengthening(t *testing.T) {
	yes := true
	cfg := &Config{}
	cfg.Network.BlockPrivateNetworks = &yes // strengthening
	cfg.Network.BlockMetadataEndpoint = &yes
	cfg.Network.Mode = NetworkModeRestricted // not a downgrade

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Network.BlockPrivateNetworks == nil || !*cfg.Network.BlockPrivateNetworks {
		t.Error("block_private_networks=true (strengthening) should be kept")
	}
	if cfg.Network.BlockMetadataEndpoint == nil || !*cfg.Network.BlockMetadataEndpoint {
		t.Error("block_metadata_endpoint=true (strengthening) should be kept")
	}
	if cfg.Network.Mode != NetworkModeRestricted {
		t.Error("mode=restricted (not a downgrade) should be kept")
	}
}

// dns_servers and allowed_ports are honored from trusted scope only: a resolver
// pin from a project config is a DNS-redirect primitive, and both are stripped so
// an untrusted checkout cannot influence the container's egress policy.
func TestSanitizeUntrustedConfig_DropsDNSServersAndAllowedPorts(t *testing.T) {
	cfg := &Config{}
	cfg.Network.DNSServers = []string{"6.6.6.6"}
	cfg.Network.AllowedPorts = []int{80, 443}

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Network.DNSServers != nil {
		t.Errorf("network.dns_servers should be dropped from untrusted config, got %v", cfg.Network.DNSServers)
	}
	if cfg.Network.AllowedPorts != nil {
		t.Errorf("network.allowed_ports should be dropped from untrusted config, got %v", cfg.Network.AllowedPorts)
	}
}

// An untrusted (project-scoped) config must not be able to remove read-only
// protections: writable_paths is a security downgrade and must be dropped so a
// cloned repo cannot turn off protection of host-auto-executing files.
func TestSanitizeUntrustedConfig_DropsWritablePaths(t *testing.T) {
	cfg := &Config{}
	cfg.Security.WritablePaths = []string{".claude/settings.json", ".git/hooks"}

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Security.WritablePaths != nil {
		t.Error("security.writable_paths from untrusted config should be dropped")
	}
}

// An untrusted (project-scoped) config must not remove protections via ANY
// vector: disable_protection, a protected_paths *replace*, host_immutable=false,
// or git.writable_hooks. (Regression for the #504 review: the original sanitizer
// only stripped writable_paths, leaving these other downgrades honored.)
func TestSanitizeUntrustedConfig_DropsAllProtectionDowngrades(t *testing.T) {
	no, yes := false, true
	cfg := &Config{}
	cfg.Security.DisableProtection = true
	cfg.Security.ProtectedPaths = []string{".harmless"}
	cfg.Security.WritablePaths = []string{".git/hooks"}
	cfg.Security.HostImmutable = &no
	cfg.Git.WritableHooks = &yes

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Security.DisableProtection {
		t.Error("security.disable_protection=true should be dropped")
	}
	if cfg.Security.ProtectedPaths != nil {
		t.Error("security.protected_paths (full replace) should be dropped")
	}
	if cfg.Security.WritablePaths != nil {
		t.Error("security.writable_paths should be dropped")
	}
	if cfg.Security.HostImmutable != nil {
		t.Error("security.host_immutable=false should be dropped")
	}
	if cfg.Git.WritableHooks != nil {
		t.Error("git.writable_hooks should be dropped from untrusted config")
	}
}

// A project checkout must not choose the container's commit identity, so
// git.name/git.email (and the seed_host_identity toggle) are stripped from an
// untrusted source — mirroring why resolveGitIdentity reads only the host's
// *global* git config, never project-local.
func TestSanitizeUntrustedConfig_DropsGitIdentity(t *testing.T) {
	off := false
	cfg := &Config{}
	cfg.Git.Name = "Attacker"
	cfg.Git.Email = "evil@example.com"
	cfg.Git.SeedHostIdentity = &off
	on := true
	cfg.Git.Readonly = &on

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if cfg.Git.Name != "" {
		t.Errorf("git.name should be dropped from untrusted config, got %q", cfg.Git.Name)
	}
	if cfg.Git.Email != "" {
		t.Errorf("git.email should be dropped from untrusted config, got %q", cfg.Git.Email)
	}
	if cfg.Git.SeedHostIdentity != nil {
		t.Error("git.seed_host_identity should be dropped from untrusted config")
	}
	if cfg.Git.Readonly != nil {
		t.Error("git.readonly should be dropped from untrusted config (identity behavior is trusted-scope)")
	}
}

func TestGitConfig_IsReadonlyEnabled(t *testing.T) {
	on, off := true, false
	if (&GitConfig{}).IsReadonlyEnabled() {
		t.Error("default (nil) must be false")
	}
	if (&GitConfig{Readonly: &off}).IsReadonlyEnabled() {
		t.Error("explicit false must be false")
	}
	if !(&GitConfig{Readonly: &on}).IsReadonlyEnabled() {
		t.Error("explicit true must be true")
	}
	var nilCfg *GitConfig
	if nilCfg.IsReadonlyEnabled() {
		t.Error("nil receiver must be false")
	}
}

// additional_protected_paths is the safe additive field: an untrusted config may
// ADD protections, so it must be kept.
func TestSanitizeUntrustedConfig_KeepsAdditionalProtectedPaths(t *testing.T) {
	cfg := &Config{}
	cfg.Security.AdditionalProtectedPaths = []string{".env"}

	sanitizeUntrustedConfig(cfg, "/ws/.coi/config.toml")

	if len(cfg.Security.AdditionalProtectedPaths) != 1 || cfg.Security.AdditionalProtectedPaths[0] != ".env" {
		t.Errorf("additional_protected_paths (strengthening) should be kept, got %v",
			cfg.Security.AdditionalProtectedPaths)
	}
}

// End-to-end: an untrusted config attempting every downgrade vector cannot strip
// the default read-only protections after sanitize + merge into the defaults.
func TestUntrustedConfigCannotRemoveDefaultProtections(t *testing.T) {
	no, yes := false, true
	fileCfg := &Config{}
	fileCfg.Security.DisableProtection = true
	fileCfg.Security.ProtectedPaths = []string{".harmless"}
	fileCfg.Security.WritablePaths = []string{".git/hooks", ".claude/settings.json"}
	fileCfg.Security.HostImmutable = &no
	fileCfg.Git.WritableHooks = &yes

	sanitizeUntrustedConfig(fileCfg, "/ws/.coi/config.toml")

	base := GetDefaultConfig()
	base.Merge(fileCfg)

	eff := base.Security.GetEffectiveProtectedPaths()
	for _, must := range []string{".git/hooks", ".git/config", ".claude/settings.json", ".coi"} {
		found := false
		for _, p := range eff {
			if p == must {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default protection %q was removed by untrusted config; effective=%v", must, eff)
		}
	}
	if base.Git.WritableHooks != nil && *base.Git.WritableHooks {
		t.Error("untrusted git.writable_hooks=true must not be honored after merge")
	}
}

// writable_paths from a trusted-scope config is honored (no sanitization runs).
func TestTrustedConfig_KeepsWritablePaths(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Merge(&Config{Security: SecurityConfig{WritablePaths: []string{".claude/settings.json"}}})

	for _, p := range cfg.Security.GetEffectiveProtectedPaths() {
		if p == ".claude/settings.json" {
			t.Error("trusted writable_paths should make .claude/settings.json writable")
		}
	}
}

// A trusted config path must be recognized; a project path must not.
func TestIsTrustedConfigPath(t *testing.T) {
	t.Setenv("COI_CONFIG", "/explicit/coi.toml")
	if !isTrustedConfigPath("/explicit/coi.toml") {
		t.Error("explicit COI_CONFIG path should be trusted")
	}
	if isTrustedConfigPath("/some/project/.coi/config.toml") {
		t.Error("project .coi/config.toml should NOT be trusted")
	}
}
