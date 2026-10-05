package config

import (
	"os"
	"path/filepath"
	"testing"
)

const trustTestMountConfig = `
[[mounts.default]]
host = "/tmp/some-host-dir"
container = "/mnt/x"
`

func writeMountConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(trustTestMountConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func findMount(cfg *Config, container string) (MountEntry, bool) {
	for _, m := range cfg.Mounts.Default {
		if m.Container == container {
			return m, true
		}
	}
	return MountEntry{}, false
}

func TestLoadConfigFileScoped_UntrustedMarksMounts(t *testing.T) {
	path := writeMountConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, false); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	m, ok := findMount(cfg, "/mnt/x")
	if !ok {
		t.Fatal("mount /mnt/x was not loaded")
	}
	if !m.Untrusted {
		t.Error("mount from untrusted config should have Untrusted=true")
	}
	abs, _ := filepath.Abs(path)
	if m.SourcePath != abs {
		t.Errorf("SourcePath = %q, want %q", m.SourcePath, abs)
	}
}

const untrustedProfileConfig = `
[network]
mode = "open"
allow_local_network_access = true

[[mounts]]
host = "/tmp/evil-host-dir"
container = "/mnt/h"
`

func writeProfile(t *testing.T, body string) (root, cfgPath string) {
	t.Helper()
	root = t.TempDir()
	profDir := filepath.Join(root, "profiles", "dev")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(profDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, cfgPath
}

// A project-scoped (untrusted) profile must have its network downgrades refused
// and its mounts tagged untrusted — closing the profile bypass of the H4/M5 gate.
func TestLoadProfileDirectories_UntrustedTagsMountsAndSanitizesNetwork(t *testing.T) {
	root, cfgPath := writeProfile(t, untrustedProfileConfig)
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, false); err != nil {
		t.Fatalf("loadProfileDirectories: %v", err)
	}
	p, ok := cfg.Profiles["dev"]
	if !ok {
		t.Fatal("profile dev not loaded")
	}
	if p.Network == nil {
		t.Fatal("profile network is nil")
	}
	if p.Network.Mode == NetworkModeOpen {
		t.Error("untrusted profile network.mode=open should have been sanitized")
	}
	if p.Network.AllowLocalNetworkAccess != nil && *p.Network.AllowLocalNetworkAccess {
		t.Error("untrusted profile allow_local_network_access=true should have been sanitized")
	}
	if len(p.Mounts) != 1 {
		t.Fatalf("expected 1 profile mount, got %d", len(p.Mounts))
	}
	if !p.Mounts[0].Untrusted {
		t.Error("project-scoped profile mount must be marked Untrusted")
	}
	abs, _ := filepath.Abs(cfgPath)
	if p.Mounts[0].SourcePath != abs {
		t.Errorf("SourcePath = %q, want %q", p.Mounts[0].SourcePath, abs)
	}
}

func TestLoadProfileDirectories_TrustedDoesNotTag(t *testing.T) {
	root, _ := writeProfile(t, "[[mounts]]\nhost = \"/tmp/x\"\ncontainer = \"/mnt/x\"\n")
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, true); err != nil {
		t.Fatalf("loadProfileDirectories: %v", err)
	}
	p := cfg.Profiles["dev"]
	if len(p.Mounts) != 1 {
		t.Fatalf("expected 1 profile mount, got %d", len(p.Mounts))
	}
	if p.Mounts[0].Untrusted {
		t.Error("trusted profile mount must not be marked Untrusted")
	}
}

const trustTestSocketConfig = `
[[sockets]]
host = "/run/host.sock"
container = "/run/c.sock"
env = "BROKER"
`

func writeSocketConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(trustTestSocketConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigFileScoped_UntrustedMarksSockets(t *testing.T) {
	path := writeSocketConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, false); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	if len(cfg.Sockets) != 1 {
		t.Fatalf("expected 1 socket, got %d", len(cfg.Sockets))
	}
	s := cfg.Sockets[0]
	if !s.Untrusted {
		t.Error("socket from untrusted config should have Untrusted=true")
	}
	abs, _ := filepath.Abs(path)
	if s.SourcePath != abs {
		t.Errorf("SourcePath = %q, want %q", s.SourcePath, abs)
	}
}

func TestLoadConfigFileScoped_TrustedDoesNotMarkSockets(t *testing.T) {
	path := writeSocketConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, true); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	if len(cfg.Sockets) != 1 {
		t.Fatalf("expected 1 socket, got %d", len(cfg.Sockets))
	}
	if cfg.Sockets[0].Untrusted || cfg.Sockets[0].SourcePath != "" {
		t.Errorf("socket from trusted config must not be marked untrusted: %+v", cfg.Sockets[0])
	}
}

func TestLoadProfileDirectories_UntrustedMarksSockets(t *testing.T) {
	body := "[[sockets]]\nhost = \"/run/host.sock\"\ncontainer = \"/run/c.sock\"\nenv = \"BROKER\"\n"
	root, cfgPath := writeProfile(t, body)
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, false); err != nil {
		t.Fatalf("loadProfileDirectories: %v", err)
	}
	p := cfg.Profiles["dev"]
	if len(p.Sockets) != 1 {
		t.Fatalf("expected 1 profile socket, got %d", len(p.Sockets))
	}
	if !p.Sockets[0].Untrusted {
		t.Error("project-scoped profile socket must be marked Untrusted")
	}
	abs, _ := filepath.Abs(cfgPath)
	if p.Sockets[0].SourcePath != abs {
		t.Errorf("SourcePath = %q, want %q", p.Sockets[0].SourcePath, abs)
	}
}

const trustTestEnvCommandsConfig = `
[defaults.env_commands]
TOKEN = "echo secret"

[defaults]
env_command_timeout = "5s"
`

func writeEnvCommandsConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(trustTestEnvCommandsConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigFileScoped_UntrustedStripsEnvCommands(t *testing.T) {
	path := writeEnvCommandsConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, false); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	if len(cfg.Defaults.EnvCommands) != 0 {
		t.Errorf("env_commands from untrusted config must be stripped, got %+v", cfg.Defaults.EnvCommands)
	}
	if cfg.Defaults.EnvCommandTimeout != "" {
		t.Errorf("env_command_timeout from untrusted config must be cleared, got %q", cfg.Defaults.EnvCommandTimeout)
	}
}

func TestLoadConfigFileScoped_TrustedKeepsEnvCommands(t *testing.T) {
	path := writeEnvCommandsConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, true); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	if cfg.Defaults.EnvCommands["TOKEN"] != "echo secret" {
		t.Errorf("env_commands from trusted config must be kept, got %+v", cfg.Defaults.EnvCommands)
	}
	if cfg.Defaults.EnvCommandTimeout != "5s" {
		t.Errorf("env_command_timeout from trusted config must be kept, got %q", cfg.Defaults.EnvCommandTimeout)
	}
}

func TestLoadProfileDirectories_UntrustedStripsEnvCommands(t *testing.T) {
	body := "[env_commands]\nTOKEN = \"echo secret\"\n"
	root, _ := writeProfile(t, body)
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, false); err != nil {
		t.Fatalf("loadProfileDirectories: %v", err)
	}
	if len(cfg.Profiles["dev"].EnvCommands) != 0 {
		t.Errorf("env_commands from untrusted profile must be stripped, got %+v", cfg.Profiles["dev"].EnvCommands)
	}
}

func TestLoadProfileDirectories_TrustedKeepsEnvCommands(t *testing.T) {
	body := "[env_commands]\nTOKEN = \"echo secret\"\n"
	root, _ := writeProfile(t, body)
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, true); err != nil {
		t.Fatalf("loadProfileDirectories: %v", err)
	}
	if cfg.Profiles["dev"].EnvCommands["TOKEN"] != "echo secret" {
		t.Errorf("env_commands from trusted profile must be kept, got %+v", cfg.Profiles["dev"].EnvCommands)
	}
}

func TestLoadConfigFileScoped_TrustedDoesNotMarkMounts(t *testing.T) {
	path := writeMountConfig(t)
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, path, true); err != nil {
		t.Fatalf("loadConfigFileScoped: %v", err)
	}
	m, ok := findMount(cfg, "/mnt/x")
	if !ok {
		t.Fatal("mount /mnt/x was not loaded")
	}
	if m.Untrusted {
		t.Error("mount from trusted config must not be marked Untrusted")
	}
	if m.SourcePath != "" {
		t.Errorf("trusted mount SourcePath should be empty, got %q", m.SourcePath)
	}
}

// TestLoad_CredentialsSurviveRealPath is an end-to-end test through the real
// production entry point (Load()), not struct literals. It plants
// [[credentials]] in both an untrusted top-level project config
// (<workspace>/.coi/config.toml) and an untrusted project-scoped profile
// (<workspace>/.coi/profiles/dev/config.toml), then verifies the entries
// survive TOML decode, JSON-schema validation, Config.Merge /
// synthesizeDefaultProfile, and untrusted trust-marking — closing the gap
// where every prior credentials test built config.CredentialEntry structs
// directly and so never exercised this path.
func TestLoad_CredentialsSurviveRealPath(t *testing.T) {
	tmpHome := t.TempDir()
	workDir := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("COI_CONFIG", "")
	t.Chdir(workDir)

	// Untrusted top-level project config: exercises Config.Merge (previously
	// dropped Credentials silently) and the loadConfigFileScoped
	// markUntrustedCredentials call site.
	topLevelDir := filepath.Join(workDir, ".coi")
	if err := os.MkdirAll(topLevelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(topLevelDir, "config.toml"),
		[]byte("[[credentials]]\nbundle = \"ollama-toplevel\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Untrusted project-scoped profile: exercises real JSON-schema validation
	// (profile.schema.json previously rejected [[credentials]] entirely) and
	// the loadProfileDirectories markUntrustedCredentials call site.
	profileDir := filepath.Join(topLevelDir, "profiles", "dev")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"),
		[]byte("[[credentials]]\nbundle = \"ollama-profile\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v (a profile with [[credentials]] must pass schema validation)", err)
	}

	// Config.Merge must have carried the top-level project credential in, and
	// loadConfigFileScoped must have marked it untrusted.
	if len(cfg.Credentials) != 1 || cfg.Credentials[0].Bundle != "ollama-toplevel" {
		t.Fatalf("top-level cfg.Credentials not merged: %+v", cfg.Credentials)
	}
	if !cfg.Credentials[0].Untrusted {
		t.Error("top-level project credential must be marked Untrusted")
	}
	if cfg.Credentials[0].SourcePath == "" {
		t.Error("top-level project credential must have SourcePath set")
	}

	// synthesizeDefaultProfile must clone top-level Credentials into the
	// built-in "default" profile rather than dropping them.
	def, ok := cfg.Profiles["default"]
	if !ok {
		t.Fatal("default profile not synthesized")
	}
	if len(def.Credentials) != 1 || def.Credentials[0].Bundle != "ollama-toplevel" {
		t.Fatalf("synthesized default profile did not clone Credentials: %+v", def.Credentials)
	}

	// The project-scoped "dev" profile must have loaded (schema validation
	// passed) and been marked untrusted.
	dev, ok := cfg.Profiles["dev"]
	if !ok {
		t.Fatal("dev profile not loaded")
	}
	if len(dev.Credentials) != 1 || dev.Credentials[0].Bundle != "ollama-profile" {
		t.Fatalf("profile Credentials not loaded: %+v", dev.Credentials)
	}
	if !dev.Credentials[0].Untrusted {
		t.Error("project-scoped profile credential must be marked Untrusted")
	}
	if dev.Credentials[0].SourcePath == "" {
		t.Error("project-scoped profile credential must have SourcePath set")
	}
}

// [tool] pre_launch runs commands automatically at session start, so it is
// honored from trusted scope only: kept from ~/.coi config and ~/.coi
// profiles, stripped from a project's .coi/config.toml and project profiles.
func TestPreLaunch_TrustedScopeOnly(t *testing.T) {
	const body = "[tool]\npre_launch = [\"claude update\"]\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	trusted := GetDefaultConfig()
	if err := loadConfigFileScoped(trusted, path, true); err != nil {
		t.Fatal(err)
	}
	if len(trusted.Tool.PreLaunch) != 1 || trusted.Tool.PreLaunch[0] != "claude update" {
		t.Errorf("trusted config must keep pre_launch, got %v", trusted.Tool.PreLaunch)
	}
	untrusted := GetDefaultConfig()
	if err := loadConfigFileScoped(untrusted, path, false); err != nil {
		t.Fatal(err)
	}
	if len(untrusted.Tool.PreLaunch) != 0 {
		t.Errorf("project config must not set pre_launch, got %v", untrusted.Tool.PreLaunch)
	}

	root, _ := writeProfile(t, body)
	tp := GetDefaultConfig()
	if err := loadProfileDirectories(tp, root, true); err != nil {
		t.Fatal(err)
	}
	if p := tp.Profiles["dev"]; p.Tool == nil || len(p.Tool.PreLaunch) != 1 {
		t.Errorf("trusted profile must keep pre_launch, got %+v", p.Tool)
	}
	up := GetDefaultConfig()
	if err := loadProfileDirectories(up, root, false); err != nil {
		t.Fatal(err)
	}
	if p := up.Profiles["dev"]; p.Tool != nil && len(p.Tool.PreLaunch) != 0 {
		t.Errorf("project profile must not set pre_launch, got %v", p.Tool.PreLaunch)
	}
}

// A project profile must not read arbitrary host files into the container via
// [tool] context_file / context_json_file — the same rule as a project's
// top-level config (the profile path used to skip sanitizeUntrustedTool).
func TestLoadProfileDirectories_UntrustedStripsToolContextInjectors(t *testing.T) {
	root, _ := writeProfile(t, "[tool]\ncontext_file = \"~/.ssh/id_rsa\"\ncontext_json_file = \"~/.aws/credentials\"\n")
	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, root, false); err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["dev"]
	if p.Tool != nil && (p.Tool.ContextFile != "" || p.Tool.ContextJSONFile != "") {
		t.Errorf("project profile host-file injectors must be stripped, got %+v", p.Tool)
	}
	trusted := GetDefaultConfig()
	if err := loadProfileDirectories(trusted, root, true); err != nil {
		t.Fatal(err)
	}
	if trusted.Profiles["dev"].Tool.ContextFile != "~/.ssh/id_rsa" {
		t.Error("a trusted profile keeps context_file")
	}
}
