package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("COI_CONFIG", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("Expected config, got nil")
	}

	// Should have defaults
	if cfg.Container.Image == "" {
		t.Error("Expected default image to be set")
	}
}

func TestLoadConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	configContent := `
[container]
image = "test-image"

[tool.claude]
model = "test-model"

[incus]
code_uid = 2000
`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Load the config
	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, configPath, true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	// Verify values
	if cfg.Container.Image != "test-image" {
		t.Errorf("Expected image 'test-image', got '%s'", cfg.Container.Image)
	}

	if cfg.Tool.Claude.Model != "test-model" {
		t.Errorf("Expected tool.claude.model 'test-model', got '%s'", cfg.Tool.Claude.Model)
	}

	if cfg.Incus.CodeUID != 2000 {
		t.Errorf("Expected CodeUID 2000, got %d", cfg.Incus.CodeUID)
	}
}

func TestLoadConfigFileNotExists(t *testing.T) {
	cfg := GetDefaultConfig()
	err := loadConfigFileScoped(cfg, "/nonexistent/path/config.toml", true)

	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	if !os.IsNotExist(err) {
		t.Errorf("Expected os.IsNotExist error, got: %v", err)
	}
}

func TestLoadConfigFileInvalid(t *testing.T) {
	// Create an invalid TOML file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.toml")

	invalidContent := `
[defaults
image = "broken
`

	if err := os.WriteFile(configPath, []byte(invalidContent), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := GetDefaultConfig()
	err := loadConfigFileScoped(cfg, configPath, true)

	if err == nil {
		t.Error("Expected error for invalid TOML")
	}
}

func TestBuildScriptPathResolution(t *testing.T) {
	// Create a temporary config file with a relative build.script path
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}

	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
[container.build]
script = "build.sh"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, configPath, true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	// Script should be resolved relative to config file directory (.coi/build.sh)
	expectedPath := filepath.Join(configDir, "build.sh")
	if cfg.Container.Build.Script != expectedPath {
		t.Errorf("Expected script path %q, got %q", expectedPath, cfg.Container.Build.Script)
	}
}

func TestBuildScriptAbsolutePath(t *testing.T) {
	// Absolute paths should pass through unchanged
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	configContent := `
[container.build]
script = "/absolute/path/to/build.sh"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, configPath, true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	if cfg.Container.Build.Script != "/absolute/path/to/build.sh" {
		t.Errorf("Expected absolute path to be preserved, got %q", cfg.Container.Build.Script)
	}
}

func TestBuildScriptTildePath(t *testing.T) {
	// Tilde paths should be expanded
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	configContent := `
[container.build]
script = "~/build-scripts/build.sh"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, configPath, true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	homeDir, _ := os.UserHomeDir()
	expectedPath := filepath.Join(homeDir, "build-scripts/build.sh")
	if cfg.Container.Build.Script != expectedPath {
		t.Errorf("Expected tilde-expanded path %q, got %q", expectedPath, cfg.Container.Build.Script)
	}
}

func TestDotCoiTomlDeprecationError(t *testing.T) {
	// Create a temp directory and change to it
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get cwd: %v", err)
	}
	defer os.Chdir(oldDir) //nolint:errcheck

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Create .coi.toml
	if err := os.WriteFile(filepath.Join(tmpDir, ".coi.toml"), []byte("[defaults]\nimage = \"test\"\n"), 0o644); err != nil {
		t.Fatalf("Failed to create .coi.toml: %v", err)
	}

	// Load should fail with deprecation error
	_, loadErr := Load()
	if loadErr == nil {
		t.Fatal("Expected error when .coi.toml exists, got nil")
	}

	expectedMsg := "found .coi.toml in project root"
	if !strings.Contains(loadErr.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got: %v", expectedMsg, loadErr)
	}

	// Should also mention migration command
	expectedMigration := "mkdir -p .coi && mv .coi.toml .coi/config.toml"
	if !strings.Contains(loadErr.Error(), expectedMigration) {
		t.Errorf("Expected error containing migration instructions %q, got: %v", expectedMigration, loadErr)
	}
}

func TestDotCoiDirConfigLoads(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("COI_CONFIG", "")

	// Create a temp directory with .coi/config.toml and change to it
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get cwd: %v", err)
	}
	defer os.Chdir(oldDir) //nolint:errcheck

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}

	// Create .coi/config.toml
	coiDir := filepath.Join(tmpDir, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatalf("Failed to create .coi dir: %v", err)
	}
	configContent := `
[container]
image = "coi-test-project"
`
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create config.toml: %v", err)
	}

	cfg, loadErr := Load()
	if loadErr != nil {
		t.Fatalf("Load() failed: %v", loadErr)
	}

	if cfg.Container.Image != "coi-test-project" {
		t.Errorf("Expected image 'coi-test-project', got %q", cfg.Container.Image)
	}
}

func TestResolveRelativePath(t *testing.T) {
	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		baseDir  string
		path     string
		expected string
	}{
		{
			name:     "relative path",
			baseDir:  "/project/.coi",
			path:     "build.sh",
			expected: "/project/.coi/build.sh",
		},
		{
			name:     "absolute path unchanged",
			baseDir:  "/project/.coi",
			path:     "/usr/local/bin/build.sh",
			expected: "/usr/local/bin/build.sh",
		},
		{
			name:     "tilde path expanded",
			baseDir:  "/project/.coi",
			path:     "~/scripts/build.sh",
			expected: filepath.Join(homeDir, "scripts/build.sh"),
		},
		{
			name:     "nested relative path",
			baseDir:  "/project/.coi",
			path:     "scripts/build.sh",
			expected: "/project/.coi/scripts/build.sh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveRelativePath(tt.baseDir, tt.path)
			if result != tt.expected {
				t.Errorf("resolveRelativePath(%q, %q) = %q, want %q", tt.baseDir, tt.path, result, tt.expected)
			}
		})
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		Paths: PathsConfig{
			SessionsDir: filepath.Join(tmpDir, "sessions"),
			StorageDir:  filepath.Join(tmpDir, "storage"),
			LogsDir:     filepath.Join(tmpDir, "logs"),
		},
	}

	if err := ensureDirectories(cfg); err != nil {
		t.Fatalf("ensureDirectories() failed: %v", err)
	}

	// Check directories were created
	dirs := []string{cfg.Paths.SessionsDir, cfg.Paths.StorageDir, cfg.Paths.LogsDir}
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil {
			t.Errorf("Directory not created: %s: %v", dir, err)
		} else if !info.IsDir() {
			t.Errorf("Expected directory, got file: %s", dir)
		}
	}
}

func TestLoadProfileFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "rust-dev")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	// Create profile config.toml
	profileContent := `
forward_env = ["RUST_BACKTRACE"]

[container]
image = "coi-rust"
persistent = true

[container.build]
base = "coi"
script = "build.sh"

[environment]
RUST_BACKTRACE = "1"

[tool]
name = "claude"
permission_mode = "bypass"

[tool.claude]
effort_level = "high"

[[mounts]]
host = "~/.cargo"
container = "/home/code/.cargo"

[limits.cpu]
count = "4"

[network]
mode = "restricted"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}

	// Create main config.toml (empty)
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	// Verify profile was loaded
	p := cfg.GetProfile("rust-dev")
	if p == nil {
		t.Fatal("Expected profile 'rust-dev' to be loaded from directory")
	}

	if p.Container.Image != "coi-rust" {
		t.Errorf("Expected image 'coi-rust', got %q", p.Container.Image)
	}
	if p.Container.Persistent == nil || !*p.Container.Persistent {
		t.Error("Expected persistent=true")
	}
	if len(p.ForwardEnv) != 1 || p.ForwardEnv[0] != "RUST_BACKTRACE" {
		t.Errorf("Expected forward_env=[RUST_BACKTRACE], got %v", p.ForwardEnv)
	}
	if p.Environment["RUST_BACKTRACE"] != "1" {
		t.Errorf("Expected RUST_BACKTRACE=1, got %q", p.Environment["RUST_BACKTRACE"])
	}
	if p.Tool == nil || p.Tool.Name != "claude" {
		t.Error("Expected tool.name=claude")
	}
	if p.Tool.PermissionMode != "bypass" {
		t.Errorf("Expected permission_mode=bypass, got %q", p.Tool.PermissionMode)
	}
	if p.Tool.Claude.EffortLevel != "high" {
		t.Errorf("Expected effort_level=high, got %q", p.Tool.Claude.EffortLevel)
	}
	if p.Container.Build.Base != "coi" {
		t.Error("Expected build.base=coi")
	}
	if len(p.Mounts) != 1 || p.Mounts[0].Host != "~/.cargo" {
		t.Errorf("Expected mount host=~/.cargo, got %v", p.Mounts)
	}
	if p.Network == nil || p.Network.Mode != NetworkModeRestricted {
		t.Error("Expected network.mode=restricted")
	}
	if p.Limits == nil || p.Limits.CPU.Count != "4" {
		t.Error("Expected limits.cpu.count=4")
	}
}

func TestProfileDirectoryBuildScriptResolution(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "test")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `
[container.build]
script = "build.sh"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	p := cfg.GetProfile("test")
	if p == nil {
		t.Fatal("Expected profile 'test' to be loaded")
	}

	expectedScript := filepath.Join(profileDir, "build.sh")
	if p.Container.Build.Script != expectedScript {
		t.Errorf("Expected build script %q, got %q", expectedScript, p.Container.Build.Script)
	}
}

func TestProfileDirectoryAbsoluteScriptPath(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "test")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `
[container.build]
script = "/absolute/path/build.sh"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	p := cfg.GetProfile("test")
	if p == nil {
		t.Fatal("Expected profile 'test' to be loaded")
	}
	if p.Container.Build.Script != "/absolute/path/build.sh" {
		t.Errorf("Expected absolute path preserved, got %q", p.Container.Build.Script)
	}
}

func TestProfileDirectoryNoConfigToml(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "empty-profile")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	// No config.toml in profile directory, just create main config
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	// Profile should not be loaded (no config.toml)
	p := cfg.GetProfile("empty-profile")
	if p != nil {
		t.Error("Profile without config.toml should not be loaded")
	}
}

func TestProfileDirectoryWithFileNotDir(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profilesDir := filepath.Join(configDir, "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		t.Fatalf("Failed to create profiles dir: %v", err)
	}

	// Create a file (not directory) inside profiles/
	if err := os.WriteFile(filepath.Join(profilesDir, "not-a-dir"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	// Should not crash or add spurious profiles
	p := cfg.GetProfile("not-a-dir")
	if p != nil {
		t.Error("Files in profiles/ dir should not be loaded as profiles")
	}
}

func TestProfileDirectoryInvalidTomlReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "broken")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte("[invalid toml {\n"), 0o644); err != nil {
		t.Fatalf("Failed to write broken config: %v", err)
	}

	cfg := GetDefaultConfig()
	err := loadProfileDirectories(cfg, configDir, true)
	if err == nil {
		t.Fatal("Expected error for invalid TOML, got nil")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("Error should mention profile name 'broken', got: %v", err)
	}
}

func TestProfileDirectorySource(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "src-test")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `[container]
image = "test-image"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	p := cfg.GetProfile("src-test")
	if p == nil {
		t.Fatal("Expected profile 'src-test'")
	}

	expectedSource := filepath.Join(profileDir, "config.toml")
	if p.Source != expectedSource {
		t.Errorf("Expected source %q, got %q", expectedSource, p.Source)
	}
}

func TestApplyProfileWithNewFields(t *testing.T) {
	// Create a real build script for validation
	tmpDir := t.TempDir()
	buildScript := filepath.Join(tmpDir, "build.sh")
	if err := os.WriteFile(buildScript, []byte("#!/bin/bash\necho build\n"), 0o755); err != nil {
		t.Fatalf("Failed to create build script: %v", err)
	}

	cfg := GetDefaultConfig()
	cfg.Profiles["full"] = ProfileConfig{
		Container: ContainerConfig{
			Image:      "test-image",
			Persistent: ptrBool(true),
			Build: BuildConfig{
				Base:   "coi",
				Script: buildScript,
			},
		},
		Environment: map[string]string{
			"MY_VAR": "val",
		},
		Tool: &ToolConfig{
			Name:           "aider",
			PermissionMode: "interactive",
			Claude: ClaudeToolConfig{
				EffortLevel: "high",
			},
		},
		Mounts: []MountEntry{
			{Host: "~/.cargo", Container: "/home/code/.cargo"},
			{Host: "~/.claude/skills", Container: "/home/code/.claude/skills", Readonly: true},
		},
		Network: &NetworkConfig{
			Mode: NetworkModeOpen,
		},
		ForwardEnv: []string{"API_KEY", "TOKEN"},
	}

	if err := cfg.ApplyProfile("full"); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	// Verify container settings were applied
	if cfg.Container.Image != "test-image" {
		t.Errorf("Expected image 'test-image', got %q", cfg.Container.Image)
	}
	if !*cfg.Container.Persistent {
		t.Error("Expected persistent=true")
	}
	if cfg.Defaults.Environment["MY_VAR"] != "val" {
		t.Error("Expected environment MY_VAR=val")
	}

	// Tool
	if cfg.Tool.Name != "aider" {
		t.Errorf("Expected tool name 'aider', got %q", cfg.Tool.Name)
	}
	if cfg.Tool.PermissionMode != "interactive" {
		t.Errorf("Expected permission_mode 'interactive', got %q", cfg.Tool.PermissionMode)
	}
	if cfg.Tool.Claude.EffortLevel != "high" {
		t.Errorf("Expected effort_level 'high', got %q", cfg.Tool.Claude.EffortLevel)
	}

	// Build
	if cfg.Container.Build.Base != "coi" {
		t.Errorf("Expected build base 'coi', got %q", cfg.Container.Build.Base)
	}
	if cfg.Container.Build.Script != buildScript {
		t.Errorf("Expected build script %q, got %q", buildScript, cfg.Container.Build.Script)
	}

	// Mounts (appended)
	found := false
	foundReadonly := false
	for _, m := range cfg.Mounts.Default {
		if m.Host == "~/.cargo" {
			found = true
			if m.Readonly {
				t.Error("Expected ~/.cargo mount to NOT be readonly")
			}
		}
		if m.Host == "~/.claude/skills" {
			foundReadonly = true
			if !m.Readonly {
				t.Error("Expected ~/.claude/skills mount to be readonly")
			}
		}
	}
	if !found {
		t.Error("Expected mount ~/.cargo to be appended")
	}
	if !foundReadonly {
		t.Error("Expected readonly mount ~/.claude/skills to be appended")
	}

	// Network
	if cfg.Network.Mode != NetworkModeOpen {
		t.Errorf("Expected network mode 'open', got %q", cfg.Network.Mode)
	}

	// ForwardEnv
	if len(cfg.Defaults.ForwardEnv) < 2 {
		t.Errorf("Expected at least 2 forward_env entries, got %d", len(cfg.Defaults.ForwardEnv))
	}
	envMap := make(map[string]bool)
	for _, e := range cfg.Defaults.ForwardEnv {
		envMap[e] = true
	}
	if !envMap["API_KEY"] || !envMap["TOKEN"] {
		t.Errorf("Expected API_KEY and TOKEN in forward_env, got %v", cfg.Defaults.ForwardEnv)
	}
}

func TestLoadConfigFileWithReadonlyMount(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	configContent := `
[container]
image = "coi"

[[mounts.default]]
host = "~/.claude/skills"
container = "/home/code/.claude/skills"
readonly = true

[[mounts.default]]
host = "~/data"
container = "/data"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadConfigFileScoped(cfg, configPath, true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	if len(cfg.Mounts.Default) != 2 {
		t.Fatalf("Expected 2 mounts, got %d", len(cfg.Mounts.Default))
	}

	// First mount should be readonly
	if cfg.Mounts.Default[0].Host != "~/.claude/skills" {
		t.Errorf("Expected first mount host '~/.claude/skills', got %q", cfg.Mounts.Default[0].Host)
	}
	if !cfg.Mounts.Default[0].Readonly {
		t.Error("Expected first mount to be readonly")
	}

	// Second mount should not be readonly
	if cfg.Mounts.Default[1].Host != "~/data" {
		t.Errorf("Expected second mount host '~/data', got %q", cfg.Mounts.Default[1].Host)
	}
	if cfg.Mounts.Default[1].Readonly {
		t.Error("Expected second mount to NOT be readonly")
	}
}

func TestLoadProfileWithReadonlyMount(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "readonly-test")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `
[container]
image = "coi"

[[mounts]]
host = "~/.claude/commands"
container = "/home/code/.claude/commands"
readonly = true
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}

	p := cfg.GetProfile("readonly-test")
	if p == nil {
		t.Fatal("Expected profile 'readonly-test' to be loaded")
	}
	if len(p.Mounts) != 1 {
		t.Fatalf("Expected 1 mount, got %d", len(p.Mounts))
	}
	if !p.Mounts[0].Readonly {
		t.Error("Expected mount to be readonly")
	}
	if p.Mounts[0].Host != "~/.claude/commands" {
		t.Errorf("Expected host '~/.claude/commands', got %q", p.Mounts[0].Host)
	}
}

func TestApplyProfileToolPartialMerge(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Tool.Name = "claude"
	cfg.Tool.PermissionMode = "bypass"

	// Profile only overrides effort level
	cfg.Profiles["partial"] = ProfileConfig{
		Tool: &ToolConfig{
			Claude: ClaudeToolConfig{
				EffortLevel: "low",
			},
		},
	}

	if err := cfg.ApplyProfile("partial"); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	// Name and permission_mode should be preserved
	if cfg.Tool.Name != "claude" {
		t.Errorf("Expected tool name preserved as 'claude', got %q", cfg.Tool.Name)
	}
	if cfg.Tool.PermissionMode != "bypass" {
		t.Errorf("Expected permission_mode preserved as 'bypass', got %q", cfg.Tool.PermissionMode)
	}
	if cfg.Tool.Claude.EffortLevel != "low" {
		t.Errorf("Expected effort_level 'low', got %q", cfg.Tool.Claude.EffortLevel)
	}
}

func TestProfileValidation(t *testing.T) {
	tests := []struct {
		name      string
		profile   ProfileConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid empty profile",
			profile: ProfileConfig{Container: ContainerConfig{Image: "coi"}},
			wantErr: false,
		},
		{
			name: "missing build script",
			profile: ProfileConfig{
				Container: ContainerConfig{
					Build: BuildConfig{Script: "/nonexistent/build.sh"},
				},
			},
			wantErr:   true,
			errSubstr: "build script",
		},
		{
			name: "mount missing host",
			profile: ProfileConfig{
				Mounts: []MountEntry{{Container: "/data"}},
			},
			wantErr:   true,
			errSubstr: "missing 'host'",
		},
		{
			name: "mount missing container",
			profile: ProfileConfig{
				Mounts: []MountEntry{{Host: "~/data"}},
			},
			wantErr:   true,
			errSubstr: "missing 'container'",
		},
		{
			name: "invalid network mode",
			profile: ProfileConfig{
				Network: &NetworkConfig{Mode: "bogus"},
			},
			wantErr:   true,
			errSubstr: "invalid network mode",
		},
		{
			name: "valid network mode restricted",
			profile: ProfileConfig{
				Network: &NetworkConfig{Mode: "restricted"},
			},
			wantErr: false,
		},
		{
			name: "valid network mode allowlist",
			profile: ProfileConfig{
				Network: &NetworkConfig{Mode: "allowlist"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate("test")
			if tt.wantErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Expected no error, got: %v", err)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("Expected error containing %q, got: %v", tt.errSubstr, err)
			}
		})
	}
}

func TestLoadProfilesFromHomeCoi(t *testing.T) {
	// Verify that profiles placed in ~/.coi/profiles/ are picked up by Load().
	// This lets users place profiles alongside their sessions/storage/logs
	// (which live under ~/.coi).
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Also change to a temp workdir so the project ./.coi doesn't interfere
	tmpWork := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldWd) //nolint:errcheck
	if err := os.Chdir(tmpWork); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// Create a profile under ~/.coi/profiles/home-coi-prof/config.toml
	profDir := filepath.Join(tmpHome, ".coi", "profiles", "home-coi-prof")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	content := "[container]\nimage = \"home-coi-image\"\n"
	if err := os.WriteFile(filepath.Join(profDir, "config.toml"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, loadErr := Load()
	if loadErr != nil {
		t.Fatalf("Load() failed: %v", loadErr)
	}

	p := cfg.GetProfile("home-coi-prof")
	if p == nil {
		t.Fatal("Expected profile 'home-coi-prof' to be loaded from ~/.coi/profiles/")
	}
	if p.Container.Image != "home-coi-image" {
		t.Errorf("Expected image 'home-coi-image', got %q", p.Container.Image)
	}
}

func TestLoadMergesProjectAndHomeProfiles(t *testing.T) {
	// Project-local .coi/profiles/ should be merged alongside ~/.coi/profiles/
	// when profile names are unique.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	tmpWork := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldWd) //nolint:errcheck
	if err := os.Chdir(tmpWork); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// Profile in ~/.coi/profiles/
	homeProf := filepath.Join(tmpHome, ".coi", "profiles", "from-home")
	if err := os.MkdirAll(homeProf, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeProf, "config.toml"), []byte("[container]\nimage = \"home-image\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Profile in project .coi/profiles/
	projProf := filepath.Join(tmpWork, ".coi", "profiles", "from-project")
	if err := os.MkdirAll(projProf, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projProf, "config.toml"), []byte("[container]\nimage = \"project-image\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, loadErr := Load()
	if loadErr != nil {
		t.Fatalf("Load() failed: %v", loadErr)
	}

	if p := cfg.GetProfile("from-home"); p == nil || p.Container.Image != "home-image" {
		t.Errorf("Expected from-home profile merged, got %+v", p)
	}
	if p := cfg.GetProfile("from-project"); p == nil || p.Container.Image != "project-image" {
		t.Errorf("Expected from-project profile merged, got %+v", p)
	}
}

func TestLoadDuplicateProfileProjectVsHomeFails(t *testing.T) {
	// Duplicate profile name between project .coi/profiles/ and ~/.coi/profiles/
	// should also error — project and home locations are merged into the same
	// namespace just like the two home locations.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	tmpWork := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldWd) //nolint:errcheck
	if err := os.Chdir(tmpWork); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	homeProf := filepath.Join(tmpHome, ".coi", "profiles", "dup")
	if err := os.MkdirAll(homeProf, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeProf, "config.toml"), []byte("[container]\nimage = \"from-home\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	projProf := filepath.Join(tmpWork, ".coi", "profiles", "dup")
	if err := os.MkdirAll(projProf, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projProf, "config.toml"), []byte("[container]\nimage = \"from-project\"\n"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, loadErr := Load()
	if loadErr == nil {
		t.Fatal("Expected Load() to fail on duplicate across home and project")
	}
	msg := loadErr.Error()
	if !strings.Contains(msg, "dup") || !strings.Contains(msg, "multiple locations") {
		t.Errorf("Error should mention 'dup' and 'multiple locations', got: %v", loadErr)
	}
	if !strings.Contains(msg, filepath.Join(homeProf, "config.toml")) {
		t.Errorf("Error should reference ~/.coi path, got: %v", loadErr)
	}
	if !strings.Contains(msg, filepath.Join(projProf, "config.toml")) {
		t.Errorf("Error should reference project .coi path, got: %v", loadErr)
	}
}

func TestLoadProfileDirectoriesDuplicateNameError(t *testing.T) {
	// Unit test for loadProfileDirectories itself: calling it twice with
	// different parent dirs containing the same profile name should error.
	tmpDir := t.TempDir()
	dir1 := filepath.Join(tmpDir, "loc1")
	dir2 := filepath.Join(tmpDir, "loc2")
	for _, d := range []string{dir1, dir2} {
		prof := filepath.Join(d, "profiles", "conflict")
		if err := os.MkdirAll(prof, 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(filepath.Join(prof, "config.toml"), []byte("[container]\nimage = \"x\"\n"), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, dir1, true); err != nil {
		t.Fatalf("First loadProfileDirectories should succeed, got: %v", err)
	}
	err := loadProfileDirectories(cfg, dir2, true)
	if err == nil {
		t.Fatal("Expected error on second load with conflicting profile name")
	}
	if !strings.Contains(err.Error(), "conflict") {
		t.Errorf("Error should mention profile name 'conflict', got: %v", err)
	}
	if !strings.Contains(err.Error(), "multiple locations") {
		t.Errorf("Error should mention 'multiple locations', got: %v", err)
	}
}

func TestMultipleProfileDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")

	// Create two profile directories
	for _, name := range []string{"alpha", "beta"} {
		profileDir := filepath.Join(configDir, "profiles", name)
		if err := os.MkdirAll(profileDir, 0o755); err != nil {
			t.Fatalf("Failed to create profile dir: %v", err)
		}
		content := fmt.Sprintf("[container]\nimage = \"img-%s\"\n", name)
		if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(content), 0o644); err != nil {
			t.Fatalf("Failed to write profile config: %v", err)
		}
	}

	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write main config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}
	if err := loadConfigFileScoped(cfg, filepath.Join(configDir, "config.toml"), true); err != nil {
		t.Fatalf("loadConfigFile() failed: %v", err)
	}

	a := cfg.GetProfile("alpha")
	if a == nil || a.Container.Image != "img-alpha" {
		t.Error("Expected profile 'alpha' with image 'img-alpha'")
	}
	b := cfg.GetProfile("beta")
	if b == nil || b.Container.Image != "img-beta" {
		t.Error("Expected profile 'beta' with image 'img-beta'")
	}
}

func TestProfileContextPathResolution(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "ctx-test")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `
context = "CONTEXT.md"

[container]
image = "coi"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}

	p := cfg.GetProfile("ctx-test")
	if p == nil {
		t.Fatal("Expected profile 'ctx-test' to be loaded")
	}

	expectedPath := filepath.Join(profileDir, "CONTEXT.md")
	if p.Context != expectedPath {
		t.Errorf("Expected context path %q, got %q", expectedPath, p.Context)
	}
}

func TestProfileContextAbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".coi")
	profileDir := filepath.Join(configDir, "profiles", "ctx-abs")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("Failed to create profile dir: %v", err)
	}

	profileContent := `
context = "/absolute/path/CONTEXT.md"

[container]
image = "coi"
`
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte(profileContent), 0o644); err != nil {
		t.Fatalf("Failed to write profile config: %v", err)
	}

	cfg := GetDefaultConfig()
	if err := loadProfileDirectories(cfg, configDir, true); err != nil {
		t.Fatalf("loadProfileDirectories() failed: %v", err)
	}

	p := cfg.GetProfile("ctx-abs")
	if p == nil {
		t.Fatal("Expected profile 'ctx-abs' to be loaded")
	}

	if p.Context != "/absolute/path/CONTEXT.md" {
		t.Errorf("Expected absolute path preserved, got %q", p.Context)
	}
}

func TestProfileContextValidationMissingFile(t *testing.T) {
	profile := ProfileConfig{
		Container: ContainerConfig{Image: "coi"},
		Context:   "/nonexistent/path/CONTEXT.md",
	}

	err := profile.Validate("test")
	if err == nil {
		t.Fatal("Expected error for missing context file, got nil")
	}
	if !strings.Contains(err.Error(), "context file") {
		t.Errorf("Error should mention 'context file', got: %v", err)
	}
}

func TestProfileContextValidationExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	contextFile := filepath.Join(tmpDir, "CONTEXT.md")
	if err := os.WriteFile(contextFile, []byte("# Profile instructions\n"), 0o644); err != nil {
		t.Fatalf("Failed to create context file: %v", err)
	}

	profile := ProfileConfig{
		Container: ContainerConfig{Image: "coi"},
		Context:   contextFile,
	}

	err := profile.Validate("test")
	if err != nil {
		t.Errorf("Expected no error for existing context file, got: %v", err)
	}
}

func TestApplyProfileSetsProfileContextFile(t *testing.T) {
	tmpDir := t.TempDir()
	contextFile := filepath.Join(tmpDir, "CONTEXT.md")
	if err := os.WriteFile(contextFile, []byte("# Profile instructions\n"), 0o644); err != nil {
		t.Fatalf("Failed to create context file: %v", err)
	}

	cfg := GetDefaultConfig()
	cfg.Profiles["ctx-profile"] = ProfileConfig{
		Container: ContainerConfig{Image: "coi"},
		Context:   contextFile,
	}

	if err := cfg.ApplyProfile("ctx-profile"); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if cfg.ProfileContextFile != contextFile {
		t.Errorf("Expected ProfileContextFile=%q, got %q", contextFile, cfg.ProfileContextFile)
	}
}

func TestApplyProfileWithoutContextLeavesEmpty(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Profiles["no-ctx"] = ProfileConfig{
		Container: ContainerConfig{Image: "coi"},
	}

	if err := cfg.ApplyProfile("no-ctx"); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if cfg.ProfileContextFile != "" {
		t.Errorf("Expected empty ProfileContextFile, got %q", cfg.ProfileContextFile)
	}
}
