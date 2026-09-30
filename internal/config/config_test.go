package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetDefaultConfig(t *testing.T) {
	cfg := GetDefaultConfig()

	if cfg == nil {
		t.Fatal("Expected default config, got nil")
	}

	// Check defaults
	if cfg.Container.Image != "coi-default" {
		t.Errorf("Expected default image 'coi-default', got '%s'", cfg.Container.Image)
	}

	// The default profile no longer pins a model — it is unset so Claude Code
	// uses its own default (model is now [tool.claude] model, opt-in).
	if cfg.Tool.Claude.Model != "" {
		t.Errorf("Expected default tool.claude.model to be unset, got '%s'", cfg.Tool.Claude.Model)
	}

	// Check Incus config
	if cfg.Incus.Project != "default" {
		t.Errorf("Expected project 'default', got '%s'", cfg.Incus.Project)
	}

	if cfg.Incus.CodeUID != 1000 {
		t.Errorf("Expected CodeUID 1000, got %d", cfg.Incus.CodeUID)
	}

	// Check paths are set
	if cfg.Paths.SessionsDir == "" {
		t.Error("Expected sessions_dir to be set")
	}
}

func TestExpandPath(t *testing.T) {
	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "expand tilde",
			input:    "~/test",
			expected: filepath.Join(homeDir, "test"),
		},
		{
			name:     "expand tilde only",
			input:    "~",
			expected: homeDir,
		},
		{
			name:     "no expansion needed",
			input:    "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "empty path",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandPath(tt.input)
			if result != tt.expected {
				t.Errorf("ExpandPath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConfigMerge(t *testing.T) {
	base := GetDefaultConfig()
	base.Container.Image = "base-image"
	base.Tool.Claude.Model = "base-model"

	other := &Config{
		Container: ContainerConfig{
			Image: "other-image",
		},
		// tool.claude.model not set - should not override
		Incus: IncusConfig{
			CodeUID: 2000, // Override
		},
	}

	base.Merge(other)

	// Check that other.Image overrode base.Image
	if base.Container.Image != "other-image" {
		t.Errorf("Expected image 'other-image', got '%s'", base.Container.Image)
	}

	// Check that base model remained because other's tool.claude.model was empty
	if base.Tool.Claude.Model != "base-model" {
		t.Errorf("Expected model 'base-model', got '%s'", base.Tool.Claude.Model)
	}

	// Check that CodeUID was overridden
	if base.Incus.CodeUID != 2000 {
		t.Errorf("Expected CodeUID 2000, got %d", base.Incus.CodeUID)
	}
}

func TestConfigMerge_AppendsSockets(t *testing.T) {
	base := GetDefaultConfig()
	base.Sockets = []SocketEntry{{Host: "/run/base.sock", Container: "/c/base.sock"}}

	other := &Config{
		Sockets: []SocketEntry{{Host: "/run/other.sock", Container: "/c/other.sock", Env: "OTHER"}},
	}
	base.Merge(other)

	if len(base.Sockets) != 2 {
		t.Fatalf("expected merged sockets to append (2), got %d", len(base.Sockets))
	}
	if base.Sockets[1].Host != "/run/other.sock" || base.Sockets[1].Env != "OTHER" {
		t.Errorf("appended socket not preserved: %+v", base.Sockets[1])
	}
}

func TestApplyProfile_AppendsSockets(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Sockets = []SocketEntry{{Host: "/run/base.sock", Container: "/c/base.sock"}}
	cfg.Profiles["broker"] = ProfileConfig{
		Sockets: []SocketEntry{{Host: "/run/broker.sock", Container: "/c/broker.sock", Env: "BROKER"}},
	}

	if err := cfg.ApplyProfile("broker"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if len(cfg.Sockets) != 2 {
		t.Fatalf("expected profile sockets appended (2), got %d", len(cfg.Sockets))
	}
	if cfg.Sockets[1].Env != "BROKER" {
		t.Errorf("profile socket not appended: %+v", cfg.Sockets)
	}
}

func TestConfigMerge_MergesEnvCommands(t *testing.T) {
	base := GetDefaultConfig()
	base.Defaults.EnvCommands = map[string]string{"A": "echo a", "SHARED": "base"}
	base.Defaults.EnvCommandTimeout = "10s"

	other := &Config{
		Defaults: DefaultsConfig{
			EnvCommands:       map[string]string{"B": "echo b", "SHARED": "other"},
			EnvCommandTimeout: "45s",
		},
	}
	base.Merge(other)

	if len(base.Defaults.EnvCommands) != 3 {
		t.Fatalf("expected 3 merged env_commands, got %d", len(base.Defaults.EnvCommands))
	}
	if base.Defaults.EnvCommands["SHARED"] != "other" {
		t.Errorf("later source should override on key collision, got %q", base.Defaults.EnvCommands["SHARED"])
	}
	if base.Defaults.EnvCommandTimeout != "45s" {
		t.Errorf("non-empty timeout should override, got %q", base.Defaults.EnvCommandTimeout)
	}
}

func TestApplyProfile_MergesEnvCommands(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Defaults.EnvCommands = map[string]string{"A": "echo a"}
	cfg.Profiles["broker"] = ProfileConfig{
		EnvCommands: map[string]string{"TOKEN": "mint.sh"},
	}

	if err := cfg.ApplyProfile("broker"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	if len(cfg.Defaults.EnvCommands) != 2 || cfg.Defaults.EnvCommands["TOKEN"] != "mint.sh" {
		t.Fatalf("profile env_commands not merged: %+v", cfg.Defaults.EnvCommands)
	}
}

func TestGetProfile(t *testing.T) {
	cfg := GetDefaultConfig()

	// Add a test profile
	cfg.Profiles["test"] = ProfileConfig{
		Container: ContainerConfig{
			Image:      "test-image",
			Persistent: ptrBool(true),
		},
	}

	// Test getting existing profile
	profile := cfg.GetProfile("test")
	if profile == nil {
		t.Fatal("Expected profile, got nil")
	}

	if profile.Container.Image != "test-image" {
		t.Errorf("Expected image 'test-image', got '%s'", profile.Container.Image)
	}

	// Test getting non-existent profile
	missing := cfg.GetProfile("nonexistent")
	if missing != nil {
		t.Error("Expected nil for non-existent profile")
	}
}

func TestApplyProfile(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Container.Image = "original-image"

	// Add a test profile
	cfg.Profiles["rust"] = ProfileConfig{
		Container: ContainerConfig{
			Image:      "rust-image",
			Persistent: ptrBool(true),
		},
	}

	// Apply the profile
	if err := cfg.ApplyProfile("rust"); err != nil {
		t.Errorf("Expected ApplyProfile to succeed, got: %v", err)
	}

	// Check that container settings were updated
	if cfg.Container.Image != "rust-image" {
		t.Errorf("Expected image 'rust-image', got '%s'", cfg.Container.Image)
	}

	if cfg.Container.Persistent == nil || !*cfg.Container.Persistent {
		t.Error("Expected persistent to be true")
	}

	// Try to apply non-existent profile
	if err := cfg.ApplyProfile("nonexistent"); err == nil {
		t.Error("Expected ApplyProfile to return error for non-existent profile")
	}
}

func TestGetConfigPaths(t *testing.T) {
	// Ensure COI_CONFIG doesn't leak in
	oldEnv := os.Getenv("COI_CONFIG")
	os.Unsetenv("COI_CONFIG")
	defer func() {
		if oldEnv != "" {
			os.Setenv("COI_CONFIG", oldEnv)
		}
	}()

	paths := GetConfigPaths()

	if len(paths) != 2 {
		t.Fatalf("Expected exactly 2 config paths (user + project), got %d: %v", len(paths), paths)
	}

	homeDir, _ := os.UserHomeDir()
	workDir, _ := os.Getwd()

	expected := []string{
		filepath.Join(homeDir, ".coi", "config.toml"),
		filepath.Join(workDir, ".coi", "config.toml"),
	}

	for i, want := range expected {
		if paths[i] != want {
			t.Errorf("paths[%d] = %q, want %q", i, paths[i], want)
		}
	}
}

func TestGetProfileParentDirs(t *testing.T) {
	// Ensure COI_CONFIG doesn't leak in
	oldEnv := os.Getenv("COI_CONFIG")
	os.Unsetenv("COI_CONFIG")
	defer func() {
		if oldEnv != "" {
			os.Setenv("COI_CONFIG", oldEnv)
		}
	}()

	dirs := GetProfileParentDirs()

	if len(dirs) != 2 {
		t.Fatalf("Expected exactly 2 profile parent dirs (user + project), got %d: %v", len(dirs), dirs)
	}

	homeDir, _ := os.UserHomeDir()
	workDir, _ := os.Getwd()

	expected := []string{
		filepath.Join(homeDir, ".coi"),
		filepath.Join(workDir, ".coi"),
	}

	for i, want := range expected {
		if dirs[i] != want {
			t.Errorf("dirs[%d] = %q, want %q", i, dirs[i], want)
		}
	}
}

func TestGetProfileParentDirsWithCoiConfig(t *testing.T) {
	oldEnv := os.Getenv("COI_CONFIG")
	os.Setenv("COI_CONFIG", "/custom/path/config.toml")
	defer func() {
		if oldEnv == "" {
			os.Unsetenv("COI_CONFIG")
		} else {
			os.Setenv("COI_CONFIG", oldEnv)
		}
	}()

	dirs := GetProfileParentDirs()

	// Last entry should be the COI_CONFIG parent dir
	last := dirs[len(dirs)-1]
	if last != "/custom/path" {
		t.Errorf("Expected last dir to be /custom/path, got %q", last)
	}
}

func TestGetProfileParentDirsIncludesHomeCoi(t *testing.T) {
	// Regression test: ~/.coi/ must be scanned for profiles so users can
	// place profiles alongside sessions/storage/logs (which live under ~/.coi).
	oldEnv := os.Getenv("COI_CONFIG")
	os.Unsetenv("COI_CONFIG")
	defer func() {
		if oldEnv != "" {
			os.Setenv("COI_CONFIG", oldEnv)
		}
	}()

	dirs := GetProfileParentDirs()
	homeDir, _ := os.UserHomeDir()
	wantDir := filepath.Join(homeDir, ".coi")

	found := false
	for _, d := range dirs {
		if d == wantDir {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected %q in profile parent dirs, got: %v", wantDir, dirs)
	}
}

func TestGitConfigDefaults(t *testing.T) {
	cfg := GetDefaultConfig()

	// Default should be to NOT allow writable hooks (protection enabled)
	if cfg.Git.WritableHooks == nil || *cfg.Git.WritableHooks {
		t.Error("Expected default Git.WritableHooks to be false")
	}
}

func TestGitConfigMerge(t *testing.T) {
	ptrBool := func(b bool) *bool { return &b }

	tests := []struct {
		name           string
		baseWritable   *bool
		otherWritable  *bool
		expectedResult *bool
	}{
		{
			name:           "true merged with true",
			baseWritable:   ptrBool(true),
			otherWritable:  ptrBool(true),
			expectedResult: ptrBool(true),
		},
		{
			name:           "true merged with false",
			baseWritable:   ptrBool(true),
			otherWritable:  ptrBool(false),
			expectedResult: ptrBool(false),
		},
		{
			name:           "false merged with true",
			baseWritable:   ptrBool(false),
			otherWritable:  ptrBool(true),
			expectedResult: ptrBool(true),
		},
		{
			name:           "false merged with false",
			baseWritable:   ptrBool(false),
			otherWritable:  ptrBool(false),
			expectedResult: ptrBool(false),
		},
		{
			name:           "true merged with nil (not set)",
			baseWritable:   ptrBool(true),
			otherWritable:  nil,
			expectedResult: ptrBool(true),
		},
		{
			name:           "false merged with nil (not set)",
			baseWritable:   ptrBool(false),
			otherWritable:  nil,
			expectedResult: ptrBool(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Git.WritableHooks = tt.baseWritable

			other := &Config{
				Git: GitConfig{
					WritableHooks: tt.otherWritable,
				},
			}

			base.Merge(other)

			if tt.expectedResult == nil {
				if base.Git.WritableHooks != nil {
					t.Errorf("Expected Git.WritableHooks to be nil, got %v", *base.Git.WritableHooks)
				}
			} else {
				if base.Git.WritableHooks == nil {
					t.Errorf("Expected Git.WritableHooks to be %v, got nil", *tt.expectedResult)
				} else if *base.Git.WritableHooks != *tt.expectedResult {
					t.Errorf("Expected Git.WritableHooks to be %v, got %v", *tt.expectedResult, *base.Git.WritableHooks)
				}
			}
		})
	}
}

func TestSSHConfigDefaults(t *testing.T) {
	cfg := GetDefaultConfig()

	if cfg.SSH.ForwardAgent == nil || *cfg.SSH.ForwardAgent {
		t.Error("Expected default SSH.ForwardAgent to be false")
	}
}

func TestSSHConfigMerge(t *testing.T) {
	ptrBool := func(b bool) *bool { return &b }

	tests := []struct {
		name           string
		baseForward    *bool
		otherForward   *bool
		expectedResult *bool
	}{
		{
			name:           "false merged with true",
			baseForward:    ptrBool(false),
			otherForward:   ptrBool(true),
			expectedResult: ptrBool(true),
		},
		{
			name:           "true merged with false",
			baseForward:    ptrBool(true),
			otherForward:   ptrBool(false),
			expectedResult: ptrBool(false),
		},
		{
			name:           "false merged with nil (not set)",
			baseForward:    ptrBool(false),
			otherForward:   nil,
			expectedResult: ptrBool(false),
		},
		{
			name:           "true merged with nil (not set)",
			baseForward:    ptrBool(true),
			otherForward:   nil,
			expectedResult: ptrBool(true),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.SSH.ForwardAgent = tt.baseForward

			other := &Config{
				SSH: SSHConfig{
					ForwardAgent: tt.otherForward,
				},
			}

			base.Merge(other)

			if tt.expectedResult == nil {
				if base.SSH.ForwardAgent != nil {
					t.Errorf("Expected SSH.ForwardAgent to be nil, got %v", *base.SSH.ForwardAgent)
				}
			} else {
				if base.SSH.ForwardAgent == nil {
					t.Errorf("Expected SSH.ForwardAgent to be %v, got nil", *tt.expectedResult)
				} else if *base.SSH.ForwardAgent != *tt.expectedResult {
					t.Errorf("Expected SSH.ForwardAgent to be %v, got %v", *tt.expectedResult, *base.SSH.ForwardAgent)
				}
			}
		})
	}
}

func TestToolConfigDefaults(t *testing.T) {
	cfg := GetDefaultConfig()

	if cfg.Tool.Name != "claude" {
		t.Errorf("Expected default tool name 'claude', got '%s'", cfg.Tool.Name)
	}

	if cfg.Tool.Binary != "" {
		t.Errorf("Expected default tool binary to be empty, got '%s'", cfg.Tool.Binary)
	}
}

func TestDefaultTmpfsSize(t *testing.T) {
	cfg := GetDefaultConfig()

	// Default is empty: /tmp stays disk-backed. coi never sizes /tmp on its own
	// (that would make it RAM-backed); tmpfs_size is strictly opt-in (#728).
	if cfg.Limits.Disk.TmpfsSize != "" {
		t.Errorf("Expected default TmpfsSize '' (disk-backed /tmp), got '%s'", cfg.Limits.Disk.TmpfsSize)
	}
}

// TestLimitsHasAny pins the single limit-presence predicate shared by the shell
// and run launch paths. The size-only case is the regression guard: a disk size
// quota must trigger the applier (and its dir-pool safety check) on BOTH paths,
// not be silently dropped on one (#728).
func TestLimitsHasAny(t *testing.T) {
	var nilCfg *LimitsConfig
	if nilCfg.HasAny() {
		t.Error("nil LimitsConfig must report no limits")
	}
	if (&LimitsConfig{}).HasAny() {
		t.Error("zero LimitsConfig must report no limits")
	}

	sizeOnly := &LimitsConfig{}
	sizeOnly.Disk.Size = "20GiB"
	if !sizeOnly.HasAny() {
		t.Error("a size-only [limits.disk] config must report limits present")
	}

	// TmpfsSize is applied outside the resource-limit applier, so it must NOT
	// flip HasAny on its own.
	tmpfsOnly := &LimitsConfig{}
	tmpfsOnly.Disk.TmpfsSize = "2GiB"
	if tmpfsOnly.HasAny() {
		t.Error("tmpfs_size alone must not report resource limits present")
	}

	for _, mut := range []func(*LimitsConfig){
		func(c *LimitsConfig) { c.CPU.Count = "2" },
		func(c *LimitsConfig) { c.Memory.Limit = "1GiB" },
		func(c *LimitsConfig) { c.Disk.Read = "10MB" },
		func(c *LimitsConfig) { c.Disk.Priority = 5 },
		func(c *LimitsConfig) { c.Runtime.MaxProcesses = 100 },
	} {
		c := &LimitsConfig{}
		mut(c)
		if !c.HasAny() {
			t.Errorf("expected HasAny() true for %+v", c)
		}
	}
}

func TestLimitsMergeDiskSize(t *testing.T) {
	tests := []struct {
		name       string
		baseSize   string
		otherSize  string
		expectSize string
	}{
		{"other overrides base", "10GiB", "20GiB", "20GiB"},
		{"empty other keeps base", "10GiB", "", "10GiB"},
		{"both empty stays empty", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Limits.Disk.Size = tt.baseSize
			other := &Config{}
			other.Limits.Disk.Size = tt.otherSize
			base.Merge(other)
			if base.Limits.Disk.Size != tt.expectSize {
				t.Errorf("Disk.Size: expected %q, got %q", tt.expectSize, base.Limits.Disk.Size)
			}
		})
	}
}

func TestLimitsMergeTmpfsSize(t *testing.T) {
	tests := []struct {
		name         string
		baseTmpfs    string
		otherTmpfs   string
		expectedSize string
	}{
		{
			name:         "other overrides base",
			baseTmpfs:    "2GiB",
			otherTmpfs:   "8GiB",
			expectedSize: "8GiB",
		},
		{
			name:         "empty other does not override base",
			baseTmpfs:    "4GiB",
			otherTmpfs:   "",
			expectedSize: "4GiB",
		},
		{
			name:         "both empty stays empty",
			baseTmpfs:    "",
			otherTmpfs:   "",
			expectedSize: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Limits.Disk.TmpfsSize = tt.baseTmpfs

			other := &Config{}
			other.Limits.Disk.TmpfsSize = tt.otherTmpfs

			base.Merge(other)

			if base.Limits.Disk.TmpfsSize != tt.expectedSize {
				t.Errorf("TmpfsSize: expected %q, got %q", tt.expectedSize, base.Limits.Disk.TmpfsSize)
			}
		})
	}
}

func TestToolConfigMerge(t *testing.T) {
	base := GetDefaultConfig()
	base.Tool.Name = "claude"
	base.Tool.Binary = ""

	tests := []struct {
		name           string
		otherName      string
		otherBinary    string
		expectedName   string
		expectedBinary string
	}{
		{
			name:           "merge tool name only",
			otherName:      "aider",
			otherBinary:    "",
			expectedName:   "aider",
			expectedBinary: "",
		},
		{
			name:           "merge binary only",
			otherName:      "",
			otherBinary:    "custom-claude",
			expectedName:   "claude",
			expectedBinary: "custom-claude",
		},
		{
			name:           "merge both",
			otherName:      "aider",
			otherBinary:    "custom-aider",
			expectedName:   "aider",
			expectedBinary: "custom-aider",
		},
		{
			name:           "merge neither (empty stays)",
			otherName:      "",
			otherBinary:    "",
			expectedName:   "claude",
			expectedBinary: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset base for each test
			testBase := GetDefaultConfig()
			testBase.Tool.Name = "claude"
			testBase.Tool.Binary = ""

			other := &Config{
				Tool: ToolConfig{
					Name:   tt.otherName,
					Binary: tt.otherBinary,
				},
			}

			testBase.Merge(other)

			if testBase.Tool.Name != tt.expectedName {
				t.Errorf("Expected tool name '%s', got '%s'", tt.expectedName, testBase.Tool.Name)
			}

			if testBase.Tool.Binary != tt.expectedBinary {
				t.Errorf("Expected tool binary '%s', got '%s'", tt.expectedBinary, testBase.Tool.Binary)
			}
		})
	}
}

func TestContextFileMerge(t *testing.T) {
	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		base     string
		other    string
		expected string
	}{
		{
			name:     "empty base + set other = expanded other",
			base:     "",
			other:    "~/my-context.md",
			expected: filepath.Join(homeDir, "my-context.md"),
		},
		{
			name:     "set base + empty other = preserved base",
			base:     "/some/path.md",
			other:    "",
			expected: "/some/path.md",
		},
		{
			name:     "set base + set other = expanded other",
			base:     "/old/path.md",
			other:    "~/new-context.md",
			expected: filepath.Join(homeDir, "new-context.md"),
		},
		{
			name:     "both empty stays empty",
			base:     "",
			other:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Tool.ContextFile = tt.base

			other := &Config{
				Tool: ToolConfig{
					ContextFile: tt.other,
				},
			}

			base.Merge(other)

			if base.Tool.ContextFile != tt.expected {
				t.Errorf("Expected ContextFile %q, got %q", tt.expected, base.Tool.ContextFile)
			}
		})
	}
}

func TestContextJSONMerge(t *testing.T) {
	homeDir, _ := os.UserHomeDir()
	boolPtr := func(b bool) *bool { return &b }

	t.Run("context_json_file is ~-expanded and overrides", func(t *testing.T) {
		base := GetDefaultConfig()
		base.Tool.ContextJSONFile = "/old/path.json"
		base.Merge(&Config{Tool: ToolConfig{ContextJSONFile: "~/custom.json"}})
		if want := filepath.Join(homeDir, "custom.json"); base.Tool.ContextJSONFile != want {
			t.Errorf("ContextJSONFile = %q, want %q", base.Tool.ContextJSONFile, want)
		}
	})

	t.Run("empty context_json_file preserves base", func(t *testing.T) {
		base := GetDefaultConfig()
		base.Tool.ContextJSONFile = "/keep.json"
		base.Merge(&Config{Tool: ToolConfig{ContextJSONFile: ""}})
		if base.Tool.ContextJSONFile != "/keep.json" {
			t.Errorf("ContextJSONFile = %q, want /keep.json", base.Tool.ContextJSONFile)
		}
	})

	t.Run("context_json=false overrides the default true", func(t *testing.T) {
		base := GetDefaultConfig() // embedded default = true
		if base.Tool.ContextJSON == nil || !*base.Tool.ContextJSON {
			t.Fatalf("precondition: default context_json should be true, got %v", base.Tool.ContextJSON)
		}
		base.Merge(&Config{Tool: ToolConfig{ContextJSON: boolPtr(false)}})
		if base.Tool.ContextJSON == nil || *base.Tool.ContextJSON {
			t.Errorf("context_json should be false after merge, got %v", base.Tool.ContextJSON)
		}
	})

	t.Run("nil context_json preserves base", func(t *testing.T) {
		base := GetDefaultConfig()
		base.Merge(&Config{Tool: ToolConfig{ContextJSON: nil}})
		if base.Tool.ContextJSON == nil || !*base.Tool.ContextJSON {
			t.Errorf("nil override should preserve default true, got %v", base.Tool.ContextJSON)
		}
	})
}

func TestClaudeEffortLevelMerge(t *testing.T) {
	tests := []struct {
		name          string
		baseEffort    string
		otherEffort   string
		expectedLevel string
	}{
		{
			name:          "merge effort from empty base",
			baseEffort:    "",
			otherEffort:   "high",
			expectedLevel: "high",
		},
		{
			name:          "merge effort overwrites base",
			baseEffort:    "low",
			otherEffort:   "medium",
			expectedLevel: "medium",
		},
		{
			name:          "empty other preserves base",
			baseEffort:    "high",
			otherEffort:   "",
			expectedLevel: "high",
		},
		{
			name:          "both empty stays empty",
			baseEffort:    "",
			otherEffort:   "",
			expectedLevel: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Tool.Claude.EffortLevel = tt.baseEffort

			other := &Config{
				Tool: ToolConfig{
					Claude: ClaudeToolConfig{
						EffortLevel: tt.otherEffort,
					},
				},
			}

			base.Merge(other)

			if base.Tool.Claude.EffortLevel != tt.expectedLevel {
				t.Errorf("Expected effort level '%s', got '%s'", tt.expectedLevel, base.Tool.Claude.EffortLevel)
			}
		})
	}
}

// TestCodexToolConfigMerge mirrors TestClaudeEffortLevelMerge for the
// [tool.codex] knobs: non-empty overlay values win, empty ones preserve base.
func TestCodexToolConfigMerge(t *testing.T) {
	tests := []struct {
		name                      string
		baseModel, otherModel     string
		baseEffort, otherEffort   string
		expectModel, expectEffort string
	}{
		{
			name:       "merge from empty base",
			otherModel: "gpt-5-codex", otherEffort: "high",
			expectModel: "gpt-5-codex", expectEffort: "high",
		},
		{
			name:      "overlay overwrites base",
			baseModel: "gpt-5", baseEffort: "low",
			otherModel: "gpt-5-codex", otherEffort: "medium",
			expectModel: "gpt-5-codex", expectEffort: "medium",
		},
		{
			name:      "empty overlay preserves base",
			baseModel: "gpt-5-codex", baseEffort: "high",
			expectModel: "gpt-5-codex", expectEffort: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Tool.Codex.Model = tt.baseModel
			base.Tool.Codex.ReasoningEffort = tt.baseEffort

			other := &Config{
				Tool: ToolConfig{
					Codex: CodexToolConfig{
						Model:           tt.otherModel,
						ReasoningEffort: tt.otherEffort,
					},
				},
			}

			base.Merge(other)

			if base.Tool.Codex.Model != tt.expectModel {
				t.Errorf("Model = %q, want %q", base.Tool.Codex.Model, tt.expectModel)
			}
			if base.Tool.Codex.ReasoningEffort != tt.expectEffort {
				t.Errorf("ReasoningEffort = %q, want %q", base.Tool.Codex.ReasoningEffort, tt.expectEffort)
			}
		})
	}
}

func TestMergeBoolZeroValueBug(t *testing.T) {
	// This test demonstrates a bug where merging a zero-value Config (simulating
	// a TOML file that only sets string fields) overwrites security-critical
	// boolean defaults with false. For example, a user config at
	// ~/.coi/config.toml that only sets image = "my-image" should NOT
	// reset block_private_networks from true to false.

	base := GetDefaultConfig()

	// Verify defaults are set correctly before merge
	if base.Network.BlockPrivateNetworks == nil || !*base.Network.BlockPrivateNetworks {
		t.Fatal("Expected default BlockPrivateNetworks to be true")
	}
	if base.Network.BlockMetadataEndpoint == nil || !*base.Network.BlockMetadataEndpoint {
		t.Fatal("Expected default BlockMetadataEndpoint to be true")
	}
	if base.Monitoring.AutoPauseOnHigh == nil || !*base.Monitoring.AutoPauseOnHigh {
		t.Fatal("Expected default AutoPauseOnHigh to be true")
	}
	if base.Monitoring.AutoKillOnCritical == nil || !*base.Monitoring.AutoKillOnCritical {
		t.Fatal("Expected default AutoKillOnCritical to be true")
	}
	if base.Limits.Runtime.AutoStop == nil || !*base.Limits.Runtime.AutoStop {
		t.Fatal("Expected default AutoStop to be true")
	}
	if base.Limits.Runtime.StopGraceful == nil || !*base.Limits.Runtime.StopGraceful {
		t.Fatal("Expected default StopGraceful to be true")
	}
	if base.Network.Logging.Enabled == nil || !*base.Network.Logging.Enabled {
		t.Fatal("Expected default NetworkLogging.Enabled to be true")
	}
	if base.Monitoring.NFT.LogDNSQueries == nil || !*base.Monitoring.NFT.LogDNSQueries {
		t.Fatal("Expected default NFT.LogDNSQueries to be true")
	}

	// Create a zero-value config, simulating a TOML file that only sets
	// image = "my-image" (all booleans remain nil / zero-value).
	other := &Config{
		Container: ContainerConfig{
			Image: "my-image",
		},
	}

	base.Merge(other)

	// After merge, all security-critical bool defaults must survive.
	if base.Network.BlockPrivateNetworks == nil || !*base.Network.BlockPrivateNetworks {
		t.Error("BlockPrivateNetworks was silently reset to false by merge")
	}
	if base.Network.BlockMetadataEndpoint == nil || !*base.Network.BlockMetadataEndpoint {
		t.Error("BlockMetadataEndpoint was silently reset to false by merge")
	}
	if base.Monitoring.AutoPauseOnHigh == nil || !*base.Monitoring.AutoPauseOnHigh {
		t.Error("AutoPauseOnHigh was silently reset to false by merge")
	}
	if base.Monitoring.AutoKillOnCritical == nil || !*base.Monitoring.AutoKillOnCritical {
		t.Error("AutoKillOnCritical was silently reset to false by merge")
	}
	if base.Limits.Runtime.AutoStop == nil || !*base.Limits.Runtime.AutoStop {
		t.Error("AutoStop was silently reset to false by merge")
	}
	if base.Limits.Runtime.StopGraceful == nil || !*base.Limits.Runtime.StopGraceful {
		t.Error("StopGraceful was silently reset to false by merge")
	}
	if base.Network.Logging.Enabled == nil || !*base.Network.Logging.Enabled {
		t.Error("NetworkLogging.Enabled was silently reset to false by merge")
	}
	if base.Monitoring.NFT.LogDNSQueries == nil || !*base.Monitoring.NFT.LogDNSQueries {
		t.Error("NFT.LogDNSQueries was silently reset to false by merge")
	}

	// Verify the image WAS overridden (merge still works for string fields).
	if base.Container.Image != "my-image" {
		t.Errorf("Expected image 'my-image', got '%s'", base.Container.Image)
	}
}

func TestPermissionModeMerge(t *testing.T) {
	tests := []struct {
		name         string
		baseMode     string
		otherMode    string
		expectedMode string
	}{
		{
			name:         "empty base + interactive other = interactive",
			baseMode:     "",
			otherMode:    "interactive",
			expectedMode: "interactive",
		},
		{
			name:         "bypass base + interactive other = interactive",
			baseMode:     "bypass",
			otherMode:    "interactive",
			expectedMode: "interactive",
		},
		{
			name:         "interactive base + empty other = interactive (preserved)",
			baseMode:     "interactive",
			otherMode:    "",
			expectedMode: "interactive",
		},
		{
			name:         "empty base + empty other = empty",
			baseMode:     "",
			otherMode:    "",
			expectedMode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Tool.PermissionMode = tt.baseMode

			other := &Config{
				Tool: ToolConfig{
					PermissionMode: tt.otherMode,
				},
			}

			base.Merge(other)

			if base.Tool.PermissionMode != tt.expectedMode {
				t.Errorf("Expected permission mode '%s', got '%s'", tt.expectedMode, base.Tool.PermissionMode)
			}
		})
	}
}

func TestForwardEnvDefaults(t *testing.T) {
	cfg := GetDefaultConfig()

	if len(cfg.Defaults.ForwardEnv) != 0 {
		t.Errorf("Expected default ForwardEnv to be empty, got %v", cfg.Defaults.ForwardEnv)
	}
	if len(cfg.Defaults.Environment) != 0 {
		t.Errorf("Expected default Environment to be empty/nil, got %v", cfg.Defaults.Environment)
	}
}

func TestForwardEnvMerge(t *testing.T) {
	tests := []struct {
		name     string
		base     []string
		other    []string
		expected []string
	}{
		{
			name:     "empty base, non-empty other",
			base:     nil,
			other:    []string{"A", "B"},
			expected: []string{"A", "B"},
		},
		{
			name:     "non-empty base, empty other (preserved)",
			base:     []string{"A"},
			other:    nil,
			expected: []string{"A"},
		},
		{
			name:     "overlapping lists are deduplicated",
			base:     []string{"A", "B"},
			other:    []string{"B", "C"},
			expected: []string{"A", "B", "C"},
		},
		{
			name:     "both empty stays empty",
			base:     nil,
			other:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Defaults.ForwardEnv = tt.base

			other := &Config{
				Defaults: DefaultsConfig{
					ForwardEnv: tt.other,
				},
			}

			base.Merge(other)

			if len(base.Defaults.ForwardEnv) != len(tt.expected) {
				t.Fatalf("ForwardEnv length: expected %d, got %d (%v)", len(tt.expected), len(base.Defaults.ForwardEnv), base.Defaults.ForwardEnv)
			}
			for i, v := range tt.expected {
				if base.Defaults.ForwardEnv[i] != v {
					t.Errorf("ForwardEnv[%d]: expected %q, got %q", i, v, base.Defaults.ForwardEnv[i])
				}
			}
		})
	}
}

func TestEnvironmentMerge(t *testing.T) {
	base := GetDefaultConfig()
	base.Defaults.Environment = map[string]string{"A": "1", "B": "2"}

	other := &Config{
		Defaults: DefaultsConfig{
			Environment: map[string]string{"B": "override", "C": "3"},
		},
	}

	base.Merge(other)

	expected := map[string]string{"A": "1", "B": "override", "C": "3"}
	for k, v := range expected {
		if base.Defaults.Environment[k] != v {
			t.Errorf("Environment[%q]: expected %q, got %q", k, v, base.Defaults.Environment[k])
		}
	}
}

func TestApplyProfileEnvironment(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Profiles["test"] = ProfileConfig{
		Environment: map[string]string{"RUST_BACKTRACE": "1", "FOO": "bar"},
	}

	if err := cfg.ApplyProfile("test"); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	if cfg.Defaults.Environment == nil {
		t.Fatal("Expected Environment to be set after ApplyProfile")
	}
	if cfg.Defaults.Environment["RUST_BACKTRACE"] != "1" {
		t.Errorf("Expected RUST_BACKTRACE=1, got %q", cfg.Defaults.Environment["RUST_BACKTRACE"])
	}
	if cfg.Defaults.Environment["FOO"] != "bar" {
		t.Errorf("Expected FOO=bar, got %q", cfg.Defaults.Environment["FOO"])
	}
}

func TestBuildConfigMerge(t *testing.T) {
	tests := []struct {
		name             string
		baseBase         string
		baseScript       string
		baseCommands     []string
		otherBase        string
		otherScript      string
		otherCommands    []string
		expectedBase     string
		expectedScript   string
		expectedCommands []string
	}{
		{
			name:             "empty base, set other",
			otherBase:        "coi-custom",
			otherScript:      "/path/to/build.sh",
			otherCommands:    []string{"echo hello"},
			expectedBase:     "coi-custom",
			expectedScript:   "/path/to/build.sh",
			expectedCommands: []string{"echo hello"},
		},
		{
			name:             "set base, empty other preserves base",
			baseBase:         "coi-rust",
			baseScript:       "/old/build.sh",
			baseCommands:     []string{"cargo build"},
			expectedBase:     "coi-rust",
			expectedScript:   "/old/build.sh",
			expectedCommands: []string{"cargo build"},
		},
		{
			name:             "other overrides base",
			baseBase:         "coi-old",
			baseScript:       "/old/build.sh",
			baseCommands:     []string{"old command"},
			otherBase:        "coi-new",
			otherScript:      "/new/build.sh",
			otherCommands:    []string{"new command"},
			expectedBase:     "coi-new",
			expectedScript:   "/new/build.sh",
			expectedCommands: []string{"new command"},
		},
		{
			name:             "commands replace entirely (not append)",
			baseCommands:     []string{"cmd1", "cmd2"},
			otherCommands:    []string{"cmd3"},
			expectedCommands: []string{"cmd3"},
		},
		{
			name:         "empty commands does not clear base commands",
			baseCommands: []string{"cmd1"},
			// otherCommands is nil
			expectedCommands: []string{"cmd1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Container.Build.Base = tt.baseBase
			base.Container.Build.Script = tt.baseScript
			base.Container.Build.Commands = tt.baseCommands

			other := &Config{
				Container: ContainerConfig{
					Build: BuildConfig{
						Base:     tt.otherBase,
						Script:   tt.otherScript,
						Commands: tt.otherCommands,
					},
				},
			}

			base.Merge(other)

			if base.Container.Build.Base != tt.expectedBase {
				t.Errorf("Build.Base: expected %q, got %q", tt.expectedBase, base.Container.Build.Base)
			}
			if base.Container.Build.Script != tt.expectedScript {
				t.Errorf("Build.Script: expected %q, got %q", tt.expectedScript, base.Container.Build.Script)
			}
			if len(base.Container.Build.Commands) != len(tt.expectedCommands) {
				t.Fatalf("Build.Commands length: expected %d, got %d (%v)", len(tt.expectedCommands), len(base.Container.Build.Commands), base.Container.Build.Commands)
			}
			for i, v := range tt.expectedCommands {
				if base.Container.Build.Commands[i] != v {
					t.Errorf("Build.Commands[%d]: expected %q, got %q", i, v, base.Container.Build.Commands[i])
				}
			}
		})
	}
}

func TestBuildConfigHasBuildConfig(t *testing.T) {
	tests := []struct {
		name     string
		build    BuildConfig
		expected bool
	}{
		{
			name:     "empty config",
			build:    BuildConfig{},
			expected: false,
		},
		{
			name:     "script only",
			build:    BuildConfig{Script: "/path/to/build.sh"},
			expected: true,
		},
		{
			name:     "commands only",
			build:    BuildConfig{Commands: []string{"echo hello"}},
			expected: true,
		},
		{
			name:     "both script and commands",
			build:    BuildConfig{Script: "/path/to/build.sh", Commands: []string{"echo hello"}},
			expected: true,
		},
		{
			name:     "base only is not enough",
			build:    BuildConfig{Base: "coi"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.build.HasBuildConfig(); got != tt.expected {
				t.Errorf("HasBuildConfig() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBuildConfigEdgeCases(t *testing.T) {
	t.Run("empty commands slice is not build config", func(t *testing.T) {
		b := BuildConfig{Commands: []string{}}
		if b.HasBuildConfig() {
			t.Error("Empty commands slice should not count as build config")
		}
	})

	t.Run("nil commands is not build config", func(t *testing.T) {
		b := BuildConfig{Commands: nil}
		if b.HasBuildConfig() {
			t.Error("Nil commands should not count as build config")
		}
	})

	t.Run("whitespace-only script is build config", func(t *testing.T) {
		// A non-empty string counts — validation happens at build time
		b := BuildConfig{Script: " "}
		if !b.HasBuildConfig() {
			t.Error("Non-empty script string should count as build config")
		}
	})

	t.Run("merge does not mix script and commands across configs", func(t *testing.T) {
		base := GetDefaultConfig()
		base.Container.Build.Script = "/path/to/build.sh"

		other := &Config{
			Container: ContainerConfig{
				Build: BuildConfig{
					Commands: []string{"echo hello"},
				},
			},
		}

		base.Merge(other)

		// Both should be set after merge (script from base, commands from other)
		if base.Container.Build.Script != "/path/to/build.sh" {
			t.Errorf("Script should be preserved from base, got %q", base.Container.Build.Script)
		}
		if len(base.Container.Build.Commands) != 1 || base.Container.Build.Commands[0] != "echo hello" {
			t.Errorf("Commands should be set from other, got %v", base.Container.Build.Commands)
		}
	})
}

func TestPreserveWorkspacePathMerge(t *testing.T) {
	tests := []struct {
		name     string
		base     bool
		other    bool
		expected bool
	}{
		{
			name:     "false base, true other = true",
			base:     false,
			other:    true,
			expected: true,
		},
		{
			name:     "true base, false other = true (sticky)",
			base:     true,
			other:    false,
			expected: true,
		},
		{
			name:     "false base, false other = false",
			base:     false,
			other:    false,
			expected: false,
		},
		{
			name:     "true base, true other = true",
			base:     true,
			other:    true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := GetDefaultConfig()
			base.Paths.PreserveWorkspacePath = tt.base

			other := &Config{
				Paths: PathsConfig{
					PreserveWorkspacePath: tt.other,
				},
			}

			base.Merge(other)

			if base.Paths.PreserveWorkspacePath != tt.expected {
				t.Errorf("Expected PreserveWorkspacePath=%v, got %v", tt.expected, base.Paths.PreserveWorkspacePath)
			}
		})
	}
}

func TestApplyProfile_AliasPreservation(t *testing.T) {
	t.Run("profile alias does not override project alias", func(t *testing.T) {
		cfg := GetDefaultConfig()
		cfg.Container.Alias = "project-alias"
		cfg.Profiles["test"] = ProfileConfig{
			Container: ContainerConfig{Alias: "profile-alias"},
		}
		if err := cfg.ApplyProfile("test"); err != nil {
			t.Fatal(err)
		}
		if cfg.Container.Alias != "project-alias" {
			t.Errorf("Alias = %q, want %q (project alias should win)", cfg.Container.Alias, "project-alias")
		}
	})

	t.Run("profile alias applied when project has no alias", func(t *testing.T) {
		cfg := GetDefaultConfig()
		cfg.Profiles["test"] = ProfileConfig{
			Container: ContainerConfig{Alias: "profile-alias"},
		}
		if err := cfg.ApplyProfile("test"); err != nil {
			t.Fatal(err)
		}
		if cfg.Container.Alias != "profile-alias" {
			t.Errorf("Alias = %q, want %q (profile alias should apply when project has none)", cfg.Container.Alias, "profile-alias")
		}
	})

	t.Run("no alias in either", func(t *testing.T) {
		cfg := GetDefaultConfig()
		cfg.Profiles["test"] = ProfileConfig{}
		if err := cfg.ApplyProfile("test"); err != nil {
			t.Fatal(err)
		}
		if cfg.Container.Alias != "" {
			t.Errorf("Alias = %q, want empty", cfg.Container.Alias)
		}
	})

	t.Run("Merge still allows alias override", func(t *testing.T) {
		cfg := GetDefaultConfig()
		cfg.Container.Alias = "base-alias"
		other := &Config{Container: ContainerConfig{Alias: "override-alias"}}
		cfg.Merge(other)
		if cfg.Container.Alias != "override-alias" {
			t.Errorf("Alias = %q, want %q (Merge should allow override)", cfg.Container.Alias, "override-alias")
		}
	})
}

// The Claude Code project settings files (where the "hooks" key lives) must be
// default protected paths so a contained agent cannot plant/modify hooks that a
// later session would auto-execute on open.
func TestDefaultConfig_ProtectsClaudeSettings(t *testing.T) {
	cfg := GetDefaultConfig()
	want := map[string]bool{
		".claude/settings.json":       false,
		".claude/settings.local.json": false,
	}
	for _, p := range cfg.Security.GetEffectiveProtectedPaths() {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, found := range want {
		if !found {
			t.Errorf("%s should be a default protected path", p)
		}
	}
}

// writable_paths removes specific entries from the effective protected set, the
// generic trusted-scope opt-out.
func TestGetEffectiveProtectedPaths_WritablePathsSubtracts(t *testing.T) {
	s := &SecurityConfig{
		ProtectedPaths: []string{".git/hooks", ".claude/settings.json", ".claude/settings.local.json"},
		WritablePaths:  []string{".claude/settings.json", ".claude/settings.local.json"},
	}
	got := s.GetEffectiveProtectedPaths()
	for _, p := range got {
		if p == ".claude/settings.json" || p == ".claude/settings.local.json" {
			t.Errorf("%s should have been removed by writable_paths", p)
		}
	}
	if len(got) != 1 || got[0] != ".git/hooks" {
		t.Errorf("expected only .git/hooks to remain, got %v", got)
	}
}

// A trusted-scope security override must carry writable_paths through Merge
// (the opt-out is only honored from trusted config).
func TestConfigMerge_CarriesWritablePaths(t *testing.T) {
	cfg := GetDefaultConfig()
	cfg.Merge(&Config{Security: SecurityConfig{WritablePaths: []string{".claude/settings.json"}}})
	for _, p := range cfg.Security.GetEffectiveProtectedPaths() {
		if p == ".claude/settings.json" {
			t.Error("Merge should carry writable_paths so .claude/settings.json becomes writable")
		}
	}
}

// The #842 reverse_shell_one_liners knob defaults to "critical" (from the
// embedded default config) and an explicit override survives Merge.
func TestConfigMerge_ReverseShellOneLiners(t *testing.T) {
	base := GetDefaultConfig()
	if got := StringVal(base.Monitoring.ReverseShellOneLiners); got != "critical" {
		t.Fatalf("default reverse_shell_one_liners = %q, want \"critical\"", got)
	}

	warn := "warn"
	base.Merge(&Config{Monitoring: MonitoringConfig{ReverseShellOneLiners: &warn}})
	if got := StringVal(base.Monitoring.ReverseShellOneLiners); got != "warn" {
		t.Errorf("after merge reverse_shell_one_liners = %q, want \"warn\"", got)
	}

	// A nil override (field unset) must NOT clobber the existing value.
	base.Merge(&Config{Monitoring: MonitoringConfig{ReverseShellOneLiners: nil}})
	if got := StringVal(base.Monitoring.ReverseShellOneLiners); got != "warn" {
		t.Errorf("nil override reset reverse_shell_one_liners to %q, want \"warn\"", got)
	}
}
