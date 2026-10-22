package config

import (
	"os"
	"path/filepath"
	"testing"
)

const maxProcesses500 = "[limits.runtime]\nmax_processes = 500\n"

// loadLayers runs Load with a temp HOME holding user as ~/.coi/config.toml
// (plus any profiles) and a temp working directory holding project as
// ./.coi/config.toml ("" writes none).
func loadLayers(t *testing.T, user, project string, profiles map[string]string) *Config {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	work := t.TempDir()
	t.Chdir(work)

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".coi", "config.toml"), user)
	if project != "" {
		write(filepath.Join(work, ".coi", "config.toml"), project)
	}
	for name, body := range profiles {
		write(filepath.Join(home, ".coi", "profiles", name, "config.toml"), body)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func wantMaxProcesses(t *testing.T, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("max_processes unset, want %d", want)
	} else if *got != want {
		t.Errorf("max_processes = %d, want %d", *got, want)
	}
}

func TestMaxProcesses_ExplicitZeroOverridesConfigFile(t *testing.T) {
	cfg := loadLayers(t, maxProcesses500, "[limits.runtime]\nmax_processes = 0\n", nil)
	wantMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

func TestMaxProcesses_ExplicitZeroOverridesInAppliedProfile(t *testing.T) {
	cfg := loadLayers(t, maxProcesses500, "", map[string]string{"nolimit": "[limits.runtime]\nmax_processes = 0\n"})
	if err := cfg.ApplyProfile("nolimit"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	wantMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

func TestMaxProcesses_ExplicitZeroOverridesParentProfile(t *testing.T) {
	cfg := loadLayers(t, "", "", map[string]string{
		"parent": maxProcesses500,
		"child":  "inherits = \"parent\"\n\n[limits.runtime]\nmax_processes = 0\n",
	})
	wantMaxProcesses(t, cfg.GetProfile("child").Limits.Runtime.MaxProcesses, 0)
	if err := cfg.ApplyProfile("child"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	wantMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 0)
}

// A later layer that does not set max_processes keeps the earlier limit.
func TestMaxProcesses_UnsetKeepsEarlierLimit(t *testing.T) {
	other := "[limits.runtime]\nmax_duration = \"1h\"\n"
	cfg := loadLayers(t, maxProcesses500, other, map[string]string{
		"other":    other,
		"child":    "inherits = \"other500\"\n\n" + other,
		"other500": maxProcesses500,
	})
	wantMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 500)
	wantMaxProcesses(t, cfg.GetProfile("child").Limits.Runtime.MaxProcesses, 500)
	if err := cfg.ApplyProfile("other"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	wantMaxProcesses(t, cfg.Limits.Runtime.MaxProcesses, 500)
}
