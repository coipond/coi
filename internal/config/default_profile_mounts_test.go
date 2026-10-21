package config

import (
	"os"
	"path/filepath"
	"testing"
)

// loadWithUserConfig runs Load with a temp HOME holding content as
// ~/.coi/config.toml (plus any profiles), from an empty working directory.
func loadWithUserConfig(t *testing.T, content string, profiles map[string]string) *Config {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	t.Chdir(t.TempDir())

	coiDir := filepath.Join(home, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range profiles {
		dir := filepath.Join(coiDir, "profiles", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

const dataMount = "[[mounts.default]]\nhost = \"/srv/data\"\ncontainer = \"/data\"\n"

func assertOneDataMount(t *testing.T, cfg *Config) {
	t.Helper()
	n := 0
	for _, m := range cfg.Mounts.Default {
		if m.Container == "/data" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want the /data mount once, got %d: %+v", n, cfg.Mounts.Default)
	}
}

func TestApplyDefaultProfile_ConfigMountsOnce(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		profiles map[string]string
		apply    string
	}{
		{name: "explicit", config: dataMount, apply: "default"},
		{name: "defaults profile", config: "[defaults]\nprofile = \"default\"\n\n" + dataMount, apply: ""},
		{name: "inherits", config: dataMount, profiles: map[string]string{"child": "inherits = \"default\"\n"}, apply: "child"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadWithUserConfig(t, tt.config, tt.profiles)
			name := tt.apply
			if name == "" {
				name = cfg.Defaults.Profile
			}
			if err := cfg.ApplyProfile(name); err != nil {
				t.Fatalf("ApplyProfile(%q): %v", name, err)
			}
			assertOneDataMount(t, cfg)
		})
	}
}

// A profile that only shares the mount, and a disk profile named "default",
// still append their mounts as before.
func TestApplyProfile_OtherProfilesStillAppendMounts(t *testing.T) {
	body := "[[mounts]]\nhost = \"/srv/data\"\ncontainer = \"/data\"\n"
	for _, name := range []string{"other", "default"} {
		t.Run(name, func(t *testing.T) {
			cfg := loadWithUserConfig(t, dataMount, map[string]string{name: body})
			if err := cfg.ApplyProfile(name); err != nil {
				t.Fatalf("ApplyProfile(%q): %v", name, err)
			}
			if got := len(cfg.Mounts.Default); got != 2 {
				t.Errorf("want 2 mounts, got %d: %+v", got, cfg.Mounts.Default)
			}
		})
	}
}

// A profile inheriting "default" with mounts of its own adds them.
func TestApplyProfile_InheritsDefaultWithOwnMounts(t *testing.T) {
	child := "inherits = \"default\"\n\n[[mounts]]\nhost = \"/srv/cache\"\ncontainer = \"/cache\"\n"
	cfg := loadWithUserConfig(t, dataMount, map[string]string{"child": child})
	if err := cfg.ApplyProfile("child"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	assertOneDataMount(t, cfg)
	if got := len(cfg.Mounts.Default); got != 2 {
		t.Errorf("want /data and /cache, got %d: %+v", got, cfg.Mounts.Default)
	}
}
