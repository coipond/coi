package config

import (
	"os"
	"path/filepath"
	"testing"
)

// loadWithConfigs runs Load with a temp HOME holding user as
// ~/.coi/config.toml (plus any profiles), from a temp working directory
// holding project as ./.coi/config.toml ("" writes none).
func loadWithConfigs(t *testing.T, user, project string, profiles map[string]string) *Config {
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
			cfg := loadWithConfigs(t, tt.config, "", tt.profiles)
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
			cfg := loadWithConfigs(t, dataMount, "", map[string]string{name: body})
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
	cfg := loadWithConfigs(t, dataMount, "", map[string]string{"child": child})
	if err := cfg.ApplyProfile("child"); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}
	assertOneDataMount(t, cfg)
	if got := len(cfg.Mounts.Default); got != 2 {
		t.Errorf("want /data and /cache, got %d: %+v", got, cfg.Mounts.Default)
	}
}
