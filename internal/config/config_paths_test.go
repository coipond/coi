package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeCoiMountConfig writes trustTestMountConfig to dir/.coi/config.toml.
func writeCoiMountConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, ".coi", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(trustTestMountConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadUserConfigOnceWhenCwdIsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COI_CONFIG", "")
	writeCoiMountConfig(t, home)
	t.Chdir(home)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if len(cfg.Mounts.Default) != 1 {
		t.Errorf("mounts = %+v, want the one mount of ~/.coi/config.toml", cfg.Mounts.Default)
	}
}

func TestLoadUserConfigOnceWhenCOIConfigNamesIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := writeCoiMountConfig(t, home)
	t.Setenv("COI_CONFIG", path)
	t.Chdir(t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	if len(cfg.Mounts.Default) != 1 {
		t.Errorf("mounts = %+v, want the one mount of ~/.coi/config.toml", cfg.Mounts.Default)
	}
}

func TestLoadRelativeCOIConfigNamingProjectConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	writeCoiMountConfig(t, ws)
	profileDir := filepath.Join(ws, ".coi", "profiles", "p")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte("[container]\nimage = \"p-image\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(ws)
	t.Setenv("COI_CONFIG", filepath.Join(".coi", "config.toml"))

	for name, load := range map[string]func() (*Config, error){
		"Load":                Load,
		"LoadOnDemand":        LoadOnDemand,
		"LoadWithoutProfiles": LoadWithoutProfiles,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load()
			if err != nil {
				t.Fatalf("%s() failed: %v", name, err)
			}
			if len(cfg.Mounts.Default) != 1 {
				t.Errorf("mounts = %+v, want the one mount of .coi/config.toml", cfg.Mounts.Default)
			}
		})
	}
}

func TestGetConfigPathsCOIConfigAbsoluteAndUnique(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ws := t.TempDir()
	t.Chdir(ws)
	userConfig := filepath.Join(home, ".coi", "config.toml")
	projectConfig := filepath.Join(ws, ".coi", "config.toml")

	tests := []struct {
		name      string
		coiConfig string
		want      []string
	}{
		{"relative", "other.toml", []string{userConfig, projectConfig, filepath.Join(ws, "other.toml")}},
		{"user config", filepath.Join(home, ".coi", "..", ".coi", "config.toml"), []string{projectConfig, userConfig}},
		{"relative project config", "./.coi/config.toml", []string{userConfig, projectConfig}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COI_CONFIG", tt.coiConfig)
			got := GetConfigPaths()
			if len(got) != len(tt.want) {
				t.Fatalf("GetConfigPaths() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetConfigPaths() = %v, want %v", got, tt.want)
					break
				}
			}
			if !isTrustedConfigPath(got[len(got)-1]) {
				t.Errorf("COI_CONFIG path %s is not trusted", got[len(got)-1])
			}
		})
	}
}

func TestLoadRelativeCOIConfigTrustsItsProfiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	profileDir := filepath.Join(ws, ".coi", "profiles", "p")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "config.toml"), []byte("forward_env = [\"TOKEN\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(ws)
	t.Setenv("COI_CONFIG", filepath.Join(".coi", "config.toml"))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	p := cfg.GetProfile("p")
	if p == nil || len(p.ForwardEnv) != 1 {
		t.Errorf("profile p = %+v, want forward_env kept (COI_CONFIG dir is trusted)", p)
	}
}

func TestGetProfileParentDirsCOIConfigAbsoluteAndUnique(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ws := t.TempDir()
	userDir := filepath.Join(home, ".coi")
	projectDir := filepath.Join(ws, ".coi")

	tests := []struct {
		name      string
		cwd       string
		coiConfig string
		want      []string
	}{
		{"cwd is home", home, "", []string{userDir}},
		{"user config", ws, filepath.Join(home, ".coi", "config.toml"), []string{projectDir, userDir}},
		{"relative project config", ws, "./.coi/config.toml", []string{userDir, projectDir}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Chdir(tt.cwd)
			t.Setenv("COI_CONFIG", tt.coiConfig)
			got := GetProfileParentDirs()
			if !slices.Equal(got, tt.want) {
				t.Errorf("GetProfileParentDirs() = %v, want %v", got, tt.want)
			}
		})
	}
}
