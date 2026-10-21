package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/spf13/cobra"
)

func newDeleteCmd(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "delete"}
	c.Flags().BoolP("force", "f", false, "")
	if err := c.Flags().Set("force", "true"); err != nil {
		t.Fatal(err)
	}
	return c
}

// diskProfile writes <root>/profiles/<name>/config.toml and returns the profile
// as the loader records it (Source = the config file path).
func diskProfile(t *testing.T, root, name string) config.ProfileConfig {
	t.Helper()
	dir := filepath.Join(root, "profiles", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return config.ProfileConfig{Source: path}
}

func TestProfileDelete_RefusesBuiltinNames(t *testing.T) {
	for _, name := range []string{"default", "hardened"} {
		t.Run(name+"/built-in", func(t *testing.T) {
			a := &App{cfg: &config.Config{Profiles: map[string]config.ProfileConfig{
				name: {Source: "(built-in)"},
			}}}
			err := a.profileDeleteRunE(newDeleteCmd(t), []string{name})
			want := "cannot delete built-in profile '" + name + "'"
			if err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
		})

		t.Run(name+"/disk", func(t *testing.T) {
			p := diskProfile(t, filepath.Join(t.TempDir(), ".coi"), name)
			a := &App{cfg: &config.Config{Profiles: map[string]config.ProfileConfig{name: p}}}
			err := a.profileDeleteRunE(newDeleteCmd(t), []string{name})
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			dir := filepath.Dir(p.Source)
			for _, want := range []string{"'" + name + "'", dir, "by hand"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want it to contain %q", err, want)
				}
			}
			if _, statErr := os.Stat(p.Source); statErr != nil {
				t.Errorf("profile file must survive the refused delete: %v", statErr)
			}
		})
	}
}

func TestProfileDelete_RemovesOtherDiskProfile(t *testing.T) {
	p := diskProfile(t, filepath.Join(t.TempDir(), ".coi"), "rust-dev")
	a := &App{cfg: &config.Config{Profiles: map[string]config.ProfileConfig{"rust-dev": p}}}
	if err := a.profileDeleteRunE(newDeleteCmd(t), []string{"rust-dev"}); err != nil {
		t.Fatalf("profileDeleteRunE: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(p.Source)); !os.IsNotExist(err) {
		t.Errorf("profile directory should be gone, stat err = %v", err)
	}
}
