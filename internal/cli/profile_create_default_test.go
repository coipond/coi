package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/coipond/coi/internal/config"
	"github.com/spf13/cobra"
)

// newCreateDefaultCmd builds a cobra command with the same flags scaffoldMainConfig
// inspects, so it can be driven directly without the root command.
func newCreateDefaultCmd() *cobra.Command {
	c := &cobra.Command{Use: "create"}
	c.Flags().Bool("user", false, "")
	c.Flags().Bool("project", false, "")
	c.Flags().String("inherits", "", "")
	return c
}

func TestScaffoldMainConfig_WritesUserConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	a := &App{workspace: t.TempDir()}

	if err := a.scaffoldMainConfig(newCreateDefaultCmd()); err != nil {
		t.Fatalf("scaffoldMainConfig: %v", err)
	}

	path := filepath.Join(home, ".coi", "config.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected config at %s: %v", path, err)
	}
	if !bytes.Equal(data, config.EmbeddedStarterConfig) {
		t.Error("written config does not match the starter template")
	}
	// The generated file must decode cleanly into Config.
	var cfg config.Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
}

func TestScaffoldMainConfig_WritesProjectConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	a := &App{workspace: ws}

	cmd := newCreateDefaultCmd()
	if err := cmd.Flags().Set("project", "true"); err != nil {
		t.Fatal(err)
	}
	if err := a.scaffoldMainConfig(cmd); err != nil {
		t.Fatalf("scaffoldMainConfig --project: %v", err)
	}

	if _, err := os.Stat(filepath.Join(ws, ".coi", "config.toml")); err != nil {
		t.Fatalf("expected project config in workspace: %v", err)
	}
}

func TestScaffoldMainConfig_RefusesWhenExists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	a := &App{workspace: t.TempDir()}

	path := filepath.Join(home, ".coi", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("# my existing config\n")
	if err := os.WriteFile(path, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}

	err := a.scaffoldMainConfig(newCreateDefaultCmd())
	if err == nil {
		t.Fatal("expected an error when the config already exists")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, sentinel) {
		t.Error("existing config was modified; it must be left untouched")
	}
}

func TestScaffoldMainConfig_RejectsProfileFlags(t *testing.T) {
	// --image/--persistent no longer exist as flags anywhere; --inherits is
	// the only profile-shaping flag left and must be rejected for "default".
	t.Setenv("HOME", t.TempDir())
	a := &App{workspace: t.TempDir()}
	cmd := newCreateDefaultCmd()
	if err := cmd.Flags().Set("inherits", "x"); err != nil {
		t.Fatal(err)
	}
	if err := a.scaffoldMainConfig(cmd); err == nil {
		t.Fatal("expected --inherits to be rejected for 'create default'")
	}
}

func TestScaffoldMainConfig_UserProjectMutuallyExclusive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a := &App{workspace: t.TempDir()}
	cmd := newCreateDefaultCmd()
	_ = cmd.Flags().Set("user", "true")
	_ = cmd.Flags().Set("project", "true")
	if err := a.scaffoldMainConfig(cmd); err == nil {
		t.Fatal("expected --user and --project together to error")
	}
}
