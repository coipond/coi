package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/session"
)

// A bad .coi/config.toml in the --workspace or alias workspace exits like any
// other config error, through the shell pipeline's error wrapping.
func TestResolveWorkspacePhase_BadProjectConfigExitsConfig(t *testing.T) {
	writeBad := func(t *testing.T, ws string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(ws, ".coi"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ws, ".coi", "config.toml"), []byte("this is = not valid toml ][\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("workspace", func(t *testing.T) {
		a, cmd, _ := newResumeTestApp(t, "")
		a.workspace = t.TempDir()
		writeBad(t, a.workspace)
		err := (&session.Pipeline{}).Run(t.Context(), a.resolveWorkspacePhase(cmd, &shellState{}))
		if got := ExitCodeFor(err); got != ExitConfig {
			t.Errorf("exit code = %d, want %d (ExitConfig); err: %v", got, ExitConfig, err)
		}
	})

	t.Run("alias", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		ws := t.TempDir()
		writeBad(t, ws)
		reg, err := alias.Load()
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Register("proj", ws, ""); err != nil {
			t.Fatal(err)
		}
		if err := reg.Save(); err != nil {
			t.Fatal(err)
		}

		a, cmd, _ := newResumeTestApp(t, "")
		a.workspace = ws
		err = (&session.Pipeline{}).Run(t.Context(), a.resolveWorkspacePhase(cmd, &shellState{aliasArg: "proj"}))
		if got := ExitCodeFor(err); got != ExitConfig {
			t.Errorf("exit code = %d, want %d (ExitConfig); err: %v", got, ExitConfig, err)
		}
	})
}
