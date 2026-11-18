package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
)

// mountRecorder records the disk mounts coi run makes, single and batched.
type mountRecorder struct {
	container.ContainerManager
	paths []string
}

func (m *mountRecorder) MountDisk(_, _, path string, _, _ bool) error {
	m.paths = append(m.paths, path)
	return nil
}

func (m *mountRecorder) MountDisks(mounts []container.DiskMount) error {
	for _, d := range mounts {
		m.paths = append(m.paths, d.Path)
	}
	return nil
}

// [git] writable_hooks reaches the nested git expansion: a submodule's hooks
// dir is mounted read-only only when hooks are not writable.
func TestApplySecurityMounts_WritableHooksLeavesNestedHooks(t *testing.T) {
	ws := t.TempDir()
	lib := filepath.Join(ws, ".git", "modules", "lib")
	for _, d := range []string{filepath.Join(ws, ".git", "hooks"), filepath.Join(lib, "hooks"), filepath.Join(lib, "info")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(lib, "HEAD"), filepath.Join(lib, "config")} {
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	nestedHooks := filepath.Join("/workspace", ".git", "modules", "lib", "hooks")
	nestedConfig := filepath.Join("/workspace", ".git", "modules", "lib", "config")

	for _, writable := range []bool{true, false} {
		cfg := config.GetDefaultConfig()
		cfg.Git.WritableHooks = &writable
		off := false
		cfg.Security.HostImmutable = &off
		mgr := &mountRecorder{}
		if err := (&App{cfg: cfg}).applySecurityMounts(mgr, ws, "/workspace", "c1", false, nil, session.NestedGitScan{}); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(mgr.paths, "\n")
		if strings.Contains(got, nestedHooks) == writable {
			t.Errorf("writable_hooks=%v: nested hooks mounted=%v, mounts:\n%s", writable, !writable, got)
		}
		if !strings.Contains(got, nestedConfig) {
			t.Errorf("writable_hooks=%v: nested config must stay protected, mounts:\n%s", writable, got)
		}
	}
}

// coi run warns about a protected commondir that names another dir, and not
// about the placeholder it creates for an absent one.
func TestApplySecurityMounts_UnexpectedCommonDir(t *testing.T) {
	for _, planted := range []bool{false, true} {
		ws := t.TempDir()
		if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(ws, "planted")
		if planted {
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ws, ".git", "commondir"), []byte(target+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cfg := config.GetDefaultConfig()
		off := false
		cfg.Security.HostImmutable = &off
		var runErr error
		stderr := captureOutput(t, &os.Stderr, func() {
			runErr = (&App{cfg: cfg}).applySecurityMounts(&mountRecorder{}, ws, "/workspace", "c1", false, nil, session.NestedGitScan{})
		})
		if runErr != nil {
			t.Fatal(runErr)
		}
		want := "unexpected git commondir, kept as it is; check it: .git/commondir -> " + target
		if strings.Contains(stderr, want) != planted {
			t.Errorf("planted=%v: stderr has warning=%v, want %v:\n%s", planted, !planted, planted, stderr)
		}
	}
}
