package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRemounter records the device operations RemountMovedWorkspace performs.
// Only the methods the helper exercises do anything; the rest satisfy
// container.ContainerDevices.
type fakeRemounter struct {
	source     string
	removeErr  error
	mountErr   error
	ops        []string
	mountedCWP string
}

func (f *fakeRemounter) GetWorkspaceSource() string { return f.source }
func (f *fakeRemounter) RemoveDevice(name string) error {
	f.ops = append(f.ops, "remove:"+name)
	if name == "workspace" {
		return f.removeErr
	}
	return nil
}

func (f *fakeRemounter) MountDisk(name, source, path string, shift, readonly bool) error {
	f.ops = append(f.ops, "mount:"+name+":"+source)
	if name == "workspace" {
		f.mountedCWP = path
	}
	return f.mountErr
}

func (f *fakeRemounter) AddProxyDevice(name, connect, listen string, uid, gid int) error { return nil }

func (f *fakeRemounter) AddHostPortDevice(name, listenAddr string, hostPort, containerPort int) error {
	return nil
}
func (f *fakeRemounter) ListDevices() ([]string, error) { return nil, nil }
func (f *fakeRemounter) SetTmpfsSize(size string) error { return nil }

func TestRemountMovedWorkspace(t *testing.T) {
	ws := t.TempDir()

	t.Run("same source is a no-op", func(t *testing.T) {
		f := &fakeRemounter{source: ws}
		cwp, moved, err := RemountMovedWorkspace(f, ws, false, nil, true, nil)
		if err != nil || moved || cwp != "" {
			t.Fatalf("expected no-op, got cwp=%q moved=%v err=%v", cwp, moved, err)
		}
		if len(f.ops) != 0 {
			t.Errorf("no device ops expected, got %v", f.ops)
		}
	})

	t.Run("unknown source is a no-op (fail open)", func(t *testing.T) {
		f := &fakeRemounter{source: ""}
		if _, moved, err := RemountMovedWorkspace(f, ws, false, nil, true, nil); err != nil || moved {
			t.Fatalf("expected fail-open no-op, got moved=%v err=%v", moved, err)
		}
	})

	t.Run("moved source replaces workspace and stale worktree device", func(t *testing.T) {
		f := &fakeRemounter{source: "/old/place"}
		cwp, moved, err := RemountMovedWorkspace(f, ws, false, nil, true, nil)
		if err != nil || !moved {
			t.Fatalf("expected remount, got moved=%v err=%v", moved, err)
		}
		if cwp != "/workspace" {
			t.Errorf("default mount path should be /workspace, got %q", cwp)
		}
		want := []string{"remove:workspace", "remove:git-worktree-common", "mount:workspace:" + ws}
		if strings.Join(f.ops, ",") != strings.Join(want, ",") {
			t.Errorf("ops = %v, want %v", f.ops, want)
		}
	})

	t.Run("preserve path derives the host path", func(t *testing.T) {
		f := &fakeRemounter{source: "/old/place"}
		cwp, moved, err := RemountMovedWorkspace(f, ws, true, nil, false, nil)
		if err != nil || !moved {
			t.Fatalf("expected remount, got moved=%v err=%v", moved, err)
		}
		if cwp != filepath.Clean(ws) {
			t.Errorf("preserve-path cwp = %q, want %q", cwp, filepath.Clean(ws))
		}
	})

	t.Run("worktree layout forces preserve and mounts the common dir", func(t *testing.T) {
		f := &fakeRemounter{source: "/old/place"}
		layout := &GitWorktreeLayout{GitDir: "/repos/main/.git/worktrees/wt", CommonDir: "/repos/main/.git"}
		cwp, moved, err := RemountMovedWorkspace(f, ws, false, layout, true, nil)
		if err != nil || !moved {
			t.Fatalf("expected remount, got moved=%v err=%v", moved, err)
		}
		if cwp != filepath.Clean(ws) {
			t.Errorf("worktree cwp = %q, want preserved %q", cwp, filepath.Clean(ws))
		}
		if !strings.Contains(strings.Join(f.ops, ","), "mount:git-worktree-common:/repos/main/.git") {
			t.Errorf("worktree common dir should be remounted, ops = %v", f.ops)
		}
	})

	t.Run("worktree under system dir fails closed", func(t *testing.T) {
		f := &fakeRemounter{source: "/old/place"}
		layout := &GitWorktreeLayout{CommonDir: "/repos/main/.git"}
		if _, _, err := RemountMovedWorkspace(f, "/etc/ws", false, layout, true, nil); err == nil {
			t.Fatal("worktree under a system dir must fail closed")
		}
		if len(f.ops) != 0 {
			t.Errorf("must fail before touching devices, got %v", f.ops)
		}
	})

	t.Run("workspace remove failure aborts before mounting", func(t *testing.T) {
		f := &fakeRemounter{source: "/old/place", removeErr: errors.New("nope")}
		if _, _, err := RemountMovedWorkspace(f, ws, false, nil, true, nil); err == nil {
			t.Fatal("expected error from RemoveDevice")
		}
		for _, op := range f.ops {
			if strings.HasPrefix(op, "mount:") {
				t.Errorf("must not mount after a failed remove, ops = %v", f.ops)
			}
		}
	})
}

// TestIdentity pins the session_name identity keying (#named-sessions): a name
// yields the same identity from any workspace location, path-keyed identities
// differ per location, and a name can never collide with a real path.
func TestIdentity(t *testing.T) {
	if Identity("/a", "proj") != Identity("/b", "proj") {
		t.Error("named identity must not depend on the workspace path")
	}
	if Identity("/a", "") == Identity("/b", "") {
		t.Error("path-keyed identities must differ per location")
	}
	if Identity("/x", "") == Identity("/ignored", "/x") {
		t.Error("a session name must be namespaced away from real paths")
	}
	if IdentityHash("/a", "proj") != IdentityHash("/b", "proj") {
		t.Error("named identity hash must be location-independent")
	}
	if WorkspaceHash("/a") != IdentityHash("/a", "") {
		t.Error("WorkspaceHash must equal the nameless identity hash")
	}
	if ContainerName("/a", "proj", 1) != ContainerName("/b", "proj", 1) {
		t.Error("container names for a named session must match across workspaces")
	}
}

// TestSameDir pins the symlink-aware comparison: an aliased path
// to the same directory is NOT a move (a spurious remount would churn devices
// on every launch), while genuinely different directories are.
func TestSameDir(t *testing.T) {
	realDir := t.TempDir()
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if !SameDir(realDir, link) {
		t.Error("a symlink alias of the same directory must not count as moved")
	}
	if !SameDir(realDir, realDir+string(filepath.Separator)) {
		t.Error("trailing separator must not count as moved")
	}
	if SameDir(realDir, t.TempDir()) {
		t.Error("different directories must count as moved")
	}
	// Nonexistent paths fall back to a lexical comparison rather than erroring.
	if !SameDir("/no/such/a", "/no/such/a") {
		t.Error("identical nonexistent paths should compare equal lexically")
	}
}

// TestNamedIdentityKeysPorts pins that port allocation follows the SAME
// identity as container naming: a refactor that ignored sessionName in
// AllocateHostPort while honoring it in ContainerName would give a moved
// named session colliding host ports with the path-keyed session at its old
// location.
func TestNamedIdentityKeysPorts(t *testing.T) {
	if AllocateHostPort("/a", "proj", 1, 0) != AllocateHostPort("/b", "proj", 1, 0) {
		t.Error("named identity's ports must be location-independent")
	}
	if AllocateHostPort("/a", "proj", 1, 0) == AllocateHostPort("/a", "", 1, 0) {
		t.Error("named identity must allocate a different port neighborhood than the path identity (hash inputs differ)")
	}
}
