package session

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func pinPaths(mounts []mountedDevice) []string {
	var out []string
	for _, m := range mounts {
		if strings.HasPrefix(m.name, pinDevicePrefix) {
			out = append(out, m.path)
		}
	}
	slices.Sort(out)
	return out
}

// Every parent dir of a default protected path is pinned read-write, once, so
// it cannot be renamed aside; top-level protected dirs need no pin.
func TestSetupSecurityMounts_PinsParentDirs(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	defaults := []string{".git/hooks", ".git/config", ".git/info/attributes", ".husky", ".vscode", ".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml"}

	rec := &recordingDevices{}
	if _, err := SetupSecurityMounts(rec, tmp, "/workspace", defaults, true, nil, NestedGitScan{}, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"/workspace/.claude", "/workspace/.codex", "/workspace/.git", "/workspace/.git/info"}
	if got := pinPaths(rec.mounts); !slices.Equal(got, want) {
		t.Errorf("pins = %v, want %v", got, want)
	}
	for _, m := range rec.mounts {
		if !strings.HasPrefix(m.name, pinDevicePrefix) {
			continue
		}
		if m.readonly || !m.shift {
			t.Errorf("pin %s: want read-write with shift, got readonly=%v shift=%v", m.path, m.readonly, m.shift)
		}
		if m.source != filepath.Join(tmp, strings.TrimPrefix(m.path, "/workspace/")) {
			t.Errorf("pin %s: source %s", m.path, m.source)
		}
	}
}

// The pin walk stops at a symlink and skips a parent that is protected itself.
func TestParentPinMounts_SymlinkAndProtectedParent(t *testing.T) {
	tmp := t.TempDir()
	for _, d := range []string{"x/real/y", "d/e"} {
		if err := os.MkdirAll(filepath.Join(tmp, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(tmp, "x", "real"), filepath.Join(tmp, "x", "link")); err != nil {
		t.Fatal(err)
	}

	pins := parentPinMounts(tmp, "/w", []string{"x/link/y/z", "d", "d/e/f"}, false)
	var got []string
	for _, p := range pins {
		got = append(got, p.Path)
	}
	slices.Sort(got)
	if want := []string{"/w/d/e", "/w/x"}; !slices.Equal(got, want) {
		t.Errorf("pins = %v, want %v", got, want)
	}
}

// The git common dir of a worktree checkout gets the same pins, at its host
// path.
func TestSetupCommonDirProtection_PinsParentDirs(t *testing.T) {
	common := t.TempDir()
	mkGitDir(t, common, ".")
	if err := os.MkdirAll(filepath.Join(common, "worktrees", "wt1"), 0o755); err != nil {
		t.Fatal(err)
	}

	rec := &recordingDevices{}
	if _, err := SetupCommonDirProtection(rec, common, false, false, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{filepath.Join(common, "info"), filepath.Join(common, "worktrees"), filepath.Join(common, "worktrees", "wt1")}
	if got := pinPaths(rec.mounts); !slices.Equal(got, want) {
		t.Errorf("pins = %v, want %v", got, want)
	}
}

// Pin names come from the container path, so equal relative paths under the
// workspace and a common dir do not collide.
func TestPinDeviceName_ByContainerPath(t *testing.T) {
	a, b := pinDeviceName("/workspace/info"), pinDeviceName("/repo/.git/info")
	if a == b || !strings.HasPrefix(a, pinDevicePrefix) || len(a) != len(pinDevicePrefix)+16 {
		t.Errorf("unexpected pin names %q, %q", a, b)
	}
}
