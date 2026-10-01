package session

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func relsOf(masks []secretMask) []string {
	out := make([]string, 0, len(masks))
	for _, m := range masks {
		out = append(out, m.relPath)
	}
	sort.Strings(out)
	return out
}

func isDirOf(masks []secretMask, rel string) (bool, bool) {
	for _, m := range masks {
		if m.relPath == rel {
			return m.isDir, true
		}
	}
	return false, false
}

func writeFileIn(t *testing.T, ws, rel, content string) {
	t.Helper()
	p := filepath.Join(ws, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExpandSecretPaths(t *testing.T) {
	ws := t.TempDir()
	writeFileIn(t, ws, ".env", "SECRET=1")
	writeFileIn(t, ws, "key.pem", "k")
	writeFileIn(t, ws, "other.pem", "k")
	writeFileIn(t, ws, "secrets/db", "pw")
	writeFileIn(t, ws, "nested/deep.pem", "k") // not matched by top-level *.pem
	writeFileIn(t, ws, "README.md", "x")

	masks, skipped := expandSecretPaths(ws, []string{".env", "*.pem", "secrets/**"})
	got := relsOf(masks)
	want := []string{".env", "key.pem", "other.pem", "secrets"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v (skipped %v)", want, got, skipped)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("expected %v, got %v", want, got)
			break
		}
	}
	if dir, ok := isDirOf(masks, "secrets"); !ok || !dir {
		t.Errorf("secrets should be masked as a directory")
	}
	if dir, ok := isDirOf(masks, ".env"); !ok || dir {
		t.Errorf(".env should be masked as a file")
	}
	for _, m := range masks {
		if m.relPath == "nested/deep.pem" || m.relPath == "README.md" {
			t.Errorf("unexpected match: %s", m.relPath)
		}
	}
}

// A secret that is a symlink to an IN-WORKSPACE target must be masked at the
// resolved real path (so a repo cannot evade masking by symlinking the secret).
func TestExpandSecretPaths_ResolvesInWorkspaceSymlink(t *testing.T) {
	ws := t.TempDir()
	writeFileIn(t, ws, "shared/real.env", "SECRET=topsecret")
	if err := os.Symlink(filepath.Join("shared", "real.env"), filepath.Join(ws, ".env")); err != nil {
		t.Fatal(err)
	}

	masks, skipped := expandSecretPaths(ws, []string{".env"})
	if len(skipped) != 0 {
		t.Errorf("an in-workspace symlinked secret must NOT be skipped, skipped=%v", skipped)
	}
	got := relsOf(masks)
	if len(got) != 1 || got[0] != "shared/real.env" {
		t.Fatalf("symlinked .env should resolve+mask shared/real.env, got %v", got)
	}
}

// A symlink resolving OUTSIDE the workspace (not reachable in the container) and
// a missing path are reported as skipped (so the caller can warn), not masked.
func TestExpandSecretPaths_SkipsEscapingSymlinkAndMissing(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(ws, "escape.pem")); err != nil {
		t.Fatal(err)
	}

	masks, skipped := expandSecretPaths(ws, []string{"escape.pem", "does-not-exist"})
	if len(masks) != 0 {
		t.Errorf("escaping symlink + missing path must not be masked, got %v", relsOf(masks))
	}
	// escape.pem matches the glob and resolves outside -> skipped; the missing
	// literal produces no glob match (so it is simply absent), which is fine.
	foundEscape := false
	for _, s := range skipped {
		if s == "escape.pem" {
			foundEscape = true
		}
	}
	if !foundEscape {
		t.Errorf("escaping symlink should be reported as skipped, skipped=%v", skipped)
	}
}

func TestExpandSecretPaths_RejectsTraversal(t *testing.T) {
	ws := t.TempDir()
	masks, _ := expandSecretPaths(ws, []string{"../etc/passwd", "..", ""})
	if len(masks) != 0 {
		t.Errorf("traversal/empty patterns must be rejected, got %v", relsOf(masks))
	}
}

// maskDeviceName must be collision-free for distinct paths (the pre-fix lossy
// pathToDeviceName collapsed e.g. ".env"/"env" and "secrets/db.conf"/"secrets/dbconf").
func TestMaskDeviceName_CollisionFree(t *testing.T) {
	collidingPairs := [][2]string{
		{".env", "env"},
		{"secrets/db.conf", "secrets/dbconf"},
		{"config/.key", "config-key"},
	}
	for _, p := range collidingPairs {
		if maskDeviceName(p[0]) == maskDeviceName(p[1]) {
			t.Errorf("device names collide for %q and %q: both %q", p[0], p[1], maskDeviceName(p[0]))
		}
	}
	// Stable per path, valid prefix, distinct from the protect-* scheme.
	stable := maskDeviceName(".env")
	for i := 0; i < 3; i++ {
		if got := maskDeviceName(".env"); got != stable {
			t.Errorf("maskDeviceName must be stable for the same path: %q != %q", got, stable)
		}
	}
	for _, in := range []string{".env", "secrets/db.conf"} {
		name := maskDeviceName(in)
		if len(name) < 6 || name[:5] != "mask-" {
			t.Errorf("maskDeviceName(%q) = %q; want a mask- prefix", in, name)
		}
		if name == pathToDeviceName(in) {
			t.Errorf("mask and protect device names must differ for %q", in)
		}
	}
}
