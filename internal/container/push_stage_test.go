package container

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// A rename push sends the staged tree, so it must carry the same modes as the
// source: a 0664 file stays 0664, and a 0555 directory can still be staged.
func TestStagePushTree_KeepsModes(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	src := filepath.Join(t.TempDir(), "src")
	ro := filepath.Join(src, "ro")
	if err := os.MkdirAll(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]fs.FileMode{filepath.Join(src, "rw.txt"): 0o664, filepath.Join(ro, "f.txt"): 0o640} {
		if err := os.WriteFile(p, []byte("x"), m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("rw.txt", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })

	stage := t.TempDir()
	t.Cleanup(func() { removeStage(stage) })
	dst := filepath.Join(stage, "renamed")
	if err := stagePushTree(src, dst); err != nil {
		t.Fatalf("stagePushTree() error = %v", err)
	}

	for rel, want := range map[string]fs.FileMode{
		"rw.txt":   0o664,
		"ro":       fs.ModeDir | 0o555,
		"ro/f.txt": 0o640,
	} {
		if got := mode(t, filepath.Join(dst, rel)); got != want {
			t.Errorf("%s mode = %v, want %v", rel, got, want)
		}
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "rw.txt" {
		t.Errorf("link = %q, %v; want a symlink to rw.txt", target, err)
	}
}

func TestCopyFileExact_IgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := t.TempDir()
	src := filepath.Join(dir, "a")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o664); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(src)
	dst := filepath.Join(dir, "b")
	if err := copyFileExact(src, dst, info); err != nil {
		t.Fatalf("copyFileExact() error = %v", err)
	}
	if got := mode(t, dst); got != 0o664 {
		t.Errorf("copy mode = %v, want 0664", got)
	}
	if b, _ := os.ReadFile(dst); string(b) != "data" {
		t.Errorf("copy content = %q, want %q", b, "data")
	}
}

// A rename push with --archive sends the staged entries' times, so staging
// keeps the source's: on directories filled during staging (a read-only one
// too) and on files copied across filesystems.
func TestStagePushTree_KeepsModTimes(t *testing.T) {
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	src := filepath.Join(t.TempDir(), "src")
	ro := filepath.Join(src, "ro")
	if err := os.MkdirAll(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ro, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	for _, p := range []string{ro, src} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	stage := t.TempDir()
	t.Cleanup(func() { removeStage(stage) })
	dst := filepath.Join(stage, "renamed")
	if err := stagePushTree(src, dst); err != nil {
		t.Fatalf("stagePushTree() error = %v", err)
	}
	for _, rel := range []string{".", "ro"} {
		fi, err := os.Stat(filepath.Join(dst, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.ModTime().Equal(old) {
			t.Errorf("%s mtime = %v, want %v", rel, fi.ModTime(), old)
		}
	}
}

func TestCopyFileExact_KeepsModTime(t *testing.T) {
	old := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := t.TempDir()
	src := filepath.Join(dir, "a")
	if err := os.WriteFile(src, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(src, old, old); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Lstat(src)
	dst := filepath.Join(dir, "b")
	if err := copyFileExact(src, dst, info); err != nil {
		t.Fatalf("copyFileExact() error = %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(old) {
		t.Errorf("copy mtime = %v, want %v", fi.ModTime(), old)
	}
}

func TestRemoveStage_ReadOnlyDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stage")
	ro := filepath.Join(root, "ro")
	if err := os.MkdirAll(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ro, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	removeStage(root)
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("stage %s should be removed, stat err = %v", root, err)
	}
}
