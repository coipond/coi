package container

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeFileIncus serves `exec … find` and `file pull` from root, which stands
// in for the container's filesystem. Opening a FIFO blocks, as over SFTP; a
// recursive pull blocks after copying when its tree holds a FIFO. running
// false fails every exec, as on a stopped container.
func fakeFileIncus(t *testing.T, root string, running bool) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	execCase := `exec) shift 3; [ "$1" = find ] || exit 9; d=$2; shift 2; exec find "$ROOT$d" "$@" ;;`
	if !running {
		execCase = `exec) echo "Error: Instance is not running" >&2; exit 1 ;;`
	}
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\nROOT=" + root + "\nshift 2\ncase \"$1\" in\n" + execCase + `
file) shift 2; rec=; [ "$1" = -r ] && { rec=1; shift; }
  for last; do :; done
  while [ $# -gt 1 ]; do
    s=$ROOT${1#c1}
    [ -p "$s" ] && cat "$s" >/dev/null
    cp -r "$s" "$last" || exit 1
    [ -n "$rec" ] && [ -n "$(find "$s" -type p)" ] && sleep 30
    shift
  done ;;
*) exit 9 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// writeConfigTree builds home/code/.claude under root with real files, a
// clean subdirectory, and a FIFO and a socket next to real files.
func writeConfigTree(t *testing.T, root string) string {
	t.Helper()
	src := filepath.Join(root, "home", "code", ".claude")
	for _, d := range []string{"projects/p", "clean", "ide"} {
		if err := os.MkdirAll(filepath.Join(src, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json"} {
		if err := os.WriteFile(filepath.Join(src, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(src, "projects", "p", "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(src, "ide", "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return src
}

func assertRealFiles(t *testing.T, dest string, names ...string) {
	t.Helper()
	for _, f := range names {
		if b, err := os.ReadFile(filepath.Join(dest, f)); err != nil || string(b) != f {
			t.Errorf("%s: %q %v", f, b, err)
		}
	}
}

// A running container's FIFO and socket are skipped before the pull: the save
// finishes well within the timeout and keeps every real file.
func TestPullDirectoryBounded_SkipsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	writeConfigTree(t, root)
	fakeFileIncus(t, root, true)

	var skipped []string
	dest := filepath.Join(t.TempDir(), "saved")
	start := time.Now()
	err := NewManager("c1").PullDirectoryBounded("/home/code/.claude", dest, 20*time.Second, func(m string) { skipped = append(skipped, m) })
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("pull took %s", d)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json")
	for _, f := range []string{"projects/p/fifo", "ide/s"} {
		if _, err := os.Lstat(filepath.Join(dest, f)); err == nil {
			t.Errorf("%s must not be saved", f)
		}
	}
	got := strings.Join(skipped, "\n")
	if len(skipped) != 2 || !strings.Contains(got, "/home/code/.claude/projects/p/fifo") || !strings.Contains(got, "/home/code/.claude/ide/s") {
		t.Errorf("debug = %q, want both special files", got)
	}
}

// A tree without special files is one recursive pull.
func TestPullDirectoryBounded_CleanTreeIsOnePull(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "home", "code", ".claude")
	if err := os.MkdirAll(filepath.Join(src, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a", "f"), []byte("a/f"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := fakeFileIncus(t, root, true)

	dest := filepath.Join(t.TempDir(), "saved")
	if err := NewManager("c1").PullDirectoryBounded("/home/code/.claude", dest, 20*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "a/f")
	var pulls []string
	for _, c := range calls(t, log) {
		if strings.Contains(c, " file pull ") {
			pulls = append(pulls, c)
		}
	}
	if len(pulls) != 1 || !strings.Contains(pulls[0], " -r c1/home/code/.claude ") {
		t.Errorf("pulls = %q, want one recursive pull of the config dir", pulls)
	}
}

// A stopped container cannot be listed: a FIFO stalls the pull until the
// timeout, which stops it and keeps what was pulled.
func TestPullDirectoryBounded_TimeoutKeepsPulled(t *testing.T) {
	root := t.TempDir()
	writeConfigTree(t, root)
	fakeFileIncus(t, root, false)

	dest := filepath.Join(t.TempDir(), "saved")
	start := time.Now()
	err := NewManager("c1").PullDirectoryBounded("/home/code/.claude", dest, time.Second, nil)
	if !errors.Is(err, ErrPullTimedOut) {
		t.Fatalf("err = %v, want ErrPullTimedOut", err)
	}
	if !strings.Contains(err.Error(), "/home/code/.claude") {
		t.Errorf("err = %v, want the stalled path", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("pull took %s", d)
	}
	assertRealFiles(t, dest, "history.jsonl", "clean/c.json")
	if _, err := os.Lstat(filepath.Join(dest, "projects", "p", "fifo")); err == nil {
		t.Error("FIFO must not be saved")
	}
}

// A stall inside a walked directory names the entry it stalled on.
func TestPullSources_NamesStalledEntry(t *testing.T) {
	root := t.TempDir()
	writeConfigTree(t, root)
	fakeFileIncus(t, root, true)
	local := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	sources := []string{"/home/code/.claude/history.jsonl", "/home/code/.claude/projects/p/fifo", "/home/code/.claude/clean/c.json"}
	err := NewManager("c1").pullSources(ctx, sources, local, false)
	if err == nil || !strings.Contains(err.Error(), "projects/p/fifo") {
		t.Fatalf("err = %v, want the FIFO named", err)
	}
}
