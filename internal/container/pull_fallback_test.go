package container

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeFileIncusScript serves `exec … find`, `query …/files?path=` and
// `file pull --verbose -r` from ROOT, which stands in for the container's
// filesystem. The pull logs each entry as `incus --verbose` does, then opens
// it: a FIFO blocks, a socket fails, a `*.slow` file grows by a byte every
// 0.2 s for SLOW_TICKS ticks. Without RUNNING every exec fails, as on a
// stopped container. VANISH is removed right after the listing.
const fakeFileIncusScript = `
[ "$1" = --project ] && shift 2
pull() {
  if [ -L "$ROOT$1" ]; then echo "level=info msg=\"Pulling $2 from $1 (symlink)\"" >&2; return 0; fi
  if [ -d "$ROOT$1" ]; then
    echo "level=info msg=\"Pulling $2 from $1 (directory)\"" >&2
    mkdir -p "$2" || return 1
    for c in $(ls -A "$ROOT$1"); do pull "$1/$c" "$2/$c" || return 1; done
    return 0
  fi
  [ -e "$ROOT$1" ] || { echo "Error: not found" >&2; return 1; }
  echo "level=info msg=\"Pulling $2 from $1 (file)\"" >&2
  [ -S "$ROOT$1" ] && { echo "Error: no such device or address" >&2; return 1; }
  case "$1" in *.slow)
    i=0; while [ $i -lt "$SLOW_TICKS" ]; do printf x >> "$2"; sleep 0.2; i=$((i+1)); done; return 0 ;;
  esac
  cat "$ROOT$1" > "$2"
}
case "$1" in
exec)
  [ -n "$RUNNING" ] || { echo "Error: Instance is not running" >&2; exit 1; }
  shift 3; d=$2; shift 2; find "$ROOT$d" "$@"; rc=$?
  [ -n "$VANISH" ] && rm -f "$ROOT$VANISH"
  exit $rc ;;
query)
  for q; do :; done
  p=${q#*path=}; p=${p%%&*}; p=$(echo "$p" | sed 's/%2F/\//g')
  if [ -d "$ROOT$p" ]; then
    printf '['; sep=; for c in $(ls -A "$ROOT$p"); do printf '%s"%s"' "$sep" "$c"; sep=,; done; echo ']'
  elif [ -e "$ROOT$p" ]; then cat "$ROOT$p"
  else echo "Error: not found" >&2; exit 1; fi ;;
file)
  shift 2; while [ "${1#-}" != "$1" ]; do shift; done
  for last; do :; done
  while [ $# -gt 1 ]; do s=${1#c1}; pull "$s" "$last${s##*/}" || exit 1; shift; done ;;
*) exit 9 ;;
esac
`

// fakeFileIncus installs fakeFileIncusScript over root and returns its call
// log.
func fakeFileIncus(t *testing.T, root string, running bool) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	env := "ROOT=" + root + "\nSLOW_TICKS=${SLOW_TICKS:-0}\n"
	if running {
		env += "RUNNING=1\n"
	}
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" + env + fakeFileIncusScript
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// writeFiles writes each name (relative to dir) with its name as content.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, f := range names {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// mkfifo plants a FIFO and releases any reader the test leaves blocked on it.
func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

// configRoot returns a fake container root and its home/code/.claude.
func configRoot(t *testing.T) (root, src string) {
	t.Helper()
	root = t.TempDir()
	src = filepath.Join(root, "home", "code", ".claude")
	writeFiles(t, src, "history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json")
	return root, src
}

func assertRealFiles(t *testing.T, dest string, names ...string) {
	t.Helper()
	for _, f := range names {
		if b, err := os.ReadFile(filepath.Join(dest, f)); err != nil || string(b) != f {
			t.Errorf("%s: %q %v", f, b, err)
		}
	}
}

func assertAbsent(t *testing.T, dest string, names ...string) {
	t.Helper()
	for _, f := range names {
		if _, err := os.Lstat(filepath.Join(dest, f)); err == nil {
			t.Errorf("%s must not be saved", f)
		}
	}
}

func pullBounded(t *testing.T, stall time.Duration) (dest string, debug, warn []string, err error) {
	t.Helper()
	dest = filepath.Join(t.TempDir(), "saved")
	err = NewManager("c1").PullDirectoryBounded("/home/code/.claude", dest, stall,
		func(m string) { debug = append(debug, m) }, func(m string) { warn = append(warn, m) })
	return dest, debug, warn, err
}

// A running container's FIFO and socket are skipped before the pull, each
// reported to debug; no pull waits on them.
func TestPullDirectoryBounded_SkipsSpecialFiles(t *testing.T) {
	root, src := configRoot(t)
	mkfifo(t, filepath.Join(src, "projects", "p", "fifo"))
	l, err := net.Listen("unix", filepath.Join(src, "ide", "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	fakeFileIncus(t, root, true)

	start := time.Now()
	dest, debug, warn, err := pullBounded(t, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("pull took %s", d)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json")
	assertAbsent(t, dest, "projects/p/fifo", "ide/s")
	got := strings.Join(debug, "\n")
	if len(debug) != 2 || !strings.Contains(got, "Skipping special file /home/code/.claude/projects/p/fifo") || !strings.Contains(got, "Skipping special file /home/code/.claude/ide/s") {
		t.Errorf("debug = %q, want both special files", got)
	}
	if len(warn) != 0 {
		t.Errorf("warn = %q, want none", warn)
	}
}

// A tree without special files is the listing plus one recursive pull.
func TestPullDirectoryBounded_CleanTreeIsOnePull(t *testing.T) {
	root, _ := configRoot(t)
	log := fakeFileIncus(t, root, true)

	dest, _, _, err := pullBounded(t, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl")
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

// A stopped container cannot be listed: a FIFO stalls the pull, which is
// stopped after the stall timeout, names the FIFO, skips it and pulls the
// rest.
func TestPullDirectoryBounded_StoppedSkipsStalledEntry(t *testing.T) {
	root, src := configRoot(t)
	mkfifo(t, filepath.Join(src, "projects", "a-fifo"))
	writeFiles(t, src, "projects/z.json")
	fakeFileIncus(t, root, false)

	dest, _, warn, err := pullBounded(t, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "projects/z.json", "clean/c.json", "ide/lock.json")
	assertAbsent(t, dest, "projects/a-fifo")
	if len(warn) != 1 || !strings.Contains(warn[0], "Skipping /home/code/.claude/projects/a-fifo") {
		t.Errorf("warn = %q, want the stalled FIFO named", warn)
	}
}

// A slow file that keeps growing is progress: it is pulled whole, even past
// the stall timeout.
func TestPullDirectoryBounded_SlowProgressIsNotAStall(t *testing.T) {
	root, src := configRoot(t)
	writeFiles(t, src, "big.slow")
	fakeFileIncus(t, root, false)
	t.Setenv("SLOW_TICKS", "15") // 3 s at one byte per 0.2 s

	dest, _, warn, err := pullBounded(t, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "big.slow")); err != nil || len(b) != 15 {
		t.Errorf("big.slow: %d bytes, %v; want 15", len(b), err)
	}
	if len(warn) != 0 {
		t.Errorf("warn = %q, want none", warn)
	}
}

// A pull that progresses forever stops at the total limit and keeps what it
// pulled.
func TestPullDirectoryBounded_TotalLimitKeepsPulled(t *testing.T) {
	orig := pullTotalLimit
	pullTotalLimit = 3 * time.Second
	t.Cleanup(func() { pullTotalLimit = orig })
	root, src := configRoot(t)
	writeFiles(t, src, "zz.slow")
	fakeFileIncus(t, root, false)
	t.Setenv("SLOW_TICKS", "100000")

	dest, _, _, err := pullBounded(t, time.Second)
	if !errors.Is(err, ErrPullTimedOut) {
		t.Fatalf("err = %v, want ErrPullTimedOut", err)
	}
	assertRealFiles(t, dest, "history.jsonl", "clean/c.json")
}

// An entry listed in the container but gone by the pull is dropped; the rest
// is saved.
func TestPullDirectoryBounded_VanishedEntry(t *testing.T) {
	root, src := configRoot(t)
	mkfifo(t, filepath.Join(src, "fifo"))
	writeFiles(t, src, "gone.tmp")
	fakeFileIncus(t, root, true)
	t.Setenv("VANISH", "/home/code/.claude/gone.tmp")

	dest, _, _, err := pullBounded(t, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json")
	assertAbsent(t, dest, "fifo", "gone.tmp")
}

// A missing config dir is ErrPullSourceMissing; callers must not read other
// "not found" errors that way.
func TestPullDirectoryBounded_MissingDir(t *testing.T) {
	fakeFileIncus(t, t.TempDir(), false)
	if _, _, _, err := pullBounded(t, time.Second); !errors.Is(err, ErrPullSourceMissing) {
		t.Fatalf("err = %v, want ErrPullSourceMissing", err)
	}
}

func TestParsePullingLine(t *testing.T) {
	const base = "/home/code/.claude"
	tests := []struct {
		line, target, source string
		ok                   bool
	}{
		{`time="2026-11-23T20:00:00Z" level=info msg="Pulling /tmp/x/.claude/a b from /home/code/.claude/a b (file)"`, "/tmp/x/.claude/a b", "/home/code/.claude/a b", true},
		{`INFO   [2026-11-23T20:00:00Z] Pulling /tmp/x/.claude from /home/code/.claude (directory)`, "/tmp/x/.claude", "/home/code/.claude", true},
		{`Error: not found`, "", "", false},
		{`level=info msg="Pulling /tmp/x from /etc/passwd (file)"`, "", "", false},
	}
	for _, tt := range tests {
		target, source, ok := parsePullingLine(tt.line, base)
		if target != tt.target || source != tt.source || ok != tt.ok {
			t.Errorf("parsePullingLine(%q) = %q, %q, %v; want %q, %q, %v", tt.line, target, source, ok, tt.target, tt.source, tt.ok)
		}
	}
}
