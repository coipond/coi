package container

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeFileIncusScript serves `exec … find`, `query …/files?path=` and
// `file pull --verbose -r` from ROOT, which stands in for the container's
// filesystem. The pull logs each entry as `incus --verbose` does (logrus
// quoting), then opens the source before it creates the target, as Incus
// does: a FIFO blocks, a socket fails with an SFTP status, a `*.slow` file
// grows by a byte every
// 0.2 s for SLOW_TICKS ticks. Each file reached is appended to PULLED if
// set. Without RUNNING every exec fails, as on a
// stopped container. VANISH is removed right after the listing.
const fakeFileIncusScript = `
[ "$1" = --project ] && shift 2
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
logpull() { printf 'level=info msg="%s"\n' "$(esc "Pulling $1 from $2 ($3)")" >&2; }
pull() {
  if [ -L "$ROOT$1" ]; then logpull "$2" "$1" symlink; return 0; fi
  if [ -d "$ROOT$1" ]; then
    logpull "$2" "$1" directory
    mkdir -p "$2" || return 1
    for c in $(ls -A "$ROOT$1"); do pull "$1/$c" "$2/$c" || return 1; done
    return 0
  fi
  [ -e "$ROOT$1" ] || { echo "Error: not found" >&2; return 1; }
  logpull "$2" "$1" file
  [ -n "$PULLED" ] && echo "$1" >> "$PULLED"
  [ -S "$ROOT$1" ] && { echo 'Error: sftp: "no such device or address" (SSH_FX_FAILURE)' >&2; return 1; }
  case "$1" in *.slow)
    i=0; while [ $i -lt "$SLOW_TICKS" ]; do printf x >> "$2"; sleep 0.2; i=$((i+1)); done; return 0 ;;
  esac
  exec 3< "$ROOT$1" || return 1
  cat <&3 > "$2"; rc=$?; exec 3<&-
  return $rc
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
    printf '['; sep=; for c in $(ls -A "$ROOT$p"); do printf '%s"%s"' "$sep" "$(esc "$c")"; sep=,; done; echo ']'
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
	logrus := func(msg string) string { return `time="2026-11-23T20:00:00Z" level=info msg=` + strconv.Quote(msg) }
	tests := []struct {
		line, target, source, typ string
		ok                        bool
	}{
		{logrus("Pulling /tmp/x/.claude/a b from /home/code/.claude/a b (file)"), "/tmp/x/.claude/a b", "/home/code/.claude/a b", "file", true},
		{logrus(`Pulling /tmp/x/.claude/a"b from /home/code/.claude/a"b (file)`), `/tmp/x/.claude/a"b`, `/home/code/.claude/a"b`, "file", true},
		{logrus(`Pulling /tmp/x/.claude/a\b from /home/code/.claude/a\b (file)`), `/tmp/x/.claude/a\b`, `/home/code/.claude/a\b`, "file", true},
		{logrus("Pulling /tmp/x/.claude/a\xffb from /home/code/.claude/a\xffb (file)"), "/tmp/x/.claude/a\xffb", "/home/code/.claude/a\xffb", "file", true},
		{`INFO   [2026-11-23T20:00:00Z] Pulling /tmp/x/.claude from /home/code/.claude (directory)`, "/tmp/x/.claude", "/home/code/.claude", "directory", true},
		{`Error: not found`, "", "", "", false},
		{logrus("Pulling /tmp/x from /etc/passwd (file)"), "", "", "", false},
		{`level=info msg="Pulling /tmp/x from /home/code/.claude/a (file)`, "", "", "", false},
	}
	for _, tt := range tests {
		target, source, typ, ok := parsePullingLine(tt.line, base)
		if target != tt.target || source != tt.source || typ != tt.typ || ok != tt.ok {
			t.Errorf("parsePullingLine(%q) = %q, %q, %q, %v; want %q, %q, %q, %v", tt.line, target, source, typ, ok, tt.target, tt.source, tt.typ, tt.ok)
		}
	}
}

// pulledCounts counts how often each file was reached (fake PULLED log).
func pulledCounts(t *testing.T, log string) map[string]int {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, l := range strings.Fields(string(b)) {
		counts[l]++
	}
	return counts
}

// Stalls on k FIFOs cost k stall waits, not k extra copies of the tree:
// files pulled before a stall are not pulled again.
func TestPullDirectoryBounded_StallsDoNotRepull(t *testing.T) {
	root, src := configRoot(t)
	for _, f := range []string{"a-fifo", "clean/b-fifo", "projects/p/c-fifo"} {
		mkfifo(t, filepath.Join(src, f))
	}
	fakeFileIncus(t, root, false)
	log := filepath.Join(t.TempDir(), "pulled")
	t.Setenv("PULLED", log)

	dest, _, warn, err := pullBounded(t, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json")
	if len(warn) != 3 {
		t.Errorf("warn = %q, want 3 skipped FIFOs", warn)
	}
	for f, n := range pulledCounts(t, log) {
		if n != 1 && !strings.HasSuffix(f, "-fifo") {
			t.Errorf("%s pulled %d times, want 1", f, n)
		}
	}
}

// The stall waits of one pull are capped in total: past the budget it stops
// and keeps what it pulled.
func TestPullDirectoryBounded_StallBudget(t *testing.T) {
	orig := pullStallBudget
	pullStallBudget = 2500 * time.Millisecond
	t.Cleanup(func() { pullStallBudget = orig })
	root, src := configRoot(t)
	for _, f := range []string{"a-fifo", "b-fifo", "c-fifo"} {
		mkfifo(t, filepath.Join(src, f))
	}
	fakeFileIncus(t, root, false)

	dest, _, warn, err := pullBounded(t, time.Second)
	if !errors.Is(err, ErrPullTimedOut) {
		t.Fatalf("err = %v, want ErrPullTimedOut", err)
	}
	if len(warn) != 2 {
		t.Errorf("warn = %q, want 2 skips within the budget", warn)
	}
	if _, statErr := os.Stat(dest); statErr != nil {
		t.Errorf("pulled part not kept: %v", statErr)
	}
}

// Vanished entries in a batch are found with one listing of its directory,
// not one query per source.
func TestPullDirectoryBounded_VanishedEntryOneListing(t *testing.T) {
	root, src := configRoot(t)
	mkfifo(t, filepath.Join(src, "fifo"))
	for i := range 20 {
		writeFiles(t, src, fmt.Sprintf("f%02d", i))
	}
	writeFiles(t, src, "gone.tmp")
	log := fakeFileIncus(t, root, true)
	t.Setenv("VANISH", "/home/code/.claude/gone.tmp")

	dest, _, _, err := pullBounded(t, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "f00", "f19")
	queries := 0
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "query ") {
			queries++
		}
	}
	if queries != 1 {
		t.Errorf("incus query calls = %d, want 1", queries)
	}
}

// Names that logrus escapes (a quote, a backslash) are skipped by their real
// path on a stopped container.
func TestPullDirectoryBounded_StoppedSkipsQuotedNames(t *testing.T) {
	root, src := configRoot(t)
	mkfifo(t, filepath.Join(src, `a"b`))
	mkfifo(t, filepath.Join(src, "projects", `a\b`))
	fakeFileIncus(t, root, false)

	dest, _, warn, err := pullBounded(t, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json")
	got := strings.Join(warn, "\n")
	if len(warn) != 2 || !strings.Contains(got, `/home/code/.claude/a"b`) || !strings.Contains(got, `/home/code/.claude/projects/a\b`) {
		t.Errorf("warn = %q, want both FIFOs by their real paths", got)
	}
}

// A socket on a stopped container fails to open; it is skipped with a
// warning and the rest is saved.
func TestPullDirectoryBounded_StoppedSkipsSocket(t *testing.T) {
	root, src := configRoot(t)
	l, err := net.Listen("unix", filepath.Join(src, "ide", "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	fakeFileIncus(t, root, false)

	dest, _, warn, err := pullBounded(t, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertRealFiles(t, dest, "history.jsonl", "projects/p/s.jsonl", "clean/c.json", "ide/lock.json")
	assertAbsent(t, dest, "ide/s")
	if len(warn) != 1 || !strings.Contains(warn[0], "Skipping /home/code/.claude/ide/s") || !strings.Contains(warn[0], "no such device or address") {
		t.Errorf("warn = %q, want the socket named with the error", warn)
	}
}

// A failure that is not an SFTP status for the entry (a dropped connection)
// fails the pull instead of skipping a file.
func TestPullOnce_ConnectionErrorIsNotASkip(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\necho 'level=info msg=\"Pulling /tmp/t/h from /home/code/.claude/h (file)\"' >&2\necho 'Error: connection lost' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	p := &boundedPull{m: NewManager("c1"), base: "/home/code/.claude", stall: time.Second, skip: map[string]bool{}}
	err := p.pullOnce(t.Context(), []string{"/home/code/.claude"}, t.TempDir())
	var se *stallError
	if err == nil || errors.As(err, &se) {
		t.Fatalf("err = %v, want a plain pull error", err)
	}
}

// Past pullMaxEntryFailures unopenable entries the pull stops and keeps what
// it pulled, instead of failing the save.
func TestPullDirectoryBounded_EntryFailureCapKeepsPulled(t *testing.T) {
	orig := pullMaxEntryFailures
	pullMaxEntryFailures = 2
	t.Cleanup(func() { pullMaxEntryFailures = orig })
	root, src := configRoot(t)
	for _, n := range []string{"s1", "s2", "s3"} {
		l, err := net.Listen("unix", filepath.Join(src, "ide", n))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
	}
	fakeFileIncus(t, root, false)

	dest, _, warn, err := pullBounded(t, 20*time.Second)
	if !errors.Is(err, ErrPullTimedOut) {
		t.Fatalf("err = %v, want ErrPullTimedOut", err)
	}
	if len(warn) != 2 {
		t.Errorf("warn = %q, want 2 skipped sockets", warn)
	}
	assertRealFiles(t, dest, "history.jsonl", "clean/c.json")
}

// An SFTP error after the target was created (a read failed mid-file) is not
// a skip: the file would be saved truncated.
func TestPullOnce_ErrorAfterTargetCreatedIsNotASkip(t *testing.T) {
	local := t.TempDir()
	target := filepath.Join(local, "h")
	bin := t.TempDir()
	script := "#!/bin/sh\necho 'level=info msg=\"Pulling " + target + " from /home/code/.claude/h (file)\"' >&2\n" +
		"printf part > " + target + "\n" +
		"echo 'Error: sftp: \"failure\" (SSH_FX_FAILURE)' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	p := &boundedPull{m: NewManager("c1"), base: "/home/code/.claude", stall: time.Second, skip: map[string]bool{}}
	err := p.pullOnce(t.Context(), []string{"/home/code/.claude/h"}, local)
	var se *stallError
	if err == nil || errors.As(err, &se) {
		t.Fatalf("err = %v, want a plain pull error", err)
	}
}
