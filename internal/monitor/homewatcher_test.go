package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUserFiles(t *testing.T) {
	files := userFiles("dev", []string{".claude/.credentials.json"})
	want := map[string]string{
		"home/dev/.ssh/authorized_keys":      "persistence",
		"home/dev/.bashrc":                   "persistence",
		"home/dev/.profile":                  "persistence",
		"var/spool/cron/crontabs/dev":        "persistence",
		"home/dev/.claude/.credentials.json": "credential_access",
	}
	if len(files) != len(want) {
		t.Fatalf("userFiles() = %d files, want %d", len(files), len(want))
	}
	for _, f := range files {
		if want[f.rel] != f.category || f.title == "" || f.desc == "" {
			t.Errorf("userFiles(): %+v", f)
		}
	}
}

func TestUserFileWatcherWatchedDirs(t *testing.T) {
	w := NewUserFileWatcher("c", "dev", []string{".pi/agent/auth.json"}, nil, nil)
	got := w.watchedDirs()
	want := []string{"home/dev/.ssh", "home/dev", "var/spool/cron/crontabs", "home/dev/.pi/agent", "home/dev/.pi"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("watchedDirs() = %v, want %v", got, want)
	}
	if !w.onWatchedPath("home/dev/.pi") || w.onWatchedPath("home/dev/.cache") {
		t.Error("onWatchedPath: wrong answer for .pi or .cache")
	}
}

func TestUserFileWatcherFromHost(t *testing.T) {
	dir := t.TempDir()
	orig := procCgroupFmt
	procCgroupFmt = dir + "/%d"
	t.Cleanup(func() { procCgroupFmt = orig })

	cases := map[int]struct {
		cgroup string
		host   bool
	}{
		1: {"0::/lxc.payload.coi-1/user.slice\n", false},
		2: {"0::/lxc.payload.coi-1\n", false},
		3: {"0::/lxc.payload/coi-1/init.scope\n", false},
		4: {"0::/system.slice/incus.service\n", true},
		5: {"0::/lxc.payload.coi-12\n", true},
	}
	for pid, c := range cases {
		if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, pid), []byte(c.cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := NewUserFileWatcher("coi-1", "code", nil, nil, nil)
	for pid, c := range cases {
		if got := w.fromHost(pid); got != c.host {
			t.Errorf("fromHost(%q) = %v, want %v", c.cgroup, got, c.host)
		}
	}
	if w.fromHost(99) {
		t.Error("fromHost of a gone process = true, want false")
	}
}

// TestUserFileWatcherEvents runs the watcher's mark pass and event handling
// on a temp root with an unprivileged FAN_REPORT_DFID_NAME group.
func TestUserFileWatcherEvents(t *testing.T) {
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		t.Skipf("unprivileged fanotify name events unavailable: %v", err)
	}
	defer unix.Close(ifd)

	root := t.TempDir()
	origRoot, origCgroup := procRootFmt, procCgroupFmt
	procRootFmt = root + "/%d"
	procCgroupFmt = root + "/cgroup-%d"
	t.Cleanup(func() { procRootFmt, procCgroupFmt = origRoot, origCgroup })
	self := os.Getpid()
	if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, self), []byte("0::/lxc.payload.c/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "1", "home", "code")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}

	var threats []ThreatEvent
	w := NewUserFileWatcher("c", "code", []string{".claude/.credentials.json"}, func(e ThreatEvent) { threats = append(threats, e) }, nil)
	st := userWatchState{dirs: make(map[dirKey]string)}
	w.mark(ifd, 1, &st)
	if len(st.dirs) != 1 {
		t.Fatalf("marked %v, want only home/code", st.dirs)
	}
	st.graceUntil = time.Time{}

	ctx, cancel := context.WithCancel(context.Background())
	evCh := make(chan fanNameEvent, 64)
	done := make(chan struct{})
	go func() { defer close(done); readNameEvents(ctx, ifd, evCh) }()
	defer func() { cancel(); <-done }()

	// drain handles events until want threats were raised or 5 s passed.
	drain := func(want int) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for len(threats) < want {
			select {
			case ev := <-evCh:
				w.handle(ifd, ev, &st)
			case <-deadline:
				t.Fatalf("threats = %d, want %d: %+v", len(threats), want, threats)
			}
		}
	}

	// Create, then rename over.
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	drain(1)
	tmp := filepath.Join(root, "1", "tmp-profile")
	if err := os.WriteFile(tmp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(home, ".profile")); err != nil {
		t.Fatal(err)
	}
	drain(2)
	// A directory on a watched path is marked when created.
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "unwatched"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The write to an unwatched file is handled after the mkdir, so once it
	// is in, the new directory is marked.
	deadline := time.After(5 * time.Second)
	for len(st.dirs) < 2 {
		select {
		case ev := <-evCh:
			w.handle(ifd, ev, &st)
		case <-deadline:
			t.Fatalf("new .claude directory not marked: %v", st.dirs)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	drain(3)

	for i, rel := range []string{"home/code/.bashrc", "home/code/.profile", "home/code/.claude/.credentials.json"} {
		got := threats[i]
		if got.Level != ThreatLevelHigh || got.Evidence.SensitiveFile == nil ||
			got.Evidence.SensitiveFile.Path != rel || got.Evidence.SensitiveFile.Pid != self {
			t.Errorf("threat %d = %+v, want HIGH write of %s by %d", i, got, rel, self)
		}
	}

	// A write from outside the container's cgroup (coi's copy) is not flagged.
	if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, self), []byte("0::/system.slice/incus.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	quiet := time.After(500 * time.Millisecond)
	for {
		select {
		case ev := <-evCh:
			w.handle(ifd, ev, &st)
			continue
		case <-quiet:
		}
		break
	}
	if len(threats) != 3 {
		t.Errorf("host-side write raised a threat: %+v", threats[3:])
	}
}

func TestUserFileWatcherGracePeriod(t *testing.T) {
	var threats int
	w := NewUserFileWatcher("c", "code", nil, func(ThreatEvent) { threats++ }, nil)
	st := userWatchState{pid: 1, dirs: map[dirKey]string{"k": "home/code"}, graceUntil: time.Now().Add(time.Minute)}
	w.handle(-1, fanNameEvent{mask: unix.FAN_CLOSE_WRITE, pid: -1, dir: "k", name: ".bashrc"}, &st)
	if threats != 0 {
		t.Errorf("threat raised in the grace period")
	}
	st.graceUntil = time.Time{}
	w.handle(-1, fanNameEvent{mask: unix.FAN_CLOSE_WRITE, pid: -1, dir: "k", name: ".bashrc"}, &st)
	w.handle(-1, fanNameEvent{mask: unix.FAN_CREATE, pid: -1, dir: "k", name: ".bashrc"}, &st)
	if threats != 1 {
		t.Errorf("threats = %d, want 1 (close-write only, not create)", threats)
	}
}

func TestParseNameEventsTruncated(t *testing.T) {
	if evs := parseNameEvents([]byte{1, 2, 3}); len(evs) != 0 {
		t.Errorf("parseNameEvents(short) = %v", evs)
	}
	buf := make([]byte, 24)
	buf[0] = 200 // event_len past the buffer
	if evs := parseNameEvents(buf); len(evs) != 0 {
		t.Errorf("parseNameEvents(truncated) = %v", evs)
	}
}
