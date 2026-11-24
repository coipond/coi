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
	w := NewUserFileWatcher("c", "", "dev", []string{".pi/agent/auth.json"}, nil, nil)
	got := w.watchedDirs()
	want := []string{
		"home/dev/.ssh", "home/dev", "var/spool/cron/crontabs", "var/spool/cron", "var/spool",
		"home/dev/.pi/agent", "home/dev/.pi",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("watchedDirs() = %v, want %v", got, want)
	}
	if !w.onWatchedPath("home/dev/.pi") || !w.onWatchedPath("var/spool/cron") || w.onWatchedPath("home/dev/.cache") {
		t.Error("onWatchedPath: wrong answer for .pi, var/spool/cron or .cache")
	}
}

func TestUserFileWatcherFromHost(t *testing.T) {
	dir := t.TempDir()
	orig := procCgroupFmt
	procCgroupFmt = dir + "/%d"
	t.Cleanup(func() { procCgroupFmt = orig })

	cases := map[int]struct {
		cgroup   string
		host     bool // container coi-1 in the default project
		hostInP1 bool // container coi-1 in project p1
	}{
		1: {"0::/lxc.payload.coi-1/user.slice\n", false, true},
		2: {"0::/lxc.payload.coi-1\n", false, true},
		3: {"0::/lxc.payload/coi-1/init.scope\n", false, true},
		4: {"0::/system.slice/incus.service\n", true, true},
		5: {"0::/lxc.payload.coi-12\n", true, true},
		6: {"0::/lxc.payload.p1_coi-1/user.slice\n", true, false},
		7: {"0::/lxc.payload.p1_coi-1\n", true, false},
	}
	for pid, c := range cases {
		if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, pid), []byte(c.cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	def := NewUserFileWatcher("coi-1", "default", "code", nil, nil, nil)
	p1 := NewUserFileWatcher("coi-1", "p1", "code", nil, nil, nil)
	for pid, c := range cases {
		if got := def.fromHost(pid); got != c.host {
			t.Errorf("default project: fromHost(%q) = %v, want %v", c.cgroup, got, c.host)
		}
		if got := p1.fromHost(pid); got != c.hostInP1 {
			t.Errorf("project p1: fromHost(%q) = %v, want %v", c.cgroup, got, c.hostInP1)
		}
	}
	if def.fromHost(99) {
		t.Error("fromHost of a gone process = true, want false")
	}
}

// watchHarness runs the watcher's mark pass and event handling on a temp
// root (init PID 1) with an unprivileged fanotify FID group, as the test
// process, which counts as in the container.
type watchHarness struct {
	t       *testing.T
	root    string
	home    string
	ifd     int
	w       *UserFileWatcher
	st      *userWatchState
	evCh    chan fanFidEvent
	threats []ThreatEvent
	seen    int // threats before this index were matched by waitFor
}

// newWatchHarness creates the temp root with home/code and var/spool, and
// prepare(root) run before the first mark pass. Call start before events.
func newWatchHarness(t *testing.T, prepare func(root string)) *watchHarness {
	t.Helper()
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME|unix.FAN_REPORT_FID, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		t.Skipf("unprivileged fanotify FID events unavailable: %v", err)
	}
	t.Cleanup(func() { unix.Close(ifd) })

	root := t.TempDir()
	origRoot, origCgroup, origRefire := procRootFmt, procCgroupFmt, refireAfter
	procRootFmt = root + "/%d"
	procCgroupFmt = root + "/cgroup-%d"
	refireAfter = 0
	t.Cleanup(func() { procRootFmt, procCgroupFmt, refireAfter = origRoot, origCgroup, origRefire })
	h := &watchHarness{t: t, root: filepath.Join(root, "1"), ifd: ifd}
	h.home = filepath.Join(h.root, "home", "code")
	h.setCgroup("0::/lxc.payload.c/x\n")
	for _, d := range []string{h.home, filepath.Join(h.root, "var", "spool")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if prepare != nil {
		prepare(h.root)
	}
	h.w = NewUserFileWatcher("c", "", "code", []string{".claude/.credentials.json"}, func(e ThreatEvent) { h.threats = append(h.threats, e) }, nil)
	h.st = newUserWatchState()
	h.w.mark(ifd, 1, h.st)
	h.st.graceUntil = time.Time{}
	return h
}

// start starts reading events into an evCh of capacity n.
func (h *watchHarness) start(n int) *watchHarness {
	h.evCh = make(chan fanFidEvent, n)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); readFidEvents(ctx, h.ifd, h.evCh) }()
	h.t.Cleanup(func() { cancel(); <-done })
	return h
}

// setCgroup writes the test process's cgroup file.
func (h *watchHarness) setCgroup(cg string) {
	if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, os.Getpid()), []byte(cg), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// write writes data to rel (under the temp root).
func (h *watchHarness) write(rel, data string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, rel), []byte(data), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// waitFor handles events until a new threat for rel by this process is
// raised, or fails after 5 s.
func (h *watchHarness) waitFor(rel string) {
	h.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		for ; h.seen < len(h.threats); h.seen++ {
			got := h.threats[h.seen]
			if got.Evidence.SensitiveFile != nil && got.Evidence.SensitiveFile.Path == rel {
				if got.Level != ThreatLevelHigh || got.Evidence.SensitiveFile.Pid != os.Getpid() {
					h.t.Errorf("threat %+v, want HIGH by %d", got, os.Getpid())
				}
				h.seen++
				return
			}
		}
		select {
		case ev := <-h.evCh:
			h.w.handle(h.ifd, ev, h.st)
		case <-deadline:
			h.t.Fatalf("no threat for %s; threats: %+v", rel, h.threats)
		}
	}
}

// quiet handles events for d and returns the threats raised meanwhile.
func (h *watchHarness) quiet(d time.Duration) []ThreatEvent {
	before := len(h.threats)
	end := time.After(d)
	for {
		select {
		case ev := <-h.evCh:
			h.w.handle(h.ifd, ev, h.st)
		case <-end:
			return h.threats[before:]
		}
	}
}

func TestUserFileWatcherEvents(t *testing.T) {
	h := newWatchHarness(t, nil).start(64)

	// Create, then rename over.
	h.write("home/code/.bashrc", "x")
	h.waitFor("home/code/.bashrc")
	h.write("tmp-profile", "x")
	if err := os.Rename(filepath.Join(h.root, "tmp-profile"), filepath.Join(h.home, ".profile")); err != nil {
		t.Fatal(err)
	}
	h.waitFor("home/code/.profile")
	// A directory on a watched path is marked when created.
	if err := os.Mkdir(filepath.Join(h.home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.quiet(200 * time.Millisecond)
	h.write("home/code/.claude/.credentials.json", "{}")
	h.waitFor("home/code/.claude/.credentials.json")
	// A prepared directory renamed into place: its watched file is flagged.
	prepared := filepath.Join(h.root, "prepared")
	if err := os.MkdirAll(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	h.write("prepared/authorized_keys", "k")
	if err := os.Rename(prepared, filepath.Join(h.home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	h.waitFor("home/code/.ssh/authorized_keys")
	// A symlink at a watched path (no write to it) is flagged.
	if err := os.Remove(filepath.Join(h.home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/elsewhere", filepath.Join(h.home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	h.waitFor("home/code/.bashrc")

	// A write from outside the container's cgroup (coi's copy) is not flagged.
	h.setCgroup("0::/system.slice/incus.service\n")
	h.write("home/code/.claude/.credentials.json", "{}")
	if got := h.quiet(500 * time.Millisecond); len(got) != 0 {
		t.Errorf("host-side write raised a threat: %+v", got)
	}
}

// TestUserFileWatcherInodeWrites checks writes that reach a watched file
// without a close or not through its path: the inode mark sees them.
func TestUserFileWatcherInodeWrites(t *testing.T) {
	h := newWatchHarness(t, func(root string) {
		if err := os.WriteFile(filepath.Join(root, "home", "code", ".bashrc"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "home", "code", ".profile"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}).start(64)

	// A hard link in an unmarked directory.
	link := filepath.Join(h.root, "link")
	if err := os.Link(filepath.Join(h.home, ".bashrc"), link); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(link, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("evil\n"); err != nil {
		t.Fatal(err)
	}
	// Kept open: the write alone is seen.
	h.waitFor("home/code/.bashrc")
	f.Close()

	// truncate(2) by path.
	if err := os.Truncate(filepath.Join(h.home, ".profile"), 0); err != nil {
		t.Fatal(err)
	}
	h.waitFor("home/code/.profile")
}

// TestUserFileWatcherNewInodeMarked checks a watched file created after
// the mark pass gets an inode mark: a write through a hard link elsewhere
// is seen.
func TestUserFileWatcherNewInodeMarked(t *testing.T) {
	h := newWatchHarness(t, nil).start(64)
	h.write("home/code/.bashrc", "x")
	h.waitFor("home/code/.bashrc")
	link := filepath.Join(h.root, "link")
	if err := os.Link(filepath.Join(h.home, ".bashrc"), link); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(link, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("evil\n"); err != nil {
		t.Fatal(err)
	}
	h.waitFor("home/code/.bashrc")
}

// TestUserFileWatcherBurst checks a burst of unrelated events does not
// drop the write that follows it.
// The events are queued before the reader starts, and its channel holds
// one: the reader must wait for the handler, not drop.
func TestUserFileWatcherBurst(t *testing.T) {
	h := newWatchHarness(t, nil)
	for i := range 300 {
		h.write(fmt.Sprintf("home/code/a%d", i), "x")
	}
	h.write("home/code/.bashrc", "x")
	h.start(1).waitFor("home/code/.bashrc")
}

// TestUserFileWatcherCrontabDirCreated checks a crontab written in a
// crontabs directory created after the mark pass.
func TestUserFileWatcherCrontabDirCreated(t *testing.T) {
	h := newWatchHarness(t, nil).start(64)
	if err := os.MkdirAll(filepath.Join(h.root, "var", "spool", "cron", "crontabs"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.write("var/spool/cron/crontabs/code", "* * * * * true\n")
	h.waitFor("var/spool/cron/crontabs/code")
}

// containerCgroups points procCgroupFmt at a temp dir where each of pids
// runs in container c's cgroup.
func containerCgroups(t *testing.T, pids ...int) {
	t.Helper()
	dir := t.TempDir()
	orig := procCgroupFmt
	procCgroupFmt = dir + "/%d"
	t.Cleanup(func() { procCgroupFmt = orig })
	for _, pid := range pids {
		if err := os.WriteFile(fmt.Sprintf(procCgroupFmt, pid), []byte("0::/lxc.payload.c/x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUserFileWatcherGracePeriod(t *testing.T) {
	root := t.TempDir()
	orig := procRootFmt
	procRootFmt = root + "/%d"
	t.Cleanup(func() { procRootFmt = orig })
	if err := os.MkdirAll(filepath.Join(root, "1", "home", "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "1", "home", "code", ".bashrc"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	containerCgroups(t, 1, 2, 3, 4)
	var threats int
	w := NewUserFileWatcher("c", "", "code", nil, func(ThreatEvent) { threats++ }, nil)
	st := newUserWatchState()
	st.pid, st.dirs["k"], st.graceUntil = 1, "home/code", time.Now().Add(time.Minute)
	w.handle(-1, fanFidEvent{mask: unix.FAN_CLOSE_WRITE, pid: 1, dir: "k", name: ".bashrc"}, st)
	if threats != 0 {
		t.Errorf("threat raised in the grace period")
	}
	st.graceUntil = time.Time{}
	w.handle(-1, fanFidEvent{mask: unix.FAN_CLOSE_WRITE, pid: 2, dir: "k", name: ".bashrc"}, st)
	w.handle(-1, fanFidEvent{mask: unix.FAN_CREATE, pid: 3, dir: "k", name: ".bashrc"}, st)
	if threats != 1 {
		t.Errorf("threats = %d, want 1 (close-write only, not the create of a regular file)", threats)
	}
	// fanotify merges the create and the close-write of a new file. The
	// create re-marks; with no fanotify fd here, that clears st.dirs.
	st.dirs["k"] = "home/code"
	w.handle(-1, fanFidEvent{mask: unix.FAN_CREATE | unix.FAN_CLOSE_WRITE, pid: 4, dir: "k", name: ".bashrc"}, st)
	if threats != 2 {
		t.Errorf("threats = %d, want 2 (merged create and close-write)", threats)
	}
}

func TestUserFileWatcherRefire(t *testing.T) {
	containerCgroups(t, 7, 8)
	var threats int
	w := NewUserFileWatcher("c", "", "code", nil, func(ThreatEvent) { threats++ }, nil)
	st := newUserWatchState()
	st.pid, st.files["f"] = 1, "home/code/.bashrc"
	for range 5 {
		w.handle(-1, fanFidEvent{mask: unix.FAN_MODIFY, pid: 7, obj: "f"}, st)
	}
	if threats != 1 {
		t.Errorf("threats = %d for 5 writes by one process, want 1", threats)
	}
	w.handle(-1, fanFidEvent{mask: unix.FAN_MODIFY, pid: 8, obj: "f"}, st)
	if threats != 2 {
		t.Errorf("threats = %d, want 2 (another process)", threats)
	}
}

func TestParseFidEventsTruncated(t *testing.T) {
	if evs := parseFidEvents([]byte{1, 2, 3}); len(evs) != 0 {
		t.Errorf("parseFidEvents(short) = %v", evs)
	}
	buf := make([]byte, 24)
	buf[0] = 200 // event_len past the buffer
	if evs := parseFidEvents(buf); len(evs) != 0 {
		t.Errorf("parseFidEvents(truncated) = %v", evs)
	}
}
