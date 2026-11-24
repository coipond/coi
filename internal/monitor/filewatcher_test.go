package monitor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSensitiveFilesTable verifies the sensitiveFiles table is self-consistent:
// every entry has a non-empty rel path, at least one level set, and the correct
// category for its type.
func TestSensitiveFilesTable(t *testing.T) {
	for _, sf := range sensitiveFiles {
		if sf.rel == "" {
			t.Errorf("sensitiveFile with empty rel path")
		}
		if sf.openLevel == "" && sf.writeLevel == "" {
			t.Errorf("sensitiveFile %q has neither openLevel nor writeLevel set", sf.rel)
		}
		if sf.openLevel != "" && sf.openTitle == "" {
			t.Errorf("sensitiveFile %q has openLevel but no openTitle", sf.rel)
		}
		if sf.writeLevel != "" && sf.writeTitle == "" {
			t.Errorf("sensitiveFile %q has writeLevel but no writeTitle", sf.rel)
		}
		if sf.category == "" {
			t.Errorf("sensitiveFile %q has no category", sf.rel)
		}
	}
}

// TestSensitiveFilesThreatLevels checks specific files have the expected levels.
func TestSensitiveFilesThreatLevels(t *testing.T) {
	fileMap := make(map[string]*monitoredFile)
	for i := range sensitiveFiles {
		fileMap[sensitiveFiles[i].rel] = &sensitiveFiles[i]
	}

	cases := []struct {
		rel        string
		openLevel  ThreatLevel
		writeLevel ThreatLevel
	}{
		{"etc/shadow", ThreatLevelHigh, ThreatLevelCritical},
		{"etc/sudoers", "", ThreatLevelCritical},
		{"root/.ssh/authorized_keys", "", ThreatLevelCritical},
		{"etc/passwd", "", ThreatLevelHigh},
		{"etc/gshadow", ThreatLevelHigh, ThreatLevelHigh},
	}

	for _, tc := range cases {
		sf, ok := fileMap[tc.rel]
		if !ok {
			t.Errorf("expected %q in sensitiveFiles, not found", tc.rel)
			continue
		}
		if sf.openLevel != tc.openLevel {
			t.Errorf("%q openLevel: got %q, want %q", tc.rel, sf.openLevel, tc.openLevel)
		}
		if sf.writeLevel != tc.writeLevel {
			t.Errorf("%q writeLevel: got %q, want %q", tc.rel, sf.writeLevel, tc.writeLevel)
		}
	}
}

// TestMarkMaskOnlyFdEvents checks every mark mask holds only events that
// carry an fd: fanotify_mark refuses any other event with EINVAL in a group
// without FAN_REPORT_FID, so the file would never be watched.
func TestMarkMaskOnlyFdEvents(t *testing.T) {
	for i := range sensitiveFiles {
		sf := &sensitiveFiles[i]
		mask := sf.markMask()
		if extra := mask &^ (unix.FAN_OPEN | unix.FAN_CLOSE_WRITE); extra != 0 {
			t.Errorf("%q mark mask has events without an fd: %#x", sf.rel, extra)
		}
		if sf.openLevel != "" && mask&unix.FAN_OPEN == 0 {
			t.Errorf("%q has openLevel but no FAN_OPEN", sf.rel)
		}
		if sf.writeLevel != "" && mask&unix.FAN_CLOSE_WRITE == 0 {
			t.Errorf("%q has writeLevel but no FAN_CLOSE_WRITE", sf.rel)
		}
	}
}

// TestSensitiveFileThreatEvidence verifies that Evidence.String() formats the
// SensitiveFile evidence correctly for deduplication.
func TestSensitiveFileThreatEvidence(t *testing.T) {
	ev := Evidence{
		SensitiveFile: &SensitiveFileThreat{
			Path:   "etc/shadow",
			Access: "read",
			Pid:    12345,
		},
	}
	got := ev.String()
	want := "file:etc/shadow:read"
	if got != want {
		t.Errorf("Evidence.String() = %q, want %q", got, want)
	}
}

// TestSensitiveFileThreatEvidenceWrite verifies write access formats correctly.
func TestSensitiveFileThreatEvidenceWrite(t *testing.T) {
	ev := Evidence{
		SensitiveFile: &SensitiveFileThreat{
			Path:   "etc/sudoers",
			Access: "write",
			Pid:    99,
		},
	}
	got := ev.String()
	want := "file:etc/sudoers:write"
	if got != want {
		t.Errorf("Evidence.String() = %q, want %q", got, want)
	}
}

// TestFileWatcherFireEmitsThreatEvent verifies that FileWatcher.fire() constructs
// a properly-formed ThreatEvent and delivers it via onThreat.
func TestFileWatcherFireEmitsThreatEvent(t *testing.T) {
	var got ThreatEvent
	w := NewFileWatcher("test-container", func(e ThreatEvent) { got = e }, nil)

	w.fire(ThreatLevelHigh, "credential_access",
		"Shadow read", "A process opened /etc/shadow",
		"etc/shadow", "read", 42)

	if got.Level != ThreatLevelHigh {
		t.Errorf("level: got %q, want %q", got.Level, ThreatLevelHigh)
	}
	if got.Category != "credential_access" {
		t.Errorf("category: got %q", got.Category)
	}
	if got.Title != "Shadow read" {
		t.Errorf("title: got %q", got.Title)
	}
	if got.Evidence.SensitiveFile == nil {
		t.Fatal("Evidence.SensitiveFile is nil")
	}
	sf := got.Evidence.SensitiveFile
	if sf.Path != "etc/shadow" {
		t.Errorf("path: got %q", sf.Path)
	}
	if sf.Access != "read" {
		t.Errorf("access: got %q", sf.Access)
	}
	if sf.Pid != 42 {
		t.Errorf("pid: got %d", sf.Pid)
	}
	if got.ID == "" {
		t.Error("ID should not be empty")
	}
	if got.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

// TestFileWatcherFireNilCallback verifies fire() is a no-op when onThreat is nil.
func TestFileWatcherFireNilCallback(t *testing.T) {
	w := NewFileWatcher("test-container", nil, nil)
	// Must not panic.
	w.fire(ThreatLevelHigh, "credential_access", "title", "desc", "etc/shadow", "read", 1)
}

// fakeProcRoot points procRootPattern at a temp dir and returns the root of
// pid 1 in it.
func fakeProcRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := procRootPattern
	procRootPattern = dir + "/%d"
	t.Cleanup(func() { procRootPattern = old })
	root := filepath.Join(dir, "1")
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// fidGroup returns a fanotify group an unprivileged process may create.
func fidGroup(t *testing.T) int {
	t.Helper()
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_REPORT_FID, unix.O_RDONLY)
	if err != nil {
		t.Skipf("unprivileged fanotify unavailable: %v", err)
	}
	t.Cleanup(func() { unix.Close(ifd) })
	return ifd
}

func inodeOf(t *testing.T, path string) inodeKey {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return inodeKey{dev: st.Dev, ino: st.Ino}
}

// TestMarkReplacesInodeMap checks a mark pass drops a moved file's inode:
// without FAN_REPORT_FID the watcher is not told about the move, and a merged
// map would keep flagging the file under its old name.
func TestMarkReplacesInodeMap(t *testing.T) {
	root := fakeProcRoot(t)
	ifd := fidGroup(t)
	sudoers := filepath.Join(root, "etc", "sudoers")
	if err := os.WriteFile(sudoers, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := inodeOf(t, sudoers)

	w := NewFileWatcher("test-container", nil, nil)
	st := watchState{}
	w.mark(ifd, 1, &st)
	if st.inodes[old].file == nil || st.inodes[old].file.rel != "etc/sudoers" {
		t.Fatalf("first pass did not mark etc/sudoers: %v", st.inodes)
	}
	grace := st.graceUntil
	if grace.IsZero() {
		t.Fatal("first pass did not start the grace period")
	}

	if err := os.Rename(sudoers, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sudoers, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mark(ifd, 1, &st)
	if _, ok := st.inodes[old]; ok {
		t.Error("the moved file's inode is still in the map")
	}
	if st.inodes[inodeOf(t, sudoers)].file == nil {
		t.Error("the new etc/sudoers is not in the map")
	}
	if !st.graceUntil.Equal(grace) {
		t.Error("a pass with the same PID restarted the grace period")
	}
}

// TestMarkReportsNoFileMarked checks a pass that marks nothing (e.g. coi has
// CAP_SYS_ADMIN but cannot reach /proc/<pid>/root) is reported, once.
func TestMarkReportsNoFileMarked(t *testing.T) {
	fakeProcRoot(t)
	ifd := fidGroup(t)
	var errs []error
	w := NewFileWatcher("test-container", nil, func(err error) { errs = append(errs, err) })
	st := watchState{}
	w.mark(ifd, 1, &st)
	w.mark(ifd, 1, &st)
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "CAP_SYS_PTRACE") {
		t.Errorf("error does not name the missing capabilities: %v", errs[0])
	}
}

// TestHandleIgnoresAuthHelperReads checks a read of /etc/shadow by sudo, su
// or unix_chkpwd raises nothing, while a read by any other program, by
// sudoedit, by an unreadable process, a read of another file by sudo and a
// write by sudo do.
func TestHandleIgnoresAuthHelperReads(t *testing.T) {
	dir := t.TempDir()
	old := procPidPattern
	procPidPattern = dir + "/%d"
	t.Cleanup(func() { procPidPattern = old })
	procs := map[int]struct{ exe, cmdline string }{
		10: {"/usr/bin/sudo", "sudo\x00true"},
		11: {"/usr/lib/cargo/bin/sudo", "sudo\x00-u\x00root\x00grep\x00-e\x00x\x00f"},
		12: {"/usr/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd\x00code\x00chkexpiry"},
		13: {"/usr/bin/su", "su\x00-"},
		14: {"/usr/lib/cargo/bin/sudo", "sudoedit\x00/etc/shadow"},
		15: {"/usr/bin/sudo", "sudo\x00-u\x00root\x00-e\x00/etc/shadow"},
		20: {"/usr/bin/cat", "cat\x00/etc/shadow"},
		21: {"/tmp/sudo", "/tmp/sudo\x00true"},
		22: {"/usr/bin/sudo", ""},
	}
	for pid, p := range procs {
		pdir := filepath.Join(dir, strconv.Itoa(pid))
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p.exe, filepath.Join(pdir, "exe")); err != nil {
			t.Fatal(err)
		}
		if p.cmdline == "" {
			continue // no cmdline: the process is gone
		}
		if err := os.WriteFile(filepath.Join(pdir, "cmdline"), []byte(p.cmdline+"\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]*monitoredFile{}
	for i := range sensitiveFiles {
		files[sensitiveFiles[i].rel] = &sensitiveFiles[i]
	}

	var got []ThreatEvent
	w := NewFileWatcher("test-container", func(e ThreatEvent) { got = append(got, e) }, nil)
	for _, tc := range []struct {
		pid  int
		rel  string
		mask uint64
		want bool
	}{
		{10, "etc/shadow", unix.FAN_OPEN, false},
		{11, "etc/shadow", unix.FAN_OPEN, false},
		{12, "etc/shadow", unix.FAN_OPEN, false},
		{13, "etc/shadow", unix.FAN_OPEN, false},
		{14, "etc/shadow", unix.FAN_OPEN, true},
		{15, "etc/shadow", unix.FAN_OPEN, true},
		{14, "root/.ssh/id_rsa", unix.FAN_OPEN, true},
		{10, "root/.ssh/id_rsa", unix.FAN_OPEN, true},
		{20, "etc/shadow", unix.FAN_OPEN, true},
		{21, "etc/shadow", unix.FAN_OPEN, true},
		{22, "etc/shadow", unix.FAN_OPEN, true},
		{30, "etc/shadow", unix.FAN_OPEN, true},
		{10, "etc/shadow", unix.FAN_CLOSE_WRITE, true},
	} {
		got = nil
		w.handle(inodeEntry{file: files[tc.rel]}, tc.mask, tc.pid)
		if (len(got) > 0) != tc.want {
			t.Errorf("pid %d (%q) %s mask %#x: threats %v, want threat %v",
				tc.pid, procs[tc.pid].cmdline, tc.rel, tc.mask, got, tc.want)
		}
	}
}

// TestSudoEdits checks edit mode is found among sudo's own options only.
func TestSudoEdits(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"sudoedit", "/etc/shadow"}, true},
		{[]string{"/usr/bin/sudoedit", "f"}, true},
		{[]string{"sudo", "-e", "f"}, true},
		{[]string{"sudo", "--edit", "f"}, true},
		{[]string{"sudo", "-nE", "-e", "f"}, true},
		{[]string{"sudo", "-ne", "f"}, true},
		{[]string{"sudo", "-u", "root", "-e", "f"}, true},
		{[]string{"sudo", "-uroot", "-e", "f"}, true},
		{[]string{"sudo", "--user", "root", "--edit", "f"}, true},
		{[]string{"sudo", "--ed", "/etc/shadow"}, true},
		{[]string{"sudo", "--edi", "/etc/shadow"}, true},
		{[]string{"sudo", "--us", "root", "-e", "/etc/shadow"}, true},
		{[]string{"sudo", "--user=root", "-e", "f"}, true},
		{[]string{"sudo", "--bogus", "f"}, true},
		{[]string{"sudo", "--re", "true"}, true},
		{[]string{"sudo", "--us", "root", "true"}, false},
		{[]string{"sudo", "--user=e", "true"}, false},
		{[]string{"sudo", "--preserve-env=PATH", "true"}, false},
		{[]string{"sudo", "--no-update", "true"}, false},
		{[]string{"sudo", "--no-u", "true"}, false},
		{[]string{"sudo", "--n", "true"}, true},
		{[]string{"sudo", "--non-interactive", "true"}, false},
		{[]string{"sudo", "--auth-type", "e", "true"}, false},
		{[]string{"sudo", "--login-class", "e", "true"}, false},
		{[]string{"sudo", "-a", "x", "-e", "f"}, true},
		{[]string{"sudo", "-c", "x", "-e", "f"}, true},
		{[]string{"sudo", "-h", "-e", "f"}, true},
		{[]string{"sudo", "-hhost", "true"}, false},
		{[]string{"sudo", "-hexample", "true"}, false},
		{[]string{"sudo", "-N", "true"}, false},
		{[]string{"sudo", "true"}, false},
		{[]string{"sudo", "-E", "env"}, false},
		{[]string{"sudo", "-u", "e", "true"}, false},
		{[]string{"sudo", "grep", "-e", "x", "f"}, false},
		{[]string{"sudo", "--", "-e"}, false},
		{[]string{"su", "-"}, false},
		{nil, false},
	} {
		if got := sudoEdits(tc.argv); got != tc.want {
			t.Errorf("sudoEdits(%q) = %v, want %v", tc.argv, got, tc.want)
		}
	}
}
