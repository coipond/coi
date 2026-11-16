package monitor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseAuthLogLine_FailedPassword(t *testing.T) {
	line := "Jun  5 12:00:00 host sshd[1234]: Failed password for invalid user attacker from 1.2.3.4 port 22222 ssh2"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelWarning {
		t.Errorf("level = %s, want warning", ev.Level)
	}
	if ev.Category != "auth" {
		t.Errorf("category = %s, want auth", ev.Category)
	}
	if ev.Evidence.AuthLog == nil {
		t.Fatal("AuthLog evidence is nil")
	}
	if ev.Evidence.AuthLog.Pattern != "ssh_failed_password" {
		t.Errorf("pattern = %s, want ssh_failed_password", ev.Evidence.AuthLog.Pattern)
	}
	if ev.Evidence.AuthLog.LogFile != "auth.log" {
		t.Errorf("log_file = %s, want auth.log", ev.Evidence.AuthLog.LogFile)
	}
}

func TestParseAuthLogLine_InvalidUser(t *testing.T) {
	line := "Jun  5 12:00:01 host sshd[1234]: Invalid user foo from 10.0.0.1 port 54321"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Evidence.AuthLog.Pattern != "ssh_invalid_user" {
		t.Errorf("pattern = %s, want ssh_invalid_user", ev.Evidence.AuthLog.Pattern)
	}
	if ev.Level != ThreatLevelWarning {
		t.Errorf("level = %s, want warning", ev.Level)
	}
}

func TestParseAuthLogLine_PamAuthFailure(t *testing.T) {
	line := "Jun  5 12:00:02 host pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Evidence.AuthLog.Pattern != "pam_auth_failure" {
		t.Errorf("pattern = %s, want pam_auth_failure", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_SudoNotAllowed(t *testing.T) {
	line := "Jun  5 12:00:03 host sudo: user : command not allowed ; TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelHigh {
		t.Errorf("level = %s, want high", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "sudo_not_allowed" {
		t.Errorf("pattern = %s, want sudo_not_allowed", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_SudoNotInSudoers(t *testing.T) {
	line := "Jun  5 12:00:04 host sudo: hacker is not in the sudoers file. This incident will be reported."
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelHigh {
		t.Errorf("level = %s, want high", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "sudo_not_in_sudoers" {
		t.Errorf("pattern = %s, want sudo_not_in_sudoers", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_SuFailed(t *testing.T) {
	line := "Jun  5 12:00:05 host su[5678]: FAILED su for root by user"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelHigh {
		t.Errorf("level = %s, want high", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "su_failed" {
		t.Errorf("pattern = %s, want su_failed", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_RootSession(t *testing.T) {
	line := "Jun  5 12:00:06 host su[5678]: pam_unix(su:session): session opened for user root by user(uid=1000)"
	ev := parseAuthLogLine("auth.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelWarning {
		t.Errorf("level = %s, want warning", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "root_session" {
		t.Errorf("pattern = %s, want root_session", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_Benign(t *testing.T) {
	benignLines := []string{
		"Jun  5 12:00:07 host sshd[1234]: Accepted publickey for code from 10.0.0.1 port 54321 ssh2",
		"Jun  5 12:00:08 host CRON[9876]: pam_unix(cron:session): session opened for user code by (uid=0)",
		"Jun  5 12:00:09 host systemd-logind[1]: New session 1 of user code.",
		"",
		"some random log line with no keywords",
	}
	for _, line := range benignLines {
		ev := parseAuthLogLine("auth.log", line)
		if ev != nil {
			t.Errorf("line %q: expected nil, got threat %s (pattern=%s)", line, ev.Title, ev.Evidence.AuthLog.Pattern)
		}
	}
}

func TestParseAuthLogLine_LongLineTruncated(t *testing.T) {
	long := "Failed password for "
	for len(long) < 350 {
		long += "x"
	}
	ev := parseAuthLogLine("auth.log", long)
	if ev == nil {
		t.Fatal("expected threat event for long line, got nil")
	}
	if len(ev.Evidence.AuthLog.Line) > 305 {
		t.Errorf("line not truncated: len=%d", len(ev.Evidence.AuthLog.Line))
	}
}

func TestEvidenceString_AuthLog(t *testing.T) {
	e := Evidence{AuthLog: &AuthLogThreat{LogFile: "auth.log", Pattern: "ssh_failed_password"}}
	s := e.String()
	if s != "auth:auth.log:ssh_failed_password" {
		t.Errorf("Evidence.String() = %q, want auth:auth.log:ssh_failed_password", s)
	}
}

func TestParseAuthLogLine_AuditdAuthFailure(t *testing.T) {
	line := `type=USER_AUTH msg=audit(1234567890.123:456): pid=1234 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct="user" exe="/usr/bin/sshd" res=failed'`
	ev := parseAuthLogLine("audit.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelHigh {
		t.Errorf("level = %s, want high", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "auditd_auth_failure" {
		t.Errorf("pattern = %s, want auditd_auth_failure", ev.Evidence.AuthLog.Pattern)
	}
	if ev.Evidence.AuthLog.LogFile != "audit.log" {
		t.Errorf("log_file = %s, want audit.log", ev.Evidence.AuthLog.LogFile)
	}
}

func TestParseAuthLogLine_AuditdUserCmdFailed(t *testing.T) {
	line := `type=USER_CMD msg=audit(1234567890.456:789): pid=5678 uid=1000 auid=1000 ses=1 msg='cwd="/home/user" cmd="bash" terminal=pts/0 res=failed'`
	ev := parseAuthLogLine("audit.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelHigh {
		t.Errorf("level = %s, want high", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "auditd_user_cmd_failed" {
		t.Errorf("pattern = %s, want auditd_user_cmd_failed", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_AuditdLoginFailure(t *testing.T) {
	line := `type=USER_LOGIN msg=audit(1234567890.789:101): pid=1234 uid=0 auid=999 ses=1 msg='op=login id=0 exe="/usr/bin/su" res=failed'`
	ev := parseAuthLogLine("audit.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelWarning {
		t.Errorf("level = %s, want warning", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "auditd_login_failure" {
		t.Errorf("pattern = %s, want auditd_login_failure", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_AuditdAcctFailure(t *testing.T) {
	line := `type=USER_ACCT msg=audit(1234567890.999:202): pid=9999 uid=0 auid=1000 ses=2 msg='op=PAM:accounting acct="hacker" exe="/usr/bin/sudo" res=failed'`
	ev := parseAuthLogLine("audit.log", line)
	if ev == nil {
		t.Fatal("expected threat event, got nil")
	}
	if ev.Level != ThreatLevelWarning {
		t.Errorf("level = %s, want warning", ev.Level)
	}
	if ev.Evidence.AuthLog.Pattern != "auditd_acct_failure" {
		t.Errorf("pattern = %s, want auditd_acct_failure", ev.Evidence.AuthLog.Pattern)
	}
}

func TestParseAuthLogLine_AuditdSuccessNotFlagged(t *testing.T) {
	// Successful auditd events should not trigger alerts
	benign := []string{
		`type=USER_AUTH msg=audit(1234567890.123:456): pid=1234 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct="user" res=success'`,
		`type=USER_CMD msg=audit(1234567890.456:789): pid=5678 uid=0 auid=0 ses=1 msg='cwd="/root" cmd="ls" res=success'`,
		`type=SYSCALL msg=audit(1234567890.789:101): arch=c000003e syscall=59 success=yes`,
	}
	for _, line := range benign {
		ev := parseAuthLogLine("audit.log", line)
		if ev != nil {
			t.Errorf("line %q: expected nil, got threat pattern=%s", line, ev.Evidence.AuthLog.Pattern)
		}
	}
}

func TestLogCandidatesIncludesAuditLog(t *testing.T) {
	found := false
	for _, c := range logCandidates {
		if c == "var/log/audit/audit.log" {
			found = true
			break
		}
	}
	if !found {
		t.Error("logCandidates does not include var/log/audit/audit.log")
	}
}

func TestReadFileChunk_ReadsFromBeginning(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.log")
	content := "line one\nline two\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	data, base, inode, err := readFileChunk(f, logState{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != content {
		t.Errorf("want %q got %q", content, string(data))
	}
	if base != 0 {
		t.Errorf("want base 0 got %d", base)
	}
	if inode == 0 {
		t.Error("want non-zero inode")
	}
}

func TestReadFileChunk_RespectsOffset(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.log")
	first := "already read\n"
	second := "new line\n"
	if err := os.WriteFile(f, []byte(first+second), 0o644); err != nil {
		t.Fatal(err)
	}

	data, base, _, err := readFileChunk(f, logState{offset: int64(len(first))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != second {
		t.Errorf("want %q got %q", second, string(data))
	}
	if base != int64(len(first)) {
		t.Errorf("want base %d got %d", len(first), base)
	}
}

func TestReadFileChunk_NoNewContent(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.log")
	content := "existing\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	data, base, _, err := readFileChunk(f, logState{offset: int64(len(content))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("want nil data when no new content, got %q", string(data))
	}
	if base != int64(len(content)) {
		t.Errorf("offset should not change, want %d got %d", len(content), base)
	}
}

func TestReadFileChunk_FileNotFound(t *testing.T) {
	_, _, _, err := readFileChunk("/nonexistent/path/file.log", logState{})
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestReadFileChunk_RotationByTruncation(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.log")
	original := "old content\n"
	if err := os.WriteFile(f, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	// Simulate rotation: overwrite with shorter content so size < offset.
	rotated := "new\n"
	if err := os.WriteFile(f, []byte(rotated), 0o644); err != nil {
		t.Fatal(err)
	}

	// State has offset past end of new file — should reset to 0.
	data, base, _, err := readFileChunk(f, logState{offset: int64(len(original))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != 0 {
		t.Errorf("want base 0 after rotation, got %d", base)
	}
	if string(data) != rotated {
		t.Errorf("want rotated content %q got %q", rotated, string(data))
	}
}

func TestReadFileChunk_RotationByInodeChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.log")
	original := "line one\nline two\n"
	if err := os.WriteFile(f, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	// Read first to capture the real inode.
	_, _, inode, err := readFileChunk(f, logState{})
	if err != nil {
		t.Fatalf("unexpected error on first read: %v", err)
	}

	// Simulate log rotation: remove and recreate (new inode).
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	rotated := "fresh log\n"
	if err := os.WriteFile(f, []byte(rotated), 0o644); err != nil {
		t.Fatal(err)
	}

	// State has old inode and offset at end of original file.
	data, base, _, err := readFileChunk(f, logState{offset: int64(len(original)), inode: inode})
	if err != nil {
		t.Fatalf("unexpected error after rotation: %v", err)
	}
	if base != 0 {
		t.Errorf("want base 0 after inode change, got %d", base)
	}
	if string(data) != rotated {
		t.Errorf("want rotated content %q got %q", rotated, string(data))
	}
}

// TestReadFileChunk_RotationMissedWhenInodeUnknown documents the hazard the
// inode-preservation fix in pollFile guards against: when the stored inode is 0
// (unknown — e.g. a prior read went through the incus fallback, which has no
// file descriptor), readFileChunk CANNOT detect a rotation whose replacement
// file is >= the old offset, so the post-rotation content is silently skipped.
// This is exactly why pollFile must preserve the last-known inode across
// fallback reads instead of clobbering it with 0.
func TestReadFileChunk_RotationMissedWhenInodeUnknown(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.log")
	original := "line one is here\n" // 17 bytes
	if err := os.WriteFile(f, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	// Rotate into a fresh file (new inode) whose size == the old offset.
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	rotated := "line two is here\n" // also 17 bytes → size == offset
	if err := os.WriteFile(f, []byte(rotated), 0o644); err != nil {
		t.Fatal(err)
	}

	// inode: 0 disables the inode check; size == offset defeats the size check.
	data, base, _, err := readFileChunk(f, logState{offset: int64(len(original)), inode: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if base != int64(len(original)) || len(data) != 0 {
		t.Fatalf("hazard characterization changed: with a lost inode the rotation "+
			"should be missed (base=%d, len(data)=%d)", base, len(data))
	}
}

// TestPollFile_DetectsRotationViaProcRoot exercises the real pollFile host-side
// path (reading /proc/<pid>/root/<rel>) across a log rotation, which is what the
// test_log_rotation_handled integration test relies on. With the inode
// preserved (as the fix guarantees after any fallback blip), a rotation into a
// same-size file is still detected.
func TestPollFile_DetectsRotationViaProcRoot(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	rel := strings.TrimPrefix(logPath, "/") // /proc/<pid>/root/<rel> == logPath

	first := "Jun  5 12:00:00 coi sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2\n"
	if err := os.WriteFile(logPath, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}

	var threats []ThreatEvent
	lw := NewLogWatcher("unused", func(e ThreatEvent) { threats = append(threats, e) }, nil)
	states := map[string]logState{}
	pid := os.Getpid()

	lw.pollFile(context.Background(), rel, states, pid)
	if len(threats) != 1 {
		t.Fatalf("want 1 threat before rotation, got %d", len(threats))
	}
	if states[rel].inode == 0 {
		t.Fatal("want a non-zero inode recorded after host-side read")
	}

	// Simulate returning from a transient fallback blip: the fix preserves the
	// last-known inode, so mark the state accordingly (inode intact).
	st := states[rel]
	st.usingFallback = true
	states[rel] = st

	// Rotate the way logrotate does: move the old file aside (keeping its inode
	// allocated) then create a fresh file — this GUARANTEES a new inode. A plain
	// remove+recreate can reuse the just-freed inode, which for a same-length
	// file is genuinely indistinguishable from "no change" (same inode, same
	// size) and is not what this test is about.
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	second := "Jun  5 12:00:01 coi sshd[2]: Failed password for a from 2.2.2.2 port 22 ssh2\n"
	if err := os.WriteFile(logPath, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}

	lw.pollFile(context.Background(), rel, states, pid)
	found := false
	for _, e := range threats {
		if strings.Contains(e.Description, "2.2.2.2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-rotation attacker line not detected; threats=%d", len(threats))
	}
}

// signalAllThreads sends SIGURG (handled and ignored by the Go runtime) to
// every thread of this process, so a thread blocked in poll(2) gets EINTR.
func signalAllThreads(t *testing.T) {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			continue
		}
		_ = unix.Tgkill(os.Getpid(), tid, unix.SIGURG)
	}
}

// TestInotifyReader_SurvivesSignals guards against a signal (SIGCHLD from the
// monitor's incus subprocesses) interrupting poll(2): poll never restarts, so
// an EINTR treated as fatal closed the channel and ended LogWatcher.Run for
// the rest of the session.
func TestInotifyReader_SurvivesSignals(t *testing.T) {
	ifd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.InotifyAddWatch(ifd, logPath, unix.IN_MODIFY); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := inotifyReader(ctx, ifd)
	t.Cleanup(func() {
		// Close ifd only after the reader stops, so it can't read the next
		// test's inotify fd once the number is reused.
		cancel()
		for range events {
		}
		unix.Close(ifd)
	})
	for range 50 {
		signalAllThreads(t)
		time.Sleep(10 * time.Millisecond)
	}

	if err := os.WriteFile(logPath, []byte("line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case ev, ok := <-events:
		if !ok {
			t.Fatal("inotify reader stopped after a signal interrupted poll")
		}
		if ev.mask&unix.IN_MODIFY == 0 {
			t.Fatalf("want IN_MODIFY, got mask %#x", ev.mask)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no inotify event after the write")
	}
}

// TestLogWatcherRun_FallsBackToPollingWhenReaderStops checks that Run keeps
// watching by polling, and reports it, when the inotify reader stops while the
// session is still live.
func TestLogWatcherRun_FallsBackToPollingWhenReaderStops(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	// incus info reports this process, so /proc/<pid>/root/<rel> is logPath.
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"PID: " + strconv.Itoa(os.Getpid()) + "\"\n"
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldCandidates, oldInterval, oldReader := logCandidates, logPollInterval, newInotifyReader
	t.Cleanup(func() {
		logCandidates, logPollInterval, newInotifyReader = oldCandidates, oldInterval, oldReader
	})
	logCandidates = []string{strings.TrimPrefix(logPath, "/")}
	logPollInterval = 50 * time.Millisecond
	newInotifyReader = func(context.Context, int) <-chan inotifyRawEvent {
		ch := make(chan inotifyRawEvent)
		close(ch)
		return ch
	}

	threats := make(chan ThreatEvent, 4)
	errs := make(chan error, 4)
	lw := NewLogWatcher("coi-logwatcher-fallback-test",
		func(e ThreatEvent) { threats <- e },
		func(err error) {
			select {
			case errs <- err:
			default:
			}
		})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { lw.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), "falling back to") {
			t.Fatalf("want the fallback message, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no fallback message after the reader stopped")
	}

	line := "Jun  5 12:00:00 coi sshd[1]: Failed password for a from 1.1.1.1 port 22 ssh2\n"
	if err := os.WriteFile(logPath, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-threats:
		if e.Evidence.AuthLog == nil || e.Evidence.AuthLog.Pattern != "ssh_failed_password" {
			t.Fatalf("want ssh_failed_password, got %+v", e.Evidence)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("line written after the fallback was not detected")
	}
}
