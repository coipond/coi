package session

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
)

type readyFake struct {
	container.ContainerManager
	readyAfter int // exec succeeds from this call on (0 = immediately)
	execs      int
	runs       int
	runErr     error
	stoppedFor int // Running reports false for this many calls (-1 = always)
}

func (f *readyFake) ExecCommand(string, container.ExecCommandOptions) (string, error) {
	f.execs++
	if f.execs > f.readyAfter {
		return "ready", nil
	}
	return "", errors.New("not yet")
}

func (f *readyFake) Running() (bool, error) {
	f.runs++
	if f.stoppedFor < 0 || f.runs <= f.stoppedFor {
		return false, f.runErr
	}
	return true, f.runErr
}

// logFake adds the start log of a container whose start aborted.
type logFake struct {
	readyFake
}

func (f *logFake) StartLogErrors(int) []string {
	return []string{`ERROR utils - safe_mount - No such file or directory - Failed to mount "disk.git--identity..."`}
}

// An already-usable container is confirmed with one exec and no status query.
func TestWaitForReady_ReadyIsOneCall(t *testing.T) {
	f := &readyFake{}
	if err := waitForReady(context.Background(), f, time.Second, time.Millisecond, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if f.execs != 1 || f.runs != 0 {
		t.Errorf("execs=%d runs=%d, want 1/0", f.execs, f.runs)
	}
}

// A container that becomes usable shortly is picked up on the next short poll.
func TestWaitForReady_PollsUntilReady(t *testing.T) {
	f := &readyFake{readyAfter: 3}
	start := time.Now()
	if err := waitForReady(context.Background(), f, 5*time.Second, 5*time.Millisecond, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if f.execs != 4 || time.Since(start) > time.Second {
		t.Errorf("execs=%d in %v", f.execs, time.Since(start))
	}
}

func TestWaitForReady_TimesOut(t *testing.T) {
	f := &readyFake{readyAfter: 1 << 30}
	err := waitForReady(context.Background(), f, 50*time.Millisecond, 5*time.Millisecond, func(string) {})
	if !errors.Is(err, ErrNotReady) {
		t.Errorf("want ErrNotReady, got %v", err)
	}
}

func TestWaitForReady_StatusErrorIsFatal(t *testing.T) {
	f := &readyFake{readyAfter: 1 << 30, runErr: errors.New("incus down")}
	err := waitForReady(context.Background(), f, time.Second, time.Millisecond, func(string) {})
	if err == nil || errors.Is(err, ErrNotReady) {
		t.Errorf("want status error, got %v", err)
	}
}

// A container that is not running is not slow to boot: its start failed. The
// wait ends after a few probes, not the whole window, and quotes the start log.
func TestWaitForReady_StoppedContainerFailsFast(t *testing.T) {
	f := &logFake{readyFake{readyAfter: 1 << 30, stoppedFor: -1}}
	start := time.Now()
	err := waitForReady(context.Background(), f, 30*time.Second, time.Millisecond, func(string) {})
	if !errors.Is(err, ErrStoppedDuringBoot) {
		t.Fatalf("want ErrStoppedDuringBoot, got %v", err)
	}
	if errors.Is(err, ErrNotReady) {
		t.Error("a stopped container is not a readiness timeout")
	}
	if !strings.Contains(err.Error(), "Failed to mount") {
		t.Errorf("error should quote the start log: %v", err)
	}
	if f.runs != stoppedConfirmations || time.Since(start) > 5*time.Second {
		t.Errorf("runs=%d in %v, want %d quick probes", f.runs, time.Since(start), stoppedConfirmations)
	}
}

// Without a readable start log the error still names the failure.
func TestWaitForReady_StoppedContainerWithoutLog(t *testing.T) {
	f := &readyFake{readyAfter: 1 << 30, stoppedFor: -1}
	err := waitForReady(context.Background(), f, 30*time.Second, time.Millisecond, func(string) {})
	if !errors.Is(err, ErrStoppedDuringBoot) || !strings.Contains(err.Error(), "--show-log") {
		t.Errorf("want ErrStoppedDuringBoot with a hint, got %v", err)
	}
}

// A single odd "not running" answer doesn't end the wait.
func TestWaitForReady_BriefNotRunningIsTolerated(t *testing.T) {
	f := &readyFake{readyAfter: 4, stoppedFor: stoppedConfirmations - 1}
	if err := waitForReady(context.Background(), f, 5*time.Second, time.Millisecond, func(string) {}); err != nil {
		t.Fatalf("container that recovers must be ready, got %v", err)
	}
}

// The readiness probe holds a systemd guest back until sysinit.target, i.e.
// until systemd-tmpfiles-setup has emptied /tmp, and passes at once without
// systemd. Run against a fake PID 1 name and a fake systemctl.
func TestReadyProbeScript(t *testing.T) {
	cases := []struct {
		name      string
		pid1      string
		systemctl bool
		sysinit   string // is-active sysinit.target answer
		state     string // is-system-running answer
		ready     bool
	}{
		{name: "no systemd", pid1: "bash", ready: true},
		{name: "no systemctl", pid1: "systemd", ready: true},
		{name: "early boot", pid1: "systemd", systemctl: true, sysinit: "inactive", state: "initializing", ready: false},
		{name: "tmpfiles running", pid1: "systemd", systemctl: true, sysinit: "activating", state: "starting", ready: false},
		{name: "manager not answering", pid1: "systemd", systemctl: true, sysinit: "inactive", state: "offline", ready: false},
		{name: "past sysinit", pid1: "systemd", systemctl: true, sysinit: "active", state: "starting", ready: true},
		{name: "booted", pid1: "systemd", systemctl: true, sysinit: "active", state: "running", ready: true},
		{name: "emergency mode", pid1: "systemd", systemctl: true, sysinit: "inactive", state: "maintenance", ready: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			comm := filepath.Join(dir, "comm")
			if err := os.WriteFile(comm, []byte(tc.pid1+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"bash", "cat", "grep"} {
				path, err := exec.LookPath(tool)
				if err != nil {
					t.Skipf("%s not found", tool)
				}
				if err := os.Symlink(path, filepath.Join(bin, tool)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.systemctl {
				fake := `#!/bin/bash
case "$1" in
is-active) [ "` + tc.sysinit + `" = active ] ;;
is-system-running) echo ` + tc.state + `; [ "` + tc.state + `" = running ] ;;
*) exit 1 ;;
esac
`
				if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fake), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.ReplaceAll(readyProbeScript, "/proc/1/comm", comm)
			cmd := exec.Command(filepath.Join(bin, "bash"), "-c", script)
			cmd.Env = []string{"PATH=" + bin}
			err := cmd.Run()
			if got := err == nil; got != tc.ready {
				t.Errorf("ready = %v (%v), want %v", got, err, tc.ready)
			}
		})
	}
}
