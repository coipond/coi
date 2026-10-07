package session

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func useTempLaunchLocks(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	prevDir, prevTimeout := launchLocksDir, launchLockTimeout
	launchLocksDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { launchLocksDir, launchLockTimeout = prevDir, prevTimeout })
}

// A second launch of the same workspace waits until the first releases.
func TestLaunchLock_SerializesSameIdentity(t *testing.T) {
	useTempLaunchLocks(t)
	release1, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan time.Time, 1)
	var waitedNote bool
	go func() {
		release2, err := AcquireLaunchLock(context.Background(), "/ws/a", "", func(m string) { waitedNote = strings.Contains(m, "Waiting") })
		if err != nil {
			t.Error(err)
			return
		}
		got <- time.Now()
		release2()
	}()

	time.Sleep(200 * time.Millisecond)
	select {
	case <-got:
		t.Fatal("second launch must wait while the first holds the lock")
	default:
	}
	released := time.Now()
	release1()
	release1() // idempotent
	select {
	case at := <-got:
		if at.Before(released) {
			t.Error("acquired before release")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second launch never got the lock after release")
	}
	if !waitedNote {
		t.Error("a waiting launch should say so")
	}
}

// Different workspaces (or session names) never contend.
func TestLaunchLock_IndependentIdentities(t *testing.T) {
	useTempLaunchLocks(t)
	r1, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	done := make(chan error, 2)
	go func() {
		r, err := AcquireLaunchLock(context.Background(), "/ws/b", "", nil)
		if err == nil {
			r()
		}
		done <- err
	}()
	go func() {
		r, err := AcquireLaunchLock(context.Background(), "/ws/a", "named", nil)
		if err == nil {
			r()
		}
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("unrelated identities must not wait on each other")
		}
	}
}

// A launch gives up with a clear error rather than waiting forever.
func TestLaunchLock_Timeout(t *testing.T) {
	useTempLaunchLocks(t)
	launchLockTimeout = 150 * time.Millisecond
	r1, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	if _, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("want a timeout error, got %v", err)
	}
}

// Cancelling the launch (context) stops the wait at once instead of waiting
// out the timeout and then launching anyway.
func TestLaunchLock_ContextCancelStopsWait(t *testing.T) {
	useTempLaunchLocks(t)
	r1, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	if _, err := AcquireLaunchLock(ctx, "/ws/a", "", nil); err == nil {
		t.Fatal("a cancelled wait must fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("cancel must stop the wait promptly")
	}
}

// Ctrl-C (SIGINT) while waiting aborts the wait.
func TestLaunchLock_InterruptStopsWait(t *testing.T) {
	useTempLaunchLocks(t)
	r1, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	// Keep the test process alive on SIGINT: with a channel registered, Go
	// delivers the signal to channels instead of terminating.
	keep := make(chan os.Signal, 1)
	signal.Notify(keep, os.Interrupt)
	defer signal.Stop(keep)

	errc := make(chan error, 1)
	go func() {
		_, err := AcquireLaunchLock(context.Background(), "/ws/a", "", nil)
		errc <- err
	}()
	time.Sleep(200 * time.Millisecond) // let it start waiting
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Errorf("want an interrupted error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGINT must stop the wait")
	}
}
