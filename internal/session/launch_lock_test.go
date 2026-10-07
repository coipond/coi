package session

import (
	"strings"
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
	release1, err := AcquireLaunchLock("/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan time.Time, 1)
	var waitedNote bool
	go func() {
		release2, err := AcquireLaunchLock("/ws/a", "", func(m string) { waitedNote = strings.Contains(m, "Waiting") })
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
	r1, err := AcquireLaunchLock("/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	done := make(chan error, 2)
	go func() {
		r, err := AcquireLaunchLock("/ws/b", "", nil)
		if err == nil {
			r()
		}
		done <- err
	}()
	go func() {
		r, err := AcquireLaunchLock("/ws/a", "named", nil)
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
	r1, err := AcquireLaunchLock("/ws/a", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r1()
	if _, err := AcquireLaunchLock("/ws/a", "", nil); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("want a timeout error, got %v", err)
	}
}
