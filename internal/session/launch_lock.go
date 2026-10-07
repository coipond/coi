package session

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Launch lock.
//
// A launch picks its slot by listing the identity's containers and taking the
// first free one, then creates (or restarts) coi-<hash>-<slot>. Without
// coordination, two launches of the same workspace (or session_name) at once
// pick the same slot: one fails with "already exists", an ephemeral run can
// delete the other's container while it is still being set up ("Removing
// existing container..."), and two persistent runs can restart and reconcile
// the same container. The launch lock serialises that window per identity —
// from slot selection until the chosen container is up — so the next launch
// sees the slot as taken and picks another. Containers of different
// workspaces never contend.

// launchLockTimeout bounds how long a launch waits for another launch of the
// same identity. The window it guards normally lasts seconds; it can include
// an image auto-build, hence the generous cap.
var launchLockTimeout = 10 * time.Minute

// launchLockPoll is how often a waiting launch retries the lock.
const launchLockPoll = 50 * time.Millisecond

// launchLocksDir is where the per-identity lock files live (a variable so
// tests can point it at a temp dir).
var launchLocksDir = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".coi", "locks"), nil
}

// AcquireLaunchLock takes the launch lock for the workspace/session_name
// identity, waiting up to launchLockTimeout for a concurrent launch to finish
// its slot selection and container start. The returned release is idempotent
// and safe to call from any path (defer it, and call it early once the
// container is up). The kernel drops the lock if the process dies.
func AcquireLaunchLock(workspacePath, sessionName string, logger func(string)) (release func(), err error) {
	dir, err := launchLocksDir()
	if err != nil {
		return nil, fmt.Errorf("launch lock: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("launch lock: %w", err)
	}
	// The container prefix is part of the name so test containers
	// (COI_CONTAINER_PREFIX) never wait on a user's real launches.
	path := filepath.Join(dir, GetContainerPrefix()+IdentityHash(workspacePath, sessionName)+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: path built from a hash under ~/.coi/locks
	if err != nil {
		return nil, fmt.Errorf("launch lock: %w", err)
	}

	deadline := time.Now().Add(launchLockTimeout)
	noted := false
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK {
			_ = f.Close()
			return nil, fmt.Errorf("launch lock: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("timed out after %s waiting for another coi launch of this workspace to start its container (lock %s)", launchLockTimeout, path)
		}
		if !noted && logger != nil {
			logger("Waiting for another coi launch of this workspace to pick its slot...")
			noted = true
		}
		time.Sleep(launchLockPoll)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}
