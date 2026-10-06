package session

import (
	"context"
	"errors"
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
}

func (f *readyFake) ExecCommand(string, container.ExecCommandOptions) (string, error) {
	f.execs++
	if f.execs > f.readyAfter {
		return "ready", nil
	}
	return "", errors.New("not yet")
}

func (f *readyFake) Running() (bool, error) { f.runs++; return true, f.runErr }

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
