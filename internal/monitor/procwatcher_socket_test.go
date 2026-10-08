//go:build linux

package monitor

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readSocketUntilDone must deliver datagrams, notice cancellation on its own
// (the old code relied on a second goroutine closing the socket under the
// blocked read, then closed it again — a double close that hit reused fds),
// and leave the socket open for its single owner to close.
func TestReadSocketUntilDone(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan string, 4)
	done := make(chan error, 1)
	go func() {
		done <- readSocketUntilDone(ctx, fds[0], func(b []byte) { got <- string(b) })
	}()

	if _, err := unix.Write(fds[1], []byte("event")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if m != "event" {
			t.Fatalf("got %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("datagram not delivered")
	}

	cancel() // nothing closes the socket: the loop must stop by itself
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * procReadTimeout):
		t.Fatal("read loop did not return after cancel")
	}

	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("read loop closed the socket it does not own: %v", err)
	}
}
