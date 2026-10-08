//go:build integration && linux

package nftmonitor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestJournalCloseWhileStreaming_ChildWaitsSurvive reproduces the leaked-rules
// flake: Daemon.Stop cancelled the reader, closed the journal while StreamLogs
// was still inside sd_journal_wait, then ran `sudo nft` to remove the rules.
// Tearing the journal down under the wait closed descriptors the process had
// already reused, and the nft child's wait failed with "waitid: bad file
// descriptor". Close must defer to the streaming goroutine, and a child
// started right after LogReader.Start returns must be waitable.
func TestJournalCloseWhileStreaming_ChildWaitsSurvive(t *testing.T) {
	probe, err := NewJournalReader()
	if err != nil {
		t.Skipf("systemd journal not accessible: %v", err)
	}
	_ = probe.Close()

	for i := 0; i < 10; i++ {
		lr, err := NewLogReader(&Config{ContainerIP: "203.0.113.10"})
		if err != nil {
			t.Fatalf("NewLogReader: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		done := make(chan struct{})
		go func() {
			close(started)
			_ = lr.Start(ctx)
			close(done)
		}()
		<-started
		time.Sleep(time.Duration(10+i*7%60) * time.Millisecond) // land inside Wait(1s)

		// Daemon.Stop order: cancel, wait for Start, Close, then exec children.
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: LogReader.Start did not return after cancel", i)
		}
		_ = lr.Close()
		for k := 0; k < 5; k++ {
			if out, err := exec.Command("true").CombinedOutput(); err != nil {
				if strings.Contains(err.Error(), "bad file descriptor") {
					t.Fatalf("iteration %d: child wait failed after journal close: %v (%s)", i, err, out)
				}
				t.Fatalf("iteration %d: child failed: %v (%s)", i, err, out)
			}
		}
	}
}
