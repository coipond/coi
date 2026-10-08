//go:build linux
// +build linux

package nftmonitor

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestJournalReaderDoubleClose ensures calling Close() twice doesn't crash
func TestJournalReaderDoubleClose(t *testing.T) {
	// Create a minimal JournalReader without actually opening the journal
	// to test the close logic
	jr := &JournalReader{
		journal: nil, // nil journal simulates already-closed or failed state
		closed:  false,
	}

	// First close should succeed
	if err := jr.Close(); err != nil {
		t.Errorf("First close failed: %v", err)
	}

	// Second close should be a no-op (sync.Once)
	if err := jr.Close(); err != nil {
		t.Errorf("Second close should be no-op, got: %v", err)
	}

	// Third close should also be a no-op
	if err := jr.Close(); err != nil {
		t.Errorf("Third close should be no-op, got: %v", err)
	}
}

// TestJournalReaderConcurrentClose tests closing from multiple goroutines
func TestJournalReaderConcurrentClose(t *testing.T) {
	jr := &JournalReader{
		journal: nil,
		closed:  false,
	}

	var wg sync.WaitGroup
	closeCount := 100

	// Spawn multiple goroutines all trying to close
	for i := 0; i < closeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = jr.Close()
		}()
	}

	// Wait for all to complete - should not panic
	wg.Wait()

	// Verify closed state
	jr.mu.Lock()
	if !jr.closed {
		t.Error("Expected closed to be true after concurrent closes")
	}
	if jr.journal != nil {
		t.Error("Expected journal to be nil after close")
	}
	jr.mu.Unlock()
}

// TestJournalReaderClosedFlag tests that closed flag prevents operations
func TestJournalReaderClosedFlag(t *testing.T) {
	jr := &JournalReader{
		journal: nil,
		closed:  true, // Already closed
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	msgChan := make(chan string, 10)

	// StreamLogs should return immediately when already closed
	err := jr.StreamLogs(ctx, msgChan)
	if err != nil {
		t.Errorf("StreamLogs with closed reader should return nil, got: %v", err)
	}
}

// TestJournalReaderContextCancel tests graceful shutdown on context cancel
func TestJournalReaderContextCancel(t *testing.T) {
	jr := &JournalReader{
		journal: nil,
		closed:  false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	msgChan := make(chan string, 10)

	done := make(chan struct{})
	go func() {
		// This should return quickly since journal is nil
		_ = jr.StreamLogs(ctx, msgChan)
		close(done)
	}()

	// Cancel after short delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Should complete without hanging
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("StreamLogs did not return after context cancel")
	}
}

// TestLogReaderDoubleClose ensures LogReader handles double close safely
func TestLogReaderDoubleClose(t *testing.T) {
	// Create LogReader with minimal mock
	jr := &JournalReader{
		journal: nil,
		closed:  false,
	}

	lr := &LogReader{
		config:      &Config{ContainerIP: "10.0.0.1"},
		journal:     jr,
		eventChan:   make(chan *NetworkEvent, 10),
		journalChan: make(chan string, 10),
		closeOnce:   sync.Once{},
	}

	// First close
	if err := lr.Close(); err != nil {
		t.Errorf("First LogReader close failed: %v", err)
	}

	// Second close should be safe
	if err := lr.Close(); err != nil {
		t.Errorf("Second LogReader close should be no-op, got: %v", err)
	}
}

// TestLogReaderConcurrentClose tests LogReader with concurrent close calls
func TestLogReaderConcurrentClose(t *testing.T) {
	jr := &JournalReader{
		journal: nil,
		closed:  false,
	}

	lr := &LogReader{
		config:      &Config{ContainerIP: "10.0.0.1"},
		journal:     jr,
		eventChan:   make(chan *NetworkEvent, 10),
		journalChan: make(chan string, 10),
		closeOnce:   sync.Once{},
	}

	var wg sync.WaitGroup
	closeCount := 100

	for i := 0; i < closeCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = lr.Close()
		}()
	}

	// Wait for all to complete - should not panic
	wg.Wait()
}
