//go:build linux
// +build linux

package nftmonitor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coipond/coi/internal/monitor"
)

// TestDaemonErrorsRouteToOnError verifies that daemon errors are routed
// through the OnError callback rather than printed directly to stdout via
// fmt.Printf. Direct stdout writes corrupt the TUI.
//
// The test creates a daemon with a responder that will fail (trying to pause
// a non-existent container on a HIGH-level threat), then verifies the error
// is captured via OnError and nothing leaks to stdout.
func TestDaemonErrorsRouteToOnError(t *testing.T) {
	// Create a temporary audit log
	tmpDir := t.TempDir()
	auditLogPath := filepath.Join(tmpDir, "audit.jsonl")
	auditLog, err := monitor.NewAuditLog(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit log: %v", err)
	}
	defer auditLog.Close()

	// Track errors received through OnError callback
	var mu sync.Mutex
	var capturedErrors []error

	cfg := Config{
		ContainerName: "nonexistent-test-container",
		ContainerIP:   "10.0.0.99",
		OnError: func(err error) {
			mu.Lock()
			capturedErrors = append(capturedErrors, err)
			mu.Unlock()
		},
	}

	// Create responder that will try to pause a non-existent container (will fail)
	responder := monitor.NewResponder(
		cfg.ContainerName,
		true,  // autoPauseOnHigh - triggers pause on HIGH threats
		false, // autoKillOnCritical
		auditLog,
		nil, // onThreat
	)

	// Create event channel (replaces real log reader)
	eventChan := make(chan *NetworkEvent, 10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build daemon manually to avoid requiring real nftables/journald
	daemon := &Daemon{
		config:    &cfg,
		detector:  NewNetworkDetector(&cfg),
		responder: responder,
		auditLog:  auditLog,
		ctx:       ctx,
		cancel:    cancel,
		logReader: &LogReader{
			config:    &cfg,
			eventChan: eventChan,
		},
	}

	// Start processEvents in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		daemon.processEvents()
	}()

	// Capture stdout to detect the bug (fmt.Printf writes to stdout)
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Send an event to an RFC1918 address - this triggers a HIGH-level threat.
	// With autoPauseOnHigh=true, the responder will try to pause the
	// non-existent container and fail, producing an error that should go
	// through OnError, not fmt.Printf.
	eventChan <- &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.0.0.99",
		SrcIP:       "10.0.0.99",
		DstIP:       "192.168.1.1",
		DstPort:     80,
		Protocol:    "TCP",
	}

	// Give processEvents time to handle the event
	time.Sleep(500 * time.Millisecond)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("Failed to read captured stdout: %v", err)
	}
	stdoutOutput := buf.String()

	// Cancel context to stop processEvents
	cancel()
	wg.Wait()

	// The responder.Handle() should have failed (non-existent container).
	// Verify: the error should NOT appear on stdout (that's the bug).
	if stdoutOutput != "" {
		t.Errorf("Bug: daemon printed to stdout (corrupts TUI): %q\n"+
			"Errors should be routed through OnError callback instead of fmt.Printf",
			stdoutOutput)
	}

	// Verify: the error should have been captured via OnError callback.
	mu.Lock()
	errorCount := len(capturedErrors)
	mu.Unlock()

	if errorCount == 0 {
		t.Error("Expected errors to be captured through OnError callback, but none were received")
	} else {
		mu.Lock()
		t.Logf("OnError captured %d error(s): %v", errorCount, capturedErrors[0])
		mu.Unlock()
	}
}

// TestNftEventToNetworkThreat verifies the conversion from nftmonitor.NetworkEvent
// to monitor.NetworkThreat used when forwarding threats to the responder.
func TestNftEventToNetworkThreat(t *testing.T) {
	t.Run("nil event returns nil", func(t *testing.T) {
		result := nftEventToNetworkThreat(nil)
		if result != nil {
			t.Errorf("nftEventToNetworkThreat(nil) = %v, want nil", result)
		}
	})

	t.Run("converts fields correctly", func(t *testing.T) {
		event := &NetworkEvent{
			Timestamp:   time.Now(),
			ContainerIP: "10.0.0.50",
			SrcIP:       "10.0.0.50",
			SrcPort:     12345,
			DstIP:       "192.168.1.1",
			DstPort:     4444,
			Protocol:    "TCP",
		}

		result := nftEventToNetworkThreat(event)
		if result == nil {
			t.Fatal("nftEventToNetworkThreat returned nil for non-nil event")
		}

		if result.Connection.Protocol != "TCP" {
			t.Errorf("Protocol = %q, want TCP", result.Connection.Protocol)
		}
		if result.Connection.LocalAddr != "10.0.0.50:12345" {
			t.Errorf("LocalAddr = %q, want 10.0.0.50:12345", result.Connection.LocalAddr)
		}
		if result.Connection.RemoteAddr != "192.168.1.1:4444" {
			t.Errorf("RemoteAddr = %q, want 192.168.1.1:4444", result.Connection.RemoteAddr)
		}
		if result.RemoteHost != "192.168.1.1" {
			t.Errorf("RemoteHost = %q, want 192.168.1.1", result.RemoteHost)
		}
		if result.Reason == "" {
			t.Error("Reason should not be empty")
		}
	})
}

// TestDaemonOnErrorNilSafe verifies that the daemon does not panic when
// OnError is nil and an error occurs. This ensures backward compatibility.
func TestDaemonOnErrorNilSafe(t *testing.T) {
	// Create a temporary audit log
	tmpDir := t.TempDir()
	auditLogPath := filepath.Join(tmpDir, "audit.jsonl")
	auditLog, err := monitor.NewAuditLog(auditLogPath)
	if err != nil {
		t.Fatalf("Failed to create audit log: %v", err)
	}
	defer auditLog.Close()

	// Config WITHOUT OnError (nil) - should not panic
	cfg := Config{
		ContainerName: "nonexistent-test-container",
		ContainerIP:   "10.0.0.99",
	}

	responder := monitor.NewResponder(
		cfg.ContainerName,
		true,  // autoPauseOnHigh
		false, // autoKillOnCritical
		auditLog,
		nil,
	)

	eventChan := make(chan *NetworkEvent, 10)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	daemon := &Daemon{
		config:    &cfg,
		detector:  NewNetworkDetector(&cfg),
		responder: responder,
		auditLog:  auditLog,
		ctx:       ctx,
		cancel:    cancel,
		logReader: &LogReader{
			config:    &cfg,
			eventChan: eventChan,
		},
	}

	// Start processEvents
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		daemon.processEvents()
	}()

	// Send an event that triggers a HIGH threat and pause error - should NOT panic
	eventChan <- &NetworkEvent{
		Timestamp:   time.Now(),
		ContainerIP: "10.0.0.99",
		SrcIP:       "10.0.0.99",
		DstIP:       "192.168.1.1",
		DstPort:     80,
		Protocol:    "TCP",
	}

	time.Sleep(500 * time.Millisecond)
	cancel()
	wg.Wait()

	// If we get here without panic, the test passes
	fmt.Fprintln(os.Stderr, "OnError=nil handled safely (no panic)")
}
