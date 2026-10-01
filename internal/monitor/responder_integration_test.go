//go:build integration

package monitor

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
)

// TestResponderPauseActualContainer tests pausing a real container
func TestResponderPauseActualContainer(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Check if the coi image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test")
	}

	// Create a test container
	containerName := "coi-test-responder-pause"

	// Clean up any existing container
	container.IncusOutput("delete", containerName, "--force")

	// Launch container
	_, err = container.IncusOutput("launch", "coi-default", containerName)
	if err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}
	defer container.IncusOutput("delete", containerName, "--force")

	// Wait for container to be ready
	time.Sleep(2 * time.Second)

	// Create responder with auto-pause enabled
	var actionCalled bool
	var actionMsg string
	var mu sync.Mutex

	responder := NewResponder(containerName, true, false, nil, nil)
	responder.SetOnAction(func(action, message string) {
		mu.Lock()
		actionCalled = true
		actionMsg = message
		mu.Unlock()
	})

	// Trigger a high-level threat that should pause the container
	threat := ThreatEvent{
		Timestamp:   time.Now(),
		Level:       ThreatLevelHigh,
		Category:    "test",
		Title:       "Test threat",
		Description: "Testing pause functionality",
	}

	err = responder.Handle(context.Background(), threat)
	if err != nil {
		t.Fatalf("Failed to handle threat: %v", err)
	}

	// Verify container is frozen
	output, err := container.IncusOutput("list", containerName, "--format", "csv", "-c", "s")
	if err != nil {
		t.Fatalf("Failed to get container status: %v", err)
	}

	status := strings.TrimSpace(output)
	if status != "FROZEN" {
		t.Errorf("Expected container to be FROZEN, got %s", status)
	}

	// Verify OnAction was called
	mu.Lock()
	if !actionCalled {
		t.Error("Expected OnAction callback to be called")
	}
	if !strings.Contains(actionMsg, "PAUSED") {
		t.Errorf("Expected action message to contain 'PAUSED', got: %s", actionMsg)
	}
	mu.Unlock()

	// Verify second pause attempt doesn't error
	err = responder.pauseContainer(context.Background())
	if err != nil {
		t.Errorf("Second pause attempt should not error: %v", err)
	}

	t.Log("Successfully paused container via responder")
}

// TestResponderHandlesAlreadyFrozen tests that responder handles already frozen container
func TestResponderHandlesAlreadyFrozen(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Check if the coi image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test")
	}

	// Create a test container
	containerName := "coi-test-responder-frozen"

	// Clean up any existing container
	container.IncusOutput("delete", containerName, "--force")

	// Launch container
	_, err = container.IncusOutput("launch", "coi-default", containerName)
	if err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}
	defer container.IncusOutput("delete", containerName, "--force")

	// Wait for container to be ready
	time.Sleep(2 * time.Second)

	// Freeze the container directly
	_, err = container.IncusOutput("pause", containerName)
	if err != nil {
		t.Fatalf("Failed to pause container: %v", err)
	}

	// Create responder with auto-pause enabled
	responder := NewResponder(containerName, true, false, nil, nil)

	// Attempt to pause already-frozen container
	err = responder.pauseContainer(context.Background())
	if err != nil {
		t.Errorf("pauseContainer should handle already-frozen without error: %v", err)
	}

	// Verify responder tracked the paused state
	responder.mu.Lock()
	isPaused := responder.paused
	responder.mu.Unlock()

	if !isPaused {
		t.Error("Responder should track paused state after pauseContainer")
	}

	t.Log("Successfully handled already-frozen container")
}

// TestResponderDeduplicationIntegration tests deduplication with real timing
func TestResponderDeduplicationIntegration(t *testing.T) {
	alertCount := 0
	var mu sync.Mutex

	responder := NewResponder(
		"test-container",
		false, // no auto-pause
		false, // no auto-kill
		nil,
		func(threat ThreatEvent) {
			mu.Lock()
			alertCount++
			mu.Unlock()
		},
	)

	// Set short dedupe window for testing
	responder.dedupeWindow = 100 * time.Millisecond

	threat := ThreatEvent{
		Timestamp:   time.Now(),
		Level:       ThreatLevelWarning,
		Category:    "network",
		Title:       "Test connection",
		Description: "Testing deduplication",
	}

	// Send same threat 5 times rapidly
	for i := 0; i < 5; i++ {
		if err := responder.Handle(context.Background(), threat); err != nil {
			t.Fatalf("Handle failed: %v", err)
		}
	}

	mu.Lock()
	firstCount := alertCount
	mu.Unlock()

	// Should only have 1 alert due to deduplication
	if firstCount != 1 {
		t.Errorf("Expected 1 alert during dedupe window, got %d", firstCount)
	}

	// Wait for dedupe window to expire
	time.Sleep(150 * time.Millisecond)

	// Send again
	if err := responder.Handle(context.Background(), threat); err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	mu.Lock()
	finalCount := alertCount
	mu.Unlock()

	// Should have 2 alerts now
	if finalCount != 2 {
		t.Errorf("Expected 2 alerts after dedupe expiry, got %d", finalCount)
	}

	t.Log("Deduplication timing works correctly")
}

// TestResponderMultipleThreatTypes tests different threats aren't deduplicated
func TestResponderMultipleThreatTypes(t *testing.T) {
	alertCount := 0
	var mu sync.Mutex

	responder := NewResponder(
		"test-container",
		false,
		false,
		nil,
		func(threat ThreatEvent) {
			mu.Lock()
			alertCount++
			mu.Unlock()
		},
	)

	threats := []ThreatEvent{
		{Level: ThreatLevelWarning, Category: "network", Title: "Connection A"},
		{Level: ThreatLevelWarning, Category: "network", Title: "Connection B"},
		{Level: ThreatLevelWarning, Category: "process", Title: "Process A"},
	}

	for _, threat := range threats {
		threat.Timestamp = time.Now()
		if err := responder.Handle(context.Background(), threat); err != nil {
			t.Fatalf("Handle failed: %v", err)
		}
	}

	mu.Lock()
	count := alertCount
	mu.Unlock()

	// Each unique threat should alert
	if count != 3 {
		t.Errorf("Expected 3 alerts for different threats, got %d", count)
	}

	t.Log("Different threat types handled correctly")
}
