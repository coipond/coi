//go:build integration

package cli

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/container"
)

// TestUnfreezeCommand_FrozenContainer tests unfreezing a frozen container
func TestUnfreezeCommand_FrozenContainer(t *testing.T) {
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
	containerName := "coi-test-unfreeze-frozen"

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

	// Freeze the container
	_, err = container.IncusOutput("pause", containerName)
	if err != nil {
		t.Fatalf("Failed to pause container: %v", err)
	}

	// Verify it's frozen
	status, err := getContainerStatus(containerName)
	if err != nil {
		t.Fatalf("Failed to get container status: %v", err)
	}
	if status != "Frozen" {
		t.Fatalf("Expected container to be Frozen, got %s", status)
	}

	// Unfreeze the container
	err = unfreezeContainer(containerName)
	if err != nil {
		t.Fatalf("Failed to unfreeze container: %v", err)
	}

	// Verify it's running
	status, err = getContainerStatus(containerName)
	if err != nil {
		t.Fatalf("Failed to get container status: %v", err)
	}
	if status != "RUNNING" {
		t.Errorf("Expected container to be RUNNING after unfreeze, got %s", status)
	}

	t.Log("Successfully unfroze frozen container")
}

// TestUnfreezeCommand_NotFrozen tests that unfreeze fails on non-frozen container
func TestUnfreezeCommand_NotFrozen(t *testing.T) {
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
	containerName := "coi-test-unfreeze-running"

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

	// Try to unfreeze a running container (should fail)
	err = unfreezeContainer(containerName)
	if err == nil {
		t.Error("Expected error when unfreezing non-frozen container, got nil")
	}

	if !strings.Contains(err.Error(), "not frozen") {
		t.Errorf("Expected error message about 'not frozen', got: %v", err)
	}

	t.Log("Correctly rejected unfreeze on non-frozen container")
}

// TestUnfreezeCommand_NonExistent tests that unfreeze fails on non-existent container
func TestUnfreezeCommand_NonExistent(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Try to unfreeze a non-existent container
	err := unfreezeContainer("coi-nonexistent-container-12345")
	if err == nil {
		t.Error("Expected error when unfreezing non-existent container, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected error message about 'not found', got: %v", err)
	}

	t.Log("Correctly rejected unfreeze on non-existent container")
}

// TestUnfreezeAllFrozen tests unfreezing all frozen containers
func TestUnfreezeAllFrozen(t *testing.T) {
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

	// Create two test containers
	containers := []string{"coi-test-unfreeze-all-1", "coi-test-unfreeze-all-2"}

	// Clean up any existing containers
	for _, name := range containers {
		container.IncusOutput("delete", name, "--force")
	}

	// Launch containers
	for _, name := range containers {
		_, err = container.IncusOutput("launch", "coi-default", name)
		if err != nil {
			t.Fatalf("Failed to launch container %s: %v", name, err)
		}
		defer container.IncusOutput("delete", name, "--force")
	}

	// Wait for containers to be ready
	time.Sleep(3 * time.Second)

	// Freeze both containers
	for _, name := range containers {
		_, err = container.IncusOutput("pause", name)
		if err != nil {
			t.Fatalf("Failed to pause container %s: %v", name, err)
		}
	}

	// Unfreeze all frozen containers
	err = unfreezeAllFrozen()
	if err != nil {
		t.Fatalf("Failed to unfreeze all frozen: %v", err)
	}

	// Verify both are running
	for _, name := range containers {
		status, err := getContainerStatus(name)
		if err != nil {
			t.Fatalf("Failed to get container %s status: %v", name, err)
		}
		if status != "RUNNING" {
			t.Errorf("Expected container %s to be RUNNING after unfreezeAllFrozen, got %s", name, status)
		}
	}

	t.Log("Successfully unfroze all frozen containers")
}
