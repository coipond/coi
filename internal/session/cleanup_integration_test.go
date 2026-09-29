//go:build integration

package session

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
	"github.com/mensfeld/coi/internal/network"
)

// cleanupTestContainer is a helper that ensures complete cleanup of a test container.
// Use with t.Cleanup() to ensure cleanup even on test failure.
func cleanupTestContainer(t *testing.T, containerName string) {
	t.Helper()
	mgr := container.NewManager(containerName)

	// Get container IP for firewall rule cleanup
	containerIP, _ := network.GetContainerIPFast(containerName)

	// Stop and delete container
	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Clean up nft rules for the IP
	if containerIP != "" {
		cleanupRulesForIP(t, containerIP)
	}
}

// TestEndToEndCleanupWithOpenMode tests the complete cleanup flow with open mode networking.
// This is an end-to-end test that verifies the fix for Bug #1 (open mode rules never cleaned).
func TestEndToEndCleanupWithOpenMode(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Count firewall rules before
	rulesBefore := countFirewallRules(t)
	t.Logf("Firewall rules before test: %d", rulesBefore)

	// Create a test container
	containerName := "coi-e2e-cleanup-open"
	mgr := container.NewManager(containerName)

	// Register cleanup to run even if test fails
	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	// Clean up any existing container
	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Launch container (non-ephemeral)
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}

	// Wait for container to get an IP
	time.Sleep(3 * time.Second)

	// Get container IP for verification
	containerIP, err := network.GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}
	t.Logf("Container IP: %s", containerIP)

	// Set up network manager with open mode
	netCfg := &config.NetworkConfig{
		Mode: config.NetworkModeOpen,
	}
	netMgr := network.NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Logf("Warning: SetupForContainer failed: %v", err)
	}

	// Count rules after setup
	rulesAfterSetup := countFirewallRules(t)
	t.Logf("Firewall rules after setup: %d", rulesAfterSetup)

	// Verify rules were created
	rulesForIP := countRulesForIP(t, containerIP)
	t.Logf("Rules for container IP after setup: %d", rulesForIP)

	// Simulate the container being stopped (like `sudo shutdown 0`)
	if err := mgr.Stop(true); err != nil {
		t.Fatalf("Failed to stop container: %v", err)
	}

	// Now call the actual Cleanup function from cleanup.go
	// This is the end-to-end test of the cleanup flow
	var logMessages []string
	cleanupOpts := CleanupOptions{
		ContainerName:  containerName,
		NetworkManager: netMgr,
		Persistent:     false,
		Logger: func(msg string) {
			logMessages = append(logMessages, msg)
			t.Logf("[cleanup] %s", msg)
		},
	}

	if err := Cleanup(cleanupOpts); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify cleanup messages
	foundRemoved := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "Container removed") || strings.Contains(msg, "removed") {
			foundRemoved = true
		}
	}
	if !foundRemoved {
		t.Log("Note: Container may not have been removed (possibly already gone)")
	}

	// Count rules after cleanup
	rulesAfterCleanup := countFirewallRules(t)
	t.Logf("Firewall rules after cleanup: %d", rulesAfterCleanup)

	// Verify rules for this container IP were cleaned up
	rulesForIPAfterCleanup := countRulesForIP(t, containerIP)
	if rulesForIPAfterCleanup > 0 {
		t.Errorf("End-to-end test failed: %d firewall rules still exist for IP %s after cleanup",
			rulesForIPAfterCleanup, containerIP)
		// Clean up manually for test hygiene
		cleanupRulesForIP(t, containerIP)
	} else {
		t.Logf("Success: All firewall rules cleaned up in end-to-end test for IP %s", containerIP)
	}

	// Verify container was deleted
	if exists, _ := mgr.Exists(); exists {
		t.Errorf("Container %s still exists after cleanup", containerName)
		_ = mgr.Delete(true)
	} else {
		t.Logf("Success: Container %s was deleted", containerName)
	}
}

// TestEndToEndCleanupWithRestrictedMode tests the complete cleanup flow with restricted mode networking.
// This is an end-to-end test that verifies the fix for Bug #2 (container deleted before cleanup).
func TestEndToEndCleanupWithRestrictedMode(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Count firewall rules before
	rulesBefore := countFirewallRules(t)
	t.Logf("Firewall rules before test: %d", rulesBefore)

	// Create a test container
	containerName := "coi-e2e-cleanup-restricted"
	mgr := container.NewManager(containerName)

	// Register cleanup to run even if test fails
	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	// Clean up any existing container
	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Launch container (non-ephemeral)
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}

	// Wait for container to get an IP
	time.Sleep(3 * time.Second)

	// Get container IP for verification
	containerIP, err := network.GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}
	t.Logf("Container IP: %s", containerIP)

	// Set up network manager with restricted mode
	boolTrue := true
	netCfg := &config.NetworkConfig{
		Mode:                  config.NetworkModeRestricted,
		BlockPrivateNetworks:  &boolTrue,
		BlockMetadataEndpoint: &boolTrue,
	}
	netMgr := network.NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	// Count rules after setup
	rulesAfterSetup := countFirewallRules(t)
	t.Logf("Firewall rules after setup: %d", rulesAfterSetup)

	// Verify rules were created
	rulesForIP := countRulesForIP(t, containerIP)
	t.Logf("Rules for container IP after setup: %d", rulesForIP)

	// Simulate the container being stopped (like `sudo shutdown 0`)
	if err := mgr.Stop(true); err != nil {
		t.Fatalf("Failed to stop container: %v", err)
	}

	// Now call the actual Cleanup function from cleanup.go
	// This is the end-to-end test of the cleanup flow
	var logMessages []string
	cleanupOpts := CleanupOptions{
		ContainerName:  containerName,
		NetworkManager: netMgr,
		Persistent:     false,
		Logger: func(msg string) {
			logMessages = append(logMessages, msg)
			t.Logf("[cleanup] %s", msg)
		},
	}

	if err := Cleanup(cleanupOpts); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Count rules after cleanup
	rulesAfterCleanup := countFirewallRules(t)
	t.Logf("Firewall rules after cleanup: %d", rulesAfterCleanup)

	// Verify rules for this container IP were cleaned up
	rulesForIPAfterCleanup := countRulesForIP(t, containerIP)
	if rulesForIPAfterCleanup > 0 {
		t.Errorf("End-to-end test failed: %d firewall rules still exist for IP %s after cleanup",
			rulesForIPAfterCleanup, containerIP)
		// Clean up manually for test hygiene
		cleanupRulesForIP(t, containerIP)
	} else {
		t.Logf("Success: All firewall rules cleaned up in end-to-end test for IP %s", containerIP)
	}

	// Verify container was deleted
	if exists, _ := mgr.Exists(); exists {
		t.Errorf("Container %s still exists after cleanup", containerName)
		_ = mgr.Delete(true)
	} else {
		t.Logf("Success: Container %s was deleted", containerName)
	}
}

// TestEndToEndCleanupMultipleContainers tests cleanup of multiple containers to verify
// no rule accumulation across container lifecycles.
func TestEndToEndCleanupMultipleContainers(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Count firewall rules before
	rulesBefore := countFirewallRules(t)
	t.Logf("Firewall rules before test: %d", rulesBefore)

	// Register cleanup for all test containers (in case of test failure)
	t.Cleanup(func() {
		for i := 1; i <= 3; i++ {
			containerName := "coi-e2e-multi-" + string(rune('0'+i))
			cleanupTestContainer(t, containerName)
		}
	})

	// Test launching and cleaning up 3 containers in sequence
	for i := 1; i <= 3; i++ {
		containerName := "coi-e2e-multi-" + string(rune('0'+i))
		t.Logf("=== Testing container %d: %s ===", i, containerName)

		mgr := container.NewManager(containerName)

		// Clean up any existing container
		if exists, _ := mgr.Exists(); exists {
			_ = mgr.Stop(true)
			_ = mgr.Delete(true)
		}

		// Launch container
		if err := mgr.Launch("coi-default", false, ""); err != nil {
			t.Fatalf("Failed to launch container %s: %v", containerName, err)
		}

		// Wait for IP
		time.Sleep(3 * time.Second)

		// Get container IP
		containerIP, err := network.GetContainerIP(containerName)
		if err != nil {
			t.Fatalf("Failed to get container IP for %s: %v", containerName, err)
		}
		t.Logf("Container %s IP: %s", containerName, containerIP)

		// Set up network with open mode
		netCfg := &config.NetworkConfig{
			Mode: config.NetworkModeOpen,
		}
		netMgr := network.NewManager(netCfg, logger.NewDiscard())
		if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
			t.Logf("Warning: SetupForContainer failed for %s: %v", containerName, err)
		}

		// Stop container
		if err := mgr.Stop(true); err != nil {
			t.Fatalf("Failed to stop container %s: %v", containerName, err)
		}

		// Cleanup
		cleanupOpts := CleanupOptions{
			ContainerName:  containerName,
			NetworkManager: netMgr,
			Persistent:     false,
			Logger: func(msg string) {
				t.Logf("[cleanup %d] %s", i, msg)
			},
		}
		if err := Cleanup(cleanupOpts); err != nil {
			t.Fatalf("Cleanup failed for %s: %v", containerName, err)
		}

		// Verify cleanup
		if countRulesForIP(t, containerIP) > 0 {
			t.Errorf("Rules still exist for container %d IP %s", i, containerIP)
			cleanupRulesForIP(t, containerIP)
		}

		rulesNow := countFirewallRules(t)
		t.Logf("Firewall rules after container %d cleanup: %d", i, rulesNow)
	}

	// Verify no rule accumulation
	rulesAfter := countFirewallRules(t)
	t.Logf("Firewall rules after all containers: %d (was %d before)", rulesAfter, rulesBefore)

	// Allow for base rules (conntrack)
	if rulesAfter > rulesBefore+1 {
		t.Errorf("Rule accumulation detected: started with %d, ended with %d", rulesBefore, rulesAfter)
	} else {
		t.Logf("Success: No significant rule accumulation after 3 container lifecycles")
	}
}

// Helper functions

func countFirewallRules(t *testing.T) int {
	t.Helper()
	ipHandles, err := network.ListCOIFilterRuleIPs()
	if err != nil {
		t.Logf("Warning: Failed to count nft coi forward rules: %v", err)
		return 0
	}
	total := 0
	for _, handles := range ipHandles {
		total += len(handles)
	}
	return total
}

func countRulesForIP(t *testing.T, ip string) int {
	t.Helper()
	ipHandles, err := network.ListCOIFilterRuleIPs()
	if err != nil {
		t.Logf("Warning: Failed to list nft coi forward rules: %v", err)
		return 0
	}
	handles, ok := ipHandles[ip]
	if !ok {
		return 0
	}
	return len(handles)
}

func cleanupRulesForIP(t *testing.T, ip string) {
	t.Helper()
	if err := network.DeleteCOIFilterRulesForIP(ip); err != nil {
		t.Logf("Warning: Failed to cleanup nft rules for IP %s: %v", ip, err)
	} else {
		t.Logf("Cleaned up nft rules for IP %s", ip)
	}
}
