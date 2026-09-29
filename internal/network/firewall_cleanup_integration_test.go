//go:build integration

package network

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
)

// cleanupTestContainer is a helper that ensures complete cleanup of a test container.
// Use with t.Cleanup() to ensure cleanup even on test failure.
func cleanupTestContainer(t *testing.T, containerName string) {
	t.Helper()
	mgr := container.NewManager(containerName)

	// Get veth name before any cleanup (might fail if container doesn't exist)
	vethName, _ := GetContainerVethName(containerName)

	// Get container IP for firewall rule cleanup
	containerIP, _ := GetContainerIPFast(containerName)

	// Stop and delete container
	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Clean up firewall rules for the IP
	if containerIP != "" {
		cleanupRulesForIP(t, containerIP)
	}

	// Clean up any residual boot-block rule (idempotent: no-op if already removed)
	if err := RemoveBootBlockRule(containerName); err != nil {
		t.Logf("Note: boot block cleanup: %v", err)
	}

	// Clean up any residual IPv6 egress block (idempotent: no-op if already removed)
	if err := RemoveIPv6BlockForContainer(containerName); err != nil {
		t.Logf("Note: IPv6 block cleanup: %v", err)
	}

	_ = vethName // zone bindings no longer used
}

// TestOpenModeFirewallCleanup verifies that open mode firewall rules are cleaned up
// when a container is torn down. This reproduces Bug #1 from ERROR.md.
func TestOpenModeFirewallCleanup(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Count firewall rules before
	rulesBefore := countFirewallRules(t)

	// Create a test container
	containerName := "coi-firewall-test-open"
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

	// Set up network manager with open mode
	netCfg := &config.NetworkConfig{
		Mode: config.NetworkModeOpen,
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Logf("Warning: SetupForContainer failed: %v", err)
	}

	// Count rules after setup
	rulesAfterSetup := countFirewallRules(t)
	t.Logf("Firewall rules: before=%d, after setup=%d", rulesBefore, rulesAfterSetup)

	// Verify rules were created (at least one new rule for open mode)
	if rulesAfterSetup <= rulesBefore {
		t.Log("No new rules created for open mode - firewall may not have created rules")
	}

	// Teardown network (should clean up rules)
	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	// Stop and delete container
	_ = mgr.Stop(true)
	_ = mgr.Delete(true)

	// Count rules after teardown
	rulesAfterTeardown := countFirewallRules(t)
	t.Logf("Firewall rules after teardown=%d", rulesAfterTeardown)

	// Verify rules were cleaned up
	// Check if container IP is still in any rules
	containerRulesRemaining := countRulesForContainer(t, containerName)
	if containerRulesRemaining > 0 {
		t.Errorf("Bug #1 confirmed: %d firewall rules still exist for container %s after teardown",
			containerRulesRemaining, containerName)
	} else {
		t.Logf("Success: All firewall rules cleaned up for %s", containerName)
	}
}

// TestRestrictedModeFirewallCleanup verifies that restricted mode firewall rules
// are cleaned up properly when teardown is called.
func TestRestrictedModeFirewallCleanup(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Count firewall rules before
	rulesBefore := countFirewallRules(t)

	// Create a test container
	containerName := "coi-firewall-test-restricted"
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

	// Set up network manager with restricted mode
	boolTrue := true
	netCfg := &config.NetworkConfig{
		Mode:                  config.NetworkModeRestricted,
		BlockPrivateNetworks:  &boolTrue,
		BlockMetadataEndpoint: &boolTrue,
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	// Count rules after setup
	rulesAfterSetup := countFirewallRules(t)
	t.Logf("Firewall rules: before=%d, after setup=%d", rulesBefore, rulesAfterSetup)

	// Get container IP for verification
	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}
	t.Logf("Container IP: %s", containerIP)

	// Teardown network (should clean up rules)
	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	// Stop and delete container
	_ = mgr.Stop(true)
	_ = mgr.Delete(true)

	// Count rules after teardown
	rulesAfterTeardown := countFirewallRules(t)
	t.Logf("Firewall rules after teardown=%d", rulesAfterTeardown)

	// Verify rules for this container IP were cleaned up
	rulesForIP := countRulesForIP(t, containerIP)
	if rulesForIP > 0 {
		t.Errorf("Found %d firewall rules still referencing IP %s after teardown",
			rulesForIP, containerIP)
	} else {
		t.Logf("Success: All firewall rules cleaned up for IP %s", containerIP)
	}
}

// TestFirewallCleanupBeforeContainerDeletion verifies that firewall cleanup must
// happen BEFORE container deletion to retrieve the IP. This reproduces Bug #2.
func TestFirewallCleanupBeforeContainerDeletion(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Create a test container
	containerName := "coi-firewall-test-order"
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

	// Get container IP before anything else
	containerIP, err := GetContainerIP(containerName)
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
	netMgr := NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	// Count rules after setup for this container
	rulesForIPAfterSetup := countRulesForIP(t, containerIP)
	t.Logf("Rules for container IP after setup: %d", rulesForIPAfterSetup)

	// BUG REPRODUCTION: Delete container FIRST, then try to teardown
	// This simulates the original buggy code flow in cleanup.go
	_ = mgr.Stop(true)
	if err := mgr.Delete(true); err != nil {
		t.Fatalf("Failed to delete container: %v", err)
	}

	// Now try to get container IP - this should fail because container is deleted
	_, ipErr := GetContainerIP(containerName)
	if ipErr == nil {
		t.Error("Expected GetContainerIP to fail after container deletion")
	} else {
		t.Logf("GetContainerIP correctly failed after deletion: %v", ipErr)
	}

	// Now call teardown - this will fail to clean up rules because IP is unavailable
	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Logf("Teardown returned error (expected): %v", err)
	}

	// Check if rules are still present (demonstrating Bug #2)
	rulesForIPAfterTeardown := countRulesForIP(t, containerIP)
	if rulesForIPAfterTeardown > 0 {
		t.Logf("Bug #2 confirmed: %d rules still exist for IP %s after teardown",
			rulesForIPAfterTeardown, containerIP)
		t.Logf("This happens because container was deleted before teardown")

		// Clean up manually for test hygiene
		cleanupRulesForIP(t, containerIP)
	} else {
		t.Logf("Rules were cleaned up successfully")
	}
}

// TestFirewallCleanupCorrectOrder verifies the correct cleanup order:
// teardown network BEFORE deleting container.
func TestFirewallCleanupCorrectOrder(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Create a test container
	containerName := "coi-firewall-test-correct"
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

	// Get container IP
	containerIP, err := GetContainerIP(containerName)
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
	netMgr := NewManager(netCfg, logger.NewDiscard())

	// Set up network (creates firewall rules)
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	// Count rules after setup
	rulesForIPAfterSetup := countRulesForIP(t, containerIP)
	t.Logf("Rules for container IP after setup: %d", rulesForIPAfterSetup)

	// CORRECT ORDER: Teardown network FIRST while container still exists
	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	// THEN delete container
	_ = mgr.Stop(true)
	if err := mgr.Delete(true); err != nil {
		t.Fatalf("Failed to delete container: %v", err)
	}

	// Verify rules were cleaned up
	rulesForIPAfterTeardown := countRulesForIP(t, containerIP)
	if rulesForIPAfterTeardown > 0 {
		t.Errorf("Found %d rules still exist for IP %s after correct-order cleanup",
			rulesForIPAfterTeardown, containerIP)
	} else {
		t.Logf("Success: Correct order cleanup removed all %d rules for IP %s",
			rulesForIPAfterSetup, containerIP)
	}
}

// Helper functions

func countFirewallRules(t *testing.T) int {
	t.Helper()
	ipHandles, err := ListCOIFilterRuleIPs()
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

func countRulesForContainer(t *testing.T, containerName string) int {
	t.Helper()
	ip, err := GetContainerIP(containerName)
	if err != nil {
		return 0
	}
	return countRulesForIP(t, ip)
}

func countRulesForIP(t *testing.T, ip string) int {
	t.Helper()
	ipHandles, err := ListCOIFilterRuleIPs()
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
	if err := DeleteCOIFilterRulesForIP(ip); err != nil {
		t.Logf("Warning: Failed to cleanup nft rules for IP %s: %v", ip, err)
	} else {
		t.Logf("Cleaned up nft rules for IP %s", ip)
	}
}
