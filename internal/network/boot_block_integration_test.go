//go:build integration

package network

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
)

// skipUnlessBootBlockReady skips the test if Incus, nft, or the coi image are absent.
func skipUnlessBootBlockReady(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	if !NftInstalled() {
		t.Skip("nft not installed, skipping integration test")
	}
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}
}

// TestApplyBootBlockRule_Integration verifies that ApplyBootBlockRule adds an
// iifname-based DROP rule to the ip coi forward chain and that
// RemoveBootBlockRule removes it cleanly.
func TestApplyBootBlockRule_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	containerName := "coi-boot-block-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("launch container: %v", err)
	}

	// Apply boot block
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Fatalf("ApplyBootBlockRule: %v", err)
	}

	comment := bootBlockComment(containerName)

	// Rule must appear in the chain
	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("list nft chain: %v", err)
	}
	chainStr := string(output)

	if !strings.Contains(chainStr, comment) {
		t.Errorf("boot block comment %q not found in chain:\n%s", comment, chainStr)
	}
	if !strings.Contains(chainStr, "iifname") {
		t.Errorf("expected iifname-based rule; chain:\n%s", chainStr)
	}
	if !strings.Contains(chainStr, "drop") {
		t.Errorf("expected drop action; chain:\n%s", chainStr)
	}

	// Calling Apply again must be idempotent (no duplicate rules)
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Errorf("second ApplyBootBlockRule: %v", err)
	}
	output2, _ := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	count := strings.Count(string(output2), comment)
	if count != 1 {
		t.Errorf("expected exactly 1 boot block rule, found %d", count)
	}

	// Remove and verify it is gone
	if err := RemoveBootBlockRule(containerName); err != nil {
		t.Errorf("RemoveBootBlockRule: %v", err)
	}
	output3, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err == nil && strings.Contains(string(output3), comment) {
		t.Errorf("boot block rule still present after RemoveBootBlockRule:\n%s", output3)
	}
}

// TestBootBlockBlocksTraffic_Integration verifies that a container cannot reach
// the gateway while the boot block is in place, and can reach it once lifted.
func TestBootBlockBlocksTraffic_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	containerName := "coi-boot-block-traffic-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("launch container: %v", err)
	}

	// Wait for container to be ready and have an IP
	var gatewayIP string
	for i := 0; i < 30; i++ {
		ip, err := getContainerGatewayIP(containerName)
		if err == nil && ip != "" {
			gatewayIP = ip
			break
		}
		time.Sleep(time.Second)
	}
	if gatewayIP == "" {
		t.Skip("could not determine gateway IP, skipping traffic test")
	}

	// Apply boot block
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Fatalf("ApplyBootBlockRule: %v", err)
	}

	// Traffic to gateway must be blocked while boot block is in place.
	// We use a single-packet ping with a short timeout to avoid slowing the test.
	_, pingErr := mgr.ExecCommand(
		"ping -c1 -W1 "+gatewayIP,
		container.ExecCommandOptions{Capture: true},
	)
	if pingErr == nil {
		// A nil error means ping exited 0 (ping succeeded) — the drop rule is not
		// taking effect. This is a failure.
		t.Errorf("ping to gateway %s succeeded while boot block was in place; rule not effective", gatewayIP)
	}

	// Lift boot block
	if err := RemoveBootBlockRule(containerName); err != nil {
		t.Fatalf("RemoveBootBlockRule: %v", err)
	}

	// After removal the container must be able to reach the gateway again.
	if _, err := mgr.ExecCommand(
		"ping -c1 -W2 "+gatewayIP,
		container.ExecCommandOptions{Capture: true},
	); err != nil {
		t.Errorf("ping to gateway %s failed after boot block was lifted: %v", gatewayIP, err)
	}
}

// TestBootBlockRemovedBySetupForContainer_Integration verifies the end-to-end
// lifecycle: boot block applied before isolation setup, removed once rules are
// in place, and the container has proper connectivity afterwards.
func TestBootBlockRemovedBySetupForContainer_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	containerName := "coi-boot-block-e2e-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("launch container: %v", err)
	}

	// Simulate what setup.go does: apply boot block right after start
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Fatalf("ApplyBootBlockRule: %v", err)
	}

	// Boot block must be in chain before SetupForContainer
	output, _ := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if !strings.Contains(string(output), bootBlockComment(containerName)) {
		t.Errorf("boot block not present before SetupForContainer")
	}

	// SetupForContainer in open mode (simplest — just needs the boot block gone)
	netCfg := &config.NetworkConfig{Mode: config.NetworkModeOpen}
	networkMgr := NewManager(netCfg, logger.NewDiscard())
	if err := networkMgr.SetupForContainer(t.Context(), containerName); err != nil {
		t.Fatalf("SetupForContainer: %v", err)
	}

	// Boot block must be gone after SetupForContainer
	output2, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err == nil && strings.Contains(string(output2), bootBlockComment(containerName)) {
		t.Errorf("boot block still present after SetupForContainer:\n%s", output2)
	}

	// Tear down open mode rules
	if err := networkMgr.Teardown(t.Context(), containerName); err != nil { //nolint:contextcheck
		t.Logf("Teardown: %v", err)
	}
}

// TestSetupForContainer_SetupError_KeepsBootBlock_Integration verifies the
// fail-closed invariant: when network isolation setup ERRORS, SetupForContainer
// must NOT lift the boot block, so a failed session stays at zero egress rather
// than being silently opened. The happy-path tests above only prove the block is
// removed on SUCCESS; a refactor that lifted the block before an early-return
// error would open every failed session with those tests still green.
//
// The failure is induced with an allowlist config that declares no allowed
// domains — setupAllowlist rejects it ("allowlist mode requires at least one
// allowed domain") and returns through the exact `return err // boot block stays`
// path that setupRestricted shares.
func TestSetupForContainer_SetupError_KeepsBootBlock_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	containerName := "coi-boot-block-failclosed-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("launch container: %v", err)
	}

	// Discover the gateway so we can confirm egress stays blocked after the failure.
	var gatewayIP string
	for i := 0; i < 30; i++ {
		if ip, err := getContainerGatewayIP(containerName); err == nil && ip != "" {
			gatewayIP = ip
			break
		}
		time.Sleep(time.Second)
	}

	// Apply the boot block, exactly as session setup does right after container start.
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Fatalf("ApplyBootBlockRule: %v", err)
	}

	// Induce a setup failure: allowlist mode with no allowed domains. setupAllowlist
	// rejects it, and SetupForContainer must return the error WITHOUT lifting the block.
	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{},
	}
	networkMgr := NewManager(netCfg, logger.NewDiscard())
	if err := networkMgr.SetupForContainer(t.Context(), containerName); err == nil {
		t.Fatal("SetupForContainer should have errored on an allowlist config with no allowed domains")
	}

	// INVARIANT: the boot block must still be present after the failed setup.
	output, _ := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if !strings.Contains(string(output), bootBlockComment(containerName)) {
		t.Errorf("boot block was removed after a FAILED setup — the failed session was silently opened:\n%s", output)
	}

	// ...and it must still be effective: the container cannot reach the gateway.
	if gatewayIP != "" {
		if _, err := mgr.ExecCommand(
			"ping -c1 -W1 "+gatewayIP,
			container.ExecCommandOptions{Capture: true},
		); err == nil {
			t.Errorf("container reached gateway %s after a failed setup — network is not fail-closed", gatewayIP)
		}
	}
}
