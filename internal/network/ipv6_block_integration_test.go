//go:build integration

package network

import (
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
)

// TestApplyIPv6BlockRule_Integration verifies that ApplyIPv6BlockForContainer adds
// an iifname-based DROP rule to the ip6 coi forward chain and that
// RemoveIPv6BlockForContainer removes it cleanly. This is the IPv6 analogue of
// the boot-block lifecycle test.
func TestApplyIPv6BlockRule_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	containerName := "coi-ipv6-block-test"
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

	if err := ApplyIPv6BlockForContainer(containerName); err != nil {
		t.Fatalf("ApplyIPv6BlockForContainer: %v", err)
	}

	comment := ipv6BlockComment(containerName)

	output, err := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if err != nil {
		t.Fatalf("list ip6 nft chain: %v", err)
	}
	chainStr := string(output)

	if !strings.Contains(chainStr, comment) {
		t.Errorf("IPv6 block comment %q not found in ip6 chain:\n%s", comment, chainStr)
	}
	if !strings.Contains(chainStr, "iifname") {
		t.Errorf("expected iifname-based rule; ip6 chain:\n%s", chainStr)
	}
	if !strings.Contains(chainStr, "drop") {
		t.Errorf("expected drop action; ip6 chain:\n%s", chainStr)
	}

	// Idempotent: a second Apply must not create a duplicate rule.
	if err := ApplyIPv6BlockForContainer(containerName); err != nil {
		t.Errorf("second ApplyIPv6BlockForContainer: %v", err)
	}
	output2, _ := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if count := strings.Count(string(output2), comment); count != 1 {
		t.Errorf("expected exactly 1 IPv6 block rule, found %d", count)
	}

	// Remove and verify it is gone.
	if err := RemoveIPv6BlockForContainer(containerName); err != nil {
		t.Errorf("RemoveIPv6BlockForContainer: %v", err)
	}
	output3, err := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if err == nil && strings.Contains(string(output3), comment) {
		t.Errorf("IPv6 block rule still present after removal:\n%s", output3)
	}
}

// TestSetupRestrictedInstallsIPv6Block_Integration is the end-to-end check that
// restricted-mode network setup installs the host-side IPv6 egress drop and that
// teardown removes it.
func TestSetupRestrictedInstallsIPv6Block_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)
	if !NftAvailable() {
		t.Skip("nft passwordless sudo not configured, skipping restricted-mode test")
	}

	containerName := "coi-ipv6-restricted-e2e"
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

	// Apply the boot block first, mirroring what setup.go does after Start().
	if err := ApplyBootBlockRule(containerName); err != nil {
		t.Fatalf("ApplyBootBlockRule: %v", err)
	}

	netCfg := &config.NetworkConfig{Mode: config.NetworkModeRestricted}
	networkMgr := NewManager(netCfg, logger.NewDiscard())
	if err := networkMgr.SetupForContainer(t.Context(), containerName); err != nil {
		t.Fatalf("SetupForContainer(restricted): %v", err)
	}

	comment := ipv6BlockComment(containerName)
	output, err := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if err != nil {
		t.Fatalf("list ip6 nft chain after setup: %v", err)
	}
	if !strings.Contains(string(output), comment) {
		t.Errorf("restricted-mode setup did not install IPv6 block rule %q:\n%s", comment, string(output))
	}

	// Teardown must remove the IPv6 block.
	if err := networkMgr.Teardown(t.Context(), containerName); err != nil { //nolint:contextcheck
		t.Logf("Teardown: %v", err)
	}
	output2, err := runNFTCommand("-a", "list", "chain", "ip6", "coi", "forward")
	if err == nil && strings.Contains(string(output2), comment) {
		t.Errorf("IPv6 block rule still present after Teardown:\n%s", output2)
	}
}

// TestIPv6BlockBlocksTraffic_Integration verifies that, even when an in-container
// root re-enables IPv6, the host-side drop prevents IPv6 egress. It is best-effort:
// if the host/bridge has no IPv6 route to begin with (common in CI), there is no
// baseline connectivity to block and the test skips.
func TestIPv6BlockBlocksTraffic_Integration(t *testing.T) {
	skipUnlessBootBlockReady(t)

	const testIPv6 = "2606:4700:4700::1111" // Cloudflare DNS (IPv6)

	containerName := "coi-ipv6-traffic-test"
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

	// Ensure IPv6 is enabled inside the container (simulate an agent re-enabling it).
	_, _ = mgr.ExecCommand(
		"sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.eth0.disable_ipv6=0",
		container.ExecCommandOptions{Capture: true},
	)

	// Baseline: can the container reach an external IPv6 host at all? If not,
	// there is nothing for the drop rule to block — skip rather than false-pass.
	if _, err := mgr.ExecCommand(
		"ping6 -c1 -W2 "+testIPv6,
		container.ExecCommandOptions{Capture: true},
	); err != nil {
		t.Skip("no baseline IPv6 connectivity from container — skipping IPv6 traffic block test")
	}

	// Install the host-side IPv6 drop and confirm egress is now blocked.
	if err := ApplyIPv6BlockForContainer(containerName); err != nil {
		t.Fatalf("ApplyIPv6BlockForContainer: %v", err)
	}

	if _, err := mgr.ExecCommand(
		"ping6 -c1 -W2 "+testIPv6,
		container.ExecCommandOptions{Capture: true},
	); err == nil {
		t.Errorf("IPv6 ping to %s succeeded while host-side IPv6 block was in place; rule not effective", testIPv6)
	}

	// Lifting the block restores IPv6 egress.
	if err := RemoveIPv6BlockForContainer(containerName); err != nil {
		t.Fatalf("RemoveIPv6BlockForContainer: %v", err)
	}
	if _, err := mgr.ExecCommand(
		"ping6 -c1 -W2 "+testIPv6,
		container.ExecCommandOptions{Capture: true},
	); err != nil {
		t.Errorf("IPv6 ping to %s failed after block was lifted: %v", testIPv6, err)
	}
}
