//go:build integration

package network

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/logger"
)

// coiForwardChainText returns the rendered ip coi forward chain, or "" if it
// cannot be listed.
func coiForwardChainText(t *testing.T) string {
	t.Helper()
	out, err := runNFTCommand("list", "chain", "ip", "coi", "forward")
	if err != nil {
		return ""
	}
	return string(out)
}

// TestSetupPurgesStaleRulesForReusedIP reproduces the DHCP-IP-reuse stale-rule
// inheritance bug. Rules in the ip coi forward chain are keyed by container IP
// (comment "coi-<IP>"). Incus DHCP recycles leases, so a new container can reuse
// a prior container's IP; if the prior container's rules were orphaned (unclean
// teardown), and the chain is evaluated first-match-wins, an inherited blanket
// ACCEPT would let a restricted successor bypass its filter.
//
// We simulate an orphan with a uniquely fingerprinted ACCEPT rule (a TEST-NET-3
// destination a real restricted setup never produces), then run SetupForContainer
// for that IP and assert the fingerprint rule is gone — i.e. setup purges
// coi-<IP> before applying the current policy.
func TestSetupPurgesStaleRulesForReusedIP(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}
	if exists, err := container.ImageExists("coi-default"); err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	containerName := "coi-stale-purge-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() { cleanupTestContainer(t, containerName) })

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}
	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
	}
	time.Sleep(3 * time.Second)

	containerIP, err := GetContainerIP(containerName)
	if err != nil {
		t.Fatalf("Failed to get container IP: %v", err)
	}

	// Simulate an orphaned rule from a previous container that held this IP.
	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — never a real resolved address.
	const fingerprint = "203.0.113.7"
	stale := NewNftManager(containerIP, "")
	if err := stale.addRule(containerIP, fingerprint+"/32", "accept"); err != nil {
		t.Fatalf("Failed to inject stale rule: %v", err)
	}
	if !strings.Contains(coiForwardChainText(t), fingerprint) {
		t.Fatalf("precondition failed: injected stale rule (%s) not present in chain", fingerprint)
	}

	// A "new container" reuses the IP and is set up in restricted mode.
	netCfg := &config.NetworkConfig{Mode: config.NetworkModeRestricted}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}
	t.Cleanup(func() { _ = netMgr.Teardown(context.Background(), containerName) })

	// The stale rule must have been purged before the restricted policy was applied.
	if strings.Contains(coiForwardChainText(t), fingerprint) {
		t.Errorf("stale coi-%s rule (%s) survived setup — DHCP-reuse inheritance not purged",
			containerIP, fingerprint)
	}
	// And the current policy must actually be in place (sanity check).
	if countRulesForIP(t, containerIP) == 0 {
		t.Errorf("no nft rules present for %s after restricted setup", containerIP)
	}
}
