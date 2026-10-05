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

// skipUnlessAllowlistReady skips the test if Incus, nft, or the coi image are absent.
func skipUnlessAllowlistReady(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	if !NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}
}

// verifyTeardownRemovesRules queries the nft chain after teardown and fails the
// test if any rules for containerIP remain. It also fails if the chain query
// itself returns an unexpected error (a missing chain means successful cleanup,
// any other error means we can't confirm the rules are gone).
func verifyTeardownRemovesRules(t *testing.T, containerIP string) {
	t.Helper()
	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		// The chain not existing after teardown is acceptable in some implementations.
		// Any other error means we cannot confirm cleanup — fail explicitly.
		if !strings.Contains(err.Error(), "No such file or directory") &&
			!strings.Contains(err.Error(), "does not exist") {
			t.Errorf("Could not verify teardown: nft chain query failed: %v", err)
		}
		return
	}
	comment := `comment "coi-` + containerIP + `"`
	if strings.Contains(string(output), comment) {
		t.Errorf("Rules for container IP %s still present in nft chain after teardown", containerIP)
	}
}

// TestAllowlistModeCIDRRule_Integration verifies that a CIDR entry in
// allowed_domains (e.g. "203.0.113.0/24") produces an nftables rule with the
// CIDR intact — not mangled into "203.0.113.0/24/32" — and that the rule is
// removed cleanly on teardown.
func TestAllowlistModeCIDRRule_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — documentation-only, never routed.
	const testCIDR = "203.0.113.0/24"

	containerName := "coi-allowlist-cidr-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

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
	t.Logf("Container IP: %s", containerIP)

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{testCIDR},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	// Query the actual nftables chain and look for the CIDR rule.
	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("Failed to list nft chain: %v", err)
	}
	rules := string(output)
	t.Logf("nft chain output:\n%s", rules)

	// The CIDR must appear verbatim in the ruleset.
	if !strings.Contains(rules, testCIDR) {
		t.Errorf("Expected CIDR %q to appear in nft rules, but it did not.\nRules:\n%s", testCIDR, rules)
	}

	// Guard against the regression: appending /32 to a CIDR produces "203.0.113.0/24/32".
	if strings.Contains(rules, testCIDR+"/32") {
		t.Errorf("Regression: found mangled CIDR %q in nft rules — /32 was incorrectly appended.\nRules:\n%s", testCIDR+"/32", rules)
	}

	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	verifyTeardownRemovesRules(t, containerIP)
}

// TestAllowlistModeWildcardDomain_Integration verifies that a wildcard domain
// entry (e.g. "*.example.com") resolves the base domain and installs /32 rules
// for its IPs — not a literal "*.example.com" string that would corrupt nftables.
func TestAllowlistModeWildcardDomain_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	containerName := "coi-allowlist-wildcard-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

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
	t.Logf("Container IP: %s", containerIP)

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{"*.example.com"},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("Failed to list nft chain: %v", err)
	}
	rules := string(output)
	t.Logf("nft chain output:\n%s", rules)

	// The literal wildcard string must never appear in nftables — it is not a valid IP/CIDR.
	if strings.Contains(rules, "*.example.com") {
		t.Errorf("Literal wildcard string \"*.example.com\" appeared in nft rules — it should have been resolved to IPs")
	}

	// There should be at least one rule for this container (the base domain resolved to IPs).
	comment := `comment "coi-` + containerIP + `"`
	if !strings.Contains(rules, comment) {
		t.Errorf("Expected at least one rule with comment %q, but found none.\nRules:\n%s", comment, rules)
	}

	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}

	verifyTeardownRemovesRules(t, containerIP)
}

// TestAllowlistModeIPv4MappedIPv6CIDRRejected_Integration verifies that an
// IPv4-mapped IPv6 CIDR (e.g. ::ffff:0:0/96) is rejected by SetupForContainer
// and does NOT produce a catch-all nftables rule that neutralises the allowlist.
//
// Without the len(ipNet.IP) guard, net.ParseCIDR("::ffff:0:0/96") returns
// a 16-byte net.IP whose To4() is non-nil, normalised to 0.0.0.0/0.
// That value reaches addRule with no ip-daddr match, accepting all traffic.
func TestAllowlistModeIPv4MappedIPv6CIDRRejected_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	containerName := "coi-allowlist-ipv6mapped-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

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
	t.Logf("Container IP: %s", containerIP)

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{"::ffff:0:0/96"},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())

	// SetupForContainer should fail: the IPv4-mapped IPv6 CIDR must be rejected.
	setupErr := netMgr.SetupForContainer(context.Background(), containerName)
	if setupErr == nil {
		// If setup unexpectedly succeeded, confirm no catch-all rule was installed.
		output, nftErr := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
		if nftErr == nil {
			rules := string(output)
			t.Logf("nft chain output:\n%s", rules)
			// 0.0.0.0/0 without ip daddr means accept-all — the bypass.
			if strings.Contains(rules, "0.0.0.0/0") {
				t.Errorf("SECURITY: catch-all 0.0.0.0/0 rule found in nft chain — IPv4-mapped IPv6 CIDR bypass not fixed")
			}
		}
		_ = netMgr.Teardown(context.Background(), containerName)
		t.Errorf("SetupForContainer should have failed for IPv4-mapped IPv6 CIDR ::ffff:0:0/96, but returned nil")
	} else {
		t.Logf("SetupForContainer correctly rejected ::ffff:0:0/96: %v", setupErr)
	}
}

// TestAllowlistModeL4Filtering_Integration verifies that allowlist-mode accept
// rules are scoped to TCP/UDP plus a rate-limited ICMP echo rule, so non-TCP/UDP
// protocols and ICMP tunneling to allowed hosts fall through to the default deny.
func TestAllowlistModeL4Filtering_Integration(t *testing.T) {
	skipUnlessAllowlistReady(t)

	const testCIDR = "203.0.113.0/24" // TEST-NET-3 (RFC 5737)

	containerName := "coi-allowlist-l4-test"
	mgr := container.NewManager(containerName)

	t.Cleanup(func() {
		cleanupTestContainer(t, containerName)
	})

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

	netCfg := &config.NetworkConfig{
		Mode:           config.NetworkModeAllowlist,
		AllowedDomains: []string{testCIDR},
	}
	netMgr := NewManager(netCfg, logger.NewDiscard())
	if err := netMgr.SetupForContainer(context.Background(), containerName); err != nil {
		t.Fatalf("SetupForContainer failed: %v", err)
	}

	output, err := runNFTCommand("-a", "list", "chain", "ip", "coi", "forward")
	if err != nil {
		t.Fatalf("Failed to list nft chain: %v", err)
	}
	rules := string(output)
	t.Logf("nft chain:\n%s", rules)

	// Bind the L4-scoping assertions to the rule lines for THIS test's CIDR
	// (TEST-NET-3, unique to this test), not the whole shared chain — otherwise a
	// leftover/concurrent allowlist rule could satisfy the substrings even if this
	// container's accept rule were emitted unscoped.
	var cidrRules []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.Contains(line, testCIDR) {
			cidrRules = append(cidrRules, line)
		}
	}
	if len(cidrRules) == 0 {
		t.Fatalf("expected allow rules for %q:\n%s", testCIDR, rules)
	}
	cidrJoined := strings.Join(cidrRules, "\n")
	if !strings.Contains(cidrJoined, "l4proto") {
		t.Errorf("expected TCP/UDP (l4proto) scoping on the %s allow rule:\n%s", testCIDR, cidrJoined)
	}
	if !strings.Contains(cidrJoined, "echo-request") || !strings.Contains(cidrJoined, "10/second") {
		t.Errorf("expected rate-limited (10/second) ICMP echo-request on the %s allow rule:\n%s", testCIDR, cidrJoined)
	}

	if err := netMgr.Teardown(context.Background(), containerName); err != nil {
		t.Errorf("Teardown failed: %v", err)
	}
	verifyTeardownRemovesRules(t, containerIP)
}
