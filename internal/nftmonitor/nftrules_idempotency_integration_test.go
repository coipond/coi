//go:build integration

package nftmonitor

import (
	"os/exec"
	"strings"
	"testing"
)

// sudoNftAvailable reports whether real nft can be driven via passwordless sudo.
func sudoNftAvailable() bool {
	return exec.Command("sudo", "-n", "nft", "list", "ruleset").Run() == nil
}

// countMonitorRulesForIP counts NFT_COI/NFT_DNS/NFT_SUSPICIOUS LOG rules in
// ip filter FORWARD whose bracketed token is exactly ip.
func countMonitorRulesForIP(t *testing.T, ip string) int {
	t.Helper()
	out, err := exec.Command("sudo", "-n", "nft", "-a", "list", "chain", "ip", "filter", "FORWARD").Output()
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		for _, prefix := range []string{"NFT_COI[", "NFT_DNS[", "NFT_SUSPICIOUS["} {
			if strings.Contains(line, prefix+ip+"]") {
				n++
				break
			}
		}
	}
	return n
}

// TestAddRules_Idempotent proves the #696 item-3a guard: running AddRules twice
// for the same container IP must not stack duplicate LOG rules in
// ip filter FORWARD. Uses a TEST-NET-3 IP so it never touches real container
// rules. Requires real nft + passwordless sudo; skips otherwise.
func TestAddRules_Idempotent(t *testing.T) {
	if !sudoNftAvailable() {
		t.Skip("nft with passwordless sudo not available, skipping integration test")
	}

	const testIP = "203.0.113.7" // TEST-NET-3, safe fingerprint
	rm := NewRuleManager(&Config{ContainerIP: testIP, LogDNSQueries: true})

	// Clean slate + guaranteed teardown (RemoveRules errors when nothing matches;
	// that's fine here).
	_ = rm.RemoveRules()
	t.Cleanup(func() { _ = rm.RemoveRules() })

	if err := rm.AddRules(); err != nil {
		t.Fatalf("first AddRules failed: %v", err)
	}
	first := countMonitorRulesForIP(t, testIP)
	if first == 0 {
		t.Fatalf("expected LOG rules for %s after first AddRules, found none", testIP)
	}

	if err := rm.AddRules(); err != nil {
		t.Fatalf("second AddRules failed: %v", err)
	}
	second := countMonitorRulesForIP(t, testIP)
	if second != first {
		t.Errorf("AddRules is not idempotent: %d rules after first call, %d after second (#696 item 3a)", first, second)
	}
}

// TestRemoveRules_ConcurrentRemovers: the session supervisor and coi container
// delete / kill cleanup remove the same IP's rules at the same time. A remover
// that loses the race on one handle must still remove the rest, and losing a
// race (the rule is already gone) is not an error.
func TestRemoveRules_ConcurrentRemovers(t *testing.T) {
	if !sudoNftAvailable() {
		t.Skip("nft with passwordless sudo not available, skipping integration test")
	}

	const testIP = "203.0.113.8" // TEST-NET-3, safe fingerprint
	cfg := &Config{ContainerIP: testIP, LogDNSQueries: true}
	_ = NewRuleManager(cfg).RemoveRules()
	t.Cleanup(func() { _ = NewRuleManager(cfg).RemoveRules() })

	for i := 0; i < 10; i++ {
		if err := NewRuleManager(cfg).AddRules(); err != nil {
			t.Fatalf("AddRules: %v", err)
		}
		errs := make(chan error, 2)
		for j := 0; j < 2; j++ {
			go func() { errs <- NewRuleManager(cfg).RemoveRules() }()
		}
		for j := 0; j < 2; j++ {
			// "no NFT rules found" is the loser's normal outcome when the other
			// remover took every rule before it listed.
			if err := <-errs; err != nil && !strings.Contains(err.Error(), "no NFT rules found") {
				t.Errorf("iteration %d: concurrent RemoveRules failed: %v", i, err)
			}
		}
		if n := countMonitorRulesForIP(t, testIP); n != 0 {
			t.Fatalf("iteration %d: %d LOG rules for %s left after concurrent removal", i, n, testIP)
		}
	}
}
