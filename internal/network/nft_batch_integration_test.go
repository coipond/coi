//go:build integration

package network

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// These run against the real nft with a made-up container IP (no Incus
// needed): they pin that batching changes HOW rules are applied, never WHICH
// rules or in what order.

const batchTestIP = "10.253.7.9"

func requireNft(t *testing.T) {
	t.Helper()
	if !NftAvailable() {
		t.Skip("nft not available")
	}
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(batchTestIP) })
	_ = DeleteCOIFilterRulesForIP(batchTestIP)
}

func ruleTexts(t *testing.T) []string {
	t.Helper()
	rules, err := forwardRulesWithComment("coi-" + batchTestIP)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rules {
		out = append(out, r.text)
	}
	return out
}

func restrictedTestConfig() *config.NetworkConfig {
	tr := true
	return &config.NetworkConfig{
		Mode:                  config.NetworkModeRestricted,
		BlockPrivateNetworks:  &tr,
		BlockMetadataEndpoint: &tr,
		DNSServers:            []string{"1.1.1.1"},
		AllowedPorts:          []int{443, 22},
	}
}

// The batched transaction installs exactly the rules, in exactly the order,
// that the old one-exec-per-rule path did.
func TestApplyRestricted_BatchMatchesPerRule_Integration(t *testing.T) {
	requireNft(t)
	cfg := restrictedTestConfig()
	dns, err := validateDNSServers(cfg.DNSServers)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := validateAllowedPorts(cfg.AllowedPorts)
	if err != nil {
		t.Fatal(err)
	}

	f := NewNftManager(batchTestIP, "10.253.7.1")
	if err := EnsureBaseRules(); err != nil {
		t.Fatal(err)
	}
	if err := f.addRestrictedRules(cfg, dns, ports); err != nil { // not batching: one exec per rule
		t.Fatal(err)
	}
	perRule := ruleTexts(t)
	_ = DeleteCOIFilterRulesForIP(batchTestIP)

	if err := f.ApplyRestricted(cfg); err != nil {
		t.Fatal(err)
	}
	batched := ruleTexts(t)
	if len(perRule) == 0 || strings.Join(perRule, "\n") != strings.Join(batched, "\n") {
		t.Errorf("batched rules differ from per-rule rules:\nper-rule:\n%s\nbatched:\n%s",
			strings.Join(perRule, "\n"), strings.Join(batched, "\n"))
	}
}

// Replacing deletes the IP's previous rules and adds the new ones in one
// transaction: the stale rule is gone and the full policy is present.
func TestApplyRestricted_ReplacesStaleRulesAtomically_Integration(t *testing.T) {
	requireNft(t)
	if err := EnsureBaseRules(); err != nil {
		t.Fatal(err)
	}
	stale := []string{
		"add", "rule", "ip", "coi", "forward", "ip", "saddr", batchTestIP,
		"ip", "daddr", "203.0.113.77", "accept", "comment", `"coi-` + batchTestIP + `"`,
	}
	if _, err := runNFTCommand(stale...); err != nil {
		t.Fatal(err)
	}

	m := NewManager(restrictedTestConfig(), logger.NewDiscard())
	m.nft = NewNftManager(batchTestIP, "10.253.7.1")
	if err := m.applyRestrictedReplacing(batchTestIP); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ruleTexts(t), "\n")
	if strings.Contains(got, "203.0.113.77") {
		t.Errorf("stale rule survived:\n%s", got)
	}
	if !strings.Contains(got, "reject") || !strings.Contains(got, "10.0.0.0/8") {
		t.Errorf("restricted policy missing:\n%s", got)
	}
}

// Open mode on a reused container whose accept rule is already in place is a
// no-op — which also pins openModeRuleText to how nft really lists the rule.
func TestApplyOpenRules_ReuseIsNoop_Integration(t *testing.T) {
	requireNft(t)
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen}, logger.NewDiscard())

	m.applyOpenRules(batchTestIP)
	first, err := forwardRulesWithComment("coi-" + batchTestIP)
	if err != nil || len(first) != 1 || first[0].text != openModeRuleText(batchTestIP) {
		t.Fatalf("open rule not as expected: %+v (err %v); want text %q", first, err, openModeRuleText(batchTestIP))
	}

	m.applyOpenRules(batchTestIP)
	second, _ := forwardRulesWithComment("coi-" + batchTestIP)
	if len(second) != 1 || second[0].handle != first[0].handle {
		t.Errorf("reuse must keep the existing rule (handle %s), got %+v", first[0].handle, second)
	}

	// A restricted leftover for the IP is replaced by the open rule.
	_ = DeleteCOIFilterRulesForIP(batchTestIP)
	if err := NewNftManager(batchTestIP, "").ApplyRestricted(restrictedTestConfig()); err != nil {
		t.Fatal(err)
	}
	m.applyOpenRules(batchTestIP)
	got := ruleTexts(t)
	if len(got) != 1 || got[0] != openModeRuleText(batchTestIP) {
		t.Errorf("leftover restricted rules must be replaced by the open rule, got %v", got)
	}
}
