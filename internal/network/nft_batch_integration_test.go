//go:build integration

package network

import (
	"os/exec"
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

// allRuleTexts is ruleTexts for the forward and the input chain.
func allRuleTexts(t *testing.T) []string {
	t.Helper()
	rules, _, err := coiChainRules("coi-" + batchTestIP)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, chain := range []string{"forward", "input"} {
		for _, r := range rules[chain] {
			out = append(out, chain+": "+r.text)
		}
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
	perRule := allRuleTexts(t)
	_ = DeleteCOIFilterRulesForIP(batchTestIP)

	if err := f.ApplyRestricted(cfg); err != nil {
		t.Fatal(err)
	}
	batched := allRuleTexts(t)
	if !strings.Contains(strings.Join(batched, "\n"), "input: ") {
		t.Errorf("restricted mode must install input rules:\n%s", strings.Join(batched, "\n"))
	}
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

// Under block_metadata_endpoint open mode's reuse check still holds, which
// pins openModeRuleTexts to how nft really lists the rules.
func TestApplyOpenRules_MetadataBlock_Integration(t *testing.T) {
	requireNft(t)
	on := true
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen, BlockMetadataEndpoint: &on}, logger.NewDiscard())
	_ = DeleteCOIFilterRulesForIP(batchTestIP)

	m.applyOpenRules(batchTestIP)
	first, err := forwardRulesWithComment("coi-" + batchTestIP)
	if err != nil || !ruleTextsEqual(first, openModeRuleTexts(batchTestIP, true)) {
		t.Fatalf("open rules = %+v (err %v), want texts %q", first, err, openModeRuleTexts(batchTestIP, true))
	}
	m.applyOpenRules(batchTestIP)
	second, _ := forwardRulesWithComment("coi-" + batchTestIP)
	if len(second) != len(first) || second[0].handle != first[0].handle {
		t.Errorf("reuse must keep the existing rules, got %+v", second)
	}
}

// coi run's lean open-mode path: its script applies on real nft, a second
// listing finds the rules in place, a stale rule of another mode is replaced,
// and Teardown removes the container's rules.
func TestOpenMetadataBlock_Integration(t *testing.T) {
	requireNft(t)
	_ = DeleteCOIFilterRulesForIP(batchTestIP)
	_, _ = runNFTCommand("delete", "table", "ip", "coi") // first container on the host
	listing := func() string {
		out, _ := runNFTCommand("-a", "list", "table", "ip", "coi")
		return string(out)
	}
	if err := applyOpenMetadataRules(batchTestIP); err != nil {
		t.Fatal(err)
	}
	first := listing()
	if err := applyOpenMetadataRules(batchTestIP); err != nil {
		t.Fatal(err)
	}
	if second := listing(); second != first {
		t.Fatalf("second apply must find the rules in place:\n%s\nthen:\n%s", first, second)
	}
	if err := NewNftManager(batchTestIP, "").ApplyRestricted(restrictedTestConfig()); err != nil {
		t.Fatal(err)
	}
	if err := applyOpenMetadataRules(batchTestIP); err != nil {
		t.Fatal(err)
	}
	got, _ := forwardRulesWithComment("coi-" + batchTestIP)
	if !ruleTextsEqual(got, openModeRuleTexts(batchTestIP, true)) {
		t.Fatalf("rules = %+v, want %q", got, openModeRuleTexts(batchTestIP, true))
	}
	if err := (&OpenMetadataBlock{ip: batchTestIP}).Teardown(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := forwardRulesWithComment("coi-" + batchTestIP); len(got) != 0 {
		t.Errorf("teardown left %+v", got)
	}
}

// Teardown removes everything the container owns — its policy rules, the
// IPv6 drop, a residual boot block and the coi6-<name> rule older coi versions
// put in the ip6 forward chain — in one transaction.
func TestTeardownRulesAtomically_Integration(t *testing.T) {
	requireNft(t)
	const name = "coi-batch-teardown-test"
	if err := NewNftManager(batchTestIP, "10.253.7.1").ApplyRestricted(restrictedTestConfig()); err != nil {
		t.Fatal(err)
	}
	// The netdev chains need a real device to hook: a dummy stands in for the
	// veth.
	const dev = "coibatchtest0"
	if out, err := exec.Command("sudo", "-n", "ip", "link", "add", dev, "type", "dummy").CombinedOutput(); err != nil {
		t.Fatalf("cannot create dummy device: %v (%s)", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("sudo", "-n", "ip", "link", "del", dev).Run() })
	if err := installVethIngressChain(bootBlockComment(name), dev, bootBlockRules); err != nil {
		t.Fatal(err)
	}
	if err := installVethIngressChain(ipv6BlockComment(name), dev, ipv6BlockRules); err != nil {
		t.Fatal(err)
	}
	if err := runNFTScript([][]string{
		{"add", "table", "ip6", "coi"},
		{"add", "chain", "ip6", "coi", "forward", "{", "type", "filter", "hook", "forward", "priority", "10", ";", "policy", "accept", ";", "}"},
		{"add", "rule", "ip6", "coi", "forward", "iifname", `"` + dev + `"`, "drop", "comment", `"` + ipv6BlockComment(name) + `"`},
	}); err != nil {
		t.Fatal(err)
	}

	m := NewManager(restrictedTestConfig(), logger.NewDiscard())
	m.nft = NewNftManager(batchTestIP, "10.253.7.1")
	if !m.teardownRulesAtomically(name) {
		t.Fatal("atomic teardown did not handle it")
	}
	if got := ruleTexts(t); len(got) != 0 {
		t.Errorf("policy rules left: %v", got)
	}
	if got := netdevChain(bootBlockComment(name)); got != "" {
		t.Errorf("boot block left:\n%s", got)
	}
	if got := netdevChain(ipv6BlockComment(name)); got != "" {
		t.Errorf("IPv6 drop left:\n%s", got)
	}
	if v6, _ := runNFTCommand("list", "chain", "ip6", "coi", "forward"); strings.Contains(string(v6), ipv6BlockComment(name)) {
		t.Errorf("legacy IPv6 rule left:\n%s", v6)
	}
}

// A chain left on an earlier veth is rebound to the new one; one already on
// the current veth is kept.
func TestInstallVethIngressChain_RebindsStaleDevice_Integration(t *testing.T) {
	requireNft(t)
	const chain = "coi6-coi-rebind-test"
	for _, dev := range []string{"coirebind0", "coirebind1"} {
		if out, err := exec.Command("sudo", "-n", "ip", "link", "add", dev, "type", "dummy").CombinedOutput(); err != nil {
			t.Fatalf("cannot create dummy device: %v (%s)", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("sudo", "-n", "ip", "link", "del", dev).Run() })
	}
	t.Cleanup(func() { _ = deleteVethIngressChain(chain) })

	for _, dev := range []string{"coirebind0", "coirebind0", "coirebind1"} {
		if err := installVethIngressChain(chain, dev, ipv6BlockRules); err != nil {
			t.Fatal(err)
		}
		got := netdevChain(chain)
		if ingressChainDevice(got) != dev || strings.Count(got, " drop ") != 1 {
			t.Errorf("after install on %s:\n%s", dev, got)
		}
	}
	if err := deleteVethIngressChain(chain); err != nil {
		t.Fatal(err)
	}
	if err := deleteVethIngressChain(chain); err != nil {
		t.Errorf("deleting a missing chain: %v", err)
	}
}
