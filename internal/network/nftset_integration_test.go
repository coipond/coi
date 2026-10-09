//go:build integration

package network

import (
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
)

// These tests drive the real nft binary. They do not need Incus or a live
// container: every rule is keyed on a source address, so a synthetic address
// exercises the exact code path a real container would take.
const testContainerIP = "10.99.99.99"

const testGatewayIP = "10.99.99.1"

// testRefreshInterval is a representative enabled-refresh cadence, so dynamic
// elements are installed with a timeout (not permanently) as they are in a real
// allowlist session.
const testRefreshInterval = 30 * time.Minute

func skipUnlessNft(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not found, skipping nft integration test")
	}
	if err := exec.Command("sudo", "-n", "nft", "list", "tables").Run(); err != nil {
		t.Skip("passwordless sudo for nft unavailable, skipping nft integration test")
	}
}

func nftDump(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("sudo", "-n", "nft", "list", "table", "ip", "coi").CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func applyTestAllowlist(t *testing.T, f *NftManager, staticCIDRs []string) {
	t.Helper()
	// Mirror production: the manager derives staticCIDRs from cfg.AllowedDomains, and
	// ApplyAllowlist re-reads cfg.AllowedDomains to build the port-scoped tuples — so
	// the two must be the same source, or the tuple set (L4) and address set (ICMP)
	// diverge.
	cfg := &config.NetworkConfig{Mode: config.NetworkModeAllowlist, AllowedDomains: staticCIDRs}
	if err := f.ApplyAllowlist(cfg, staticCIDRs); err != nil {
		t.Fatalf("ApplyAllowlist: %v", err)
	}
}

// TestAllowlistSets_Lifecycle exercises the set-based allowlist end to end
// against the real kernel: rules reference the sets, static and resolved
// addresses land in the right set, and teardown removes both rules and sets.
func TestAllowlistSets_Lifecycle(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })

	applyTestAllowlist(t, f, []string{"8.8.8.8/32", "192.0.2.0/24"})

	dump := nftDump(t)

	// The rules must name the sets, not individual addresses. That is what makes
	// them stable for the container's lifetime and lets updates be pure element
	// operations, with no window where a stale reject shadows a fresh accept.
	for _, want := range []string{
		"@" + staticSetName(testContainerIP),      // address set (ICMP + monitor)
		"@" + dynamicSetName(testContainerIP),     // address set (ICMP + monitor)
		"@" + staticPortSetName(testContainerIP),  // port-scoped set (L4)
		"@" + dynamicPortSetName(testContainerIP), // port-scoped set (L4)
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("expected a rule referencing %s\n%s", want, dump)
		}
	}

	for _, want := range []string{"8.8.8.8", "192.0.2.0/24"} {
		if !strings.Contains(dump, want) {
			t.Errorf("expected static element %s in the ruleset\n%s", want, dump)
		}
	}

	if !strings.Contains(dump, "reject") {
		t.Errorf("expected a default reject rule\n%s", dump)
	}

	if err := f.AllowDynamicIPsPorts([]string{"172.217.112.4"}, []portRange{{Lo: 443, Hi: 443}}, 300, testRefreshInterval); err != nil {
		t.Fatalf("AllowDynamicIPsPorts: %v", err)
	}
	dump = nftDump(t)
	if !strings.Contains(dump, "172.217.112.4") {
		t.Errorf("expected the resolved address in the dynamic set\n%s", dump)
	}
	if !strings.Contains(dump, "timeout") {
		t.Errorf("dynamic elements must carry a timeout so a rotated-out address expires\n%s", dump)
	}
	// The port-scoped tuple must land in the dynamic concatenated set too, so the
	// L4 accept reaches the resolved address only on its permitted port.
	if !strings.Contains(dump, "172.217.112.4 . 443") {
		t.Errorf("expected the resolved address·port tuple in the dynamic port set\n%s", dump)
	}

	// Teardown must remove the rules *and* the sets. The kernel refuses to drop a
	// set that a rule still references, so getting this order wrong leaks sets
	// across container restarts.
	if err := f.RemoveRules(); err != nil {
		t.Fatalf("RemoveRules: %v", err)
	}
	dump = nftDump(t)
	if strings.Contains(dump, testContainerIP) {
		t.Errorf("rules for %s survived teardown\n%s", testContainerIP, dump)
	}
	for _, set := range []string{
		staticSetName(testContainerIP), dynamicSetName(testContainerIP),
		staticPortSetName(testContainerIP), dynamicPortSetName(testContainerIP),
	} {
		if strings.Contains(dump, set) {
			t.Errorf("set %s survived teardown\n%s", set, dump)
		}
	}
}

// TestAllowlistPerDestinationPorts is the Phase 3 guard: each allowed_domains
// entry's ports land in the concatenated set as the right address·port tuple, a
// bare entry inherits the global allowed_ports, and the L4 accept matches the set
// via `ip daddr . th dport`.
func TestAllowlistPerDestinationPorts(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })

	cfg := &config.NetworkConfig{
		Mode:         config.NetworkModeAllowlist,
		AllowedPorts: []int{443}, // the global cap a bare entry inherits
		AllowedDomains: []string{
			"8.8.8.8:53",             // literal, explicit single port
			"192.0.2.0/24:8000-8100", // literal CIDR, port range
			"1.1.1.1",                // bare -> inherits global 443
		},
	}
	policy, err := NewAllowPolicy(cfg.AllowedDomains)
	if err != nil {
		t.Fatalf("NewAllowPolicy: %v", err)
	}
	if err := f.ApplyAllowlist(cfg, policy.StaticCIDRs()); err != nil {
		t.Fatalf("ApplyAllowlist: %v", err)
	}

	dump := nftDump(t)

	// Each destination is reachable only on its own ports.
	for _, want := range []string{
		"8.8.8.8 . 53",
		"192.0.2.0/24 . 8000-8100",
		"1.1.1.1 . 443", // bare entry inherited the global allowed_ports
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("expected tuple %q in the port-scoped set\n%s", want, dump)
		}
	}
	// The bare entry must NOT be reachable on all ports: no 1-65535 tuple for it.
	if strings.Contains(dump, "1.1.1.1 . 1-65535") {
		t.Errorf("bare entry with a global cap must not be all-ports\n%s", dump)
	}
	// The L4 accept matches the concatenated set, not a bare address set.
	if !strings.Contains(dump, "th dport @"+staticPortSetName(testContainerIP)) {
		t.Errorf("L4 accept must match the port-scoped set via th dport\n%s", dump)
	}
}

// TestHostFirewallPerHostPorts is the Phase 4 guard: a restricted-mode
// [[network.hosts]] entry's targeted allow is scoped to the entry's OWN ports —
// entry ports override the global cap, and an entry with no ports falls back to it.
func TestHostFirewallPerHostPorts(t *testing.T) {
	skipUnlessNft(t)

	const cip = "10.99.99.99"
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(cip) })
	if err := ensureCOITableAndChain(); err != nil {
		t.Fatalf("ensureCOITableAndChain: %v", err)
	}

	cases := []struct {
		ip        string
		entryPort []int
		global    []int
		wantPort  string
	}{
		{"192.168.5.5", []int{443}, nil, "443"},         // entry ports, no global
		{"192.168.6.6", nil, []int{80}, "80"},           // no entry ports -> inherit global
		{"192.168.7.7", []int{8443}, []int{80}, "8443"}, // entry ports override global
	}
	for _, c := range cases {
		entry := config.HostEntry{IP: c.ip, Hostnames: []string{"h.local"}, Ports: c.entryPort}
		if err := applyHostFirewall(config.NetworkModeRestricted, false, cip, entry, c.global); err != nil {
			t.Fatalf("applyHostFirewall(%s): %v", c.ip, err)
		}
	}

	dump := nftDump(t)
	for _, c := range cases {
		line := ""
		for _, ln := range strings.Split(dump, "\n") {
			if strings.Contains(ln, "ip daddr "+c.ip) && strings.Contains(ln, "accept") {
				line = ln
				break
			}
		}
		if line == "" {
			t.Errorf("no targeted accept rule for host %s\n%s", c.ip, dump)
			continue
		}
		// Word-boundary match so "8443" doesn't satisfy a check for "443".
		portRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(c.wantPort) + `\b`)
		if !strings.Contains(line, "dport") || !portRe.MatchString(line) {
			t.Errorf("host %s must be scoped to port %s: %s", c.ip, c.wantPort, line)
		}
		if c.ip == "192.168.7.7" && regexp.MustCompile(`\b80\b`).MatchString(line) {
			t.Errorf("entry ports must OVERRIDE the global cap (not fall back to 80): %s", line)
		}
	}
}

// TestApplyAllowlist_BlocksDNSInBothChains is the guard for the invariant the
// whole mode rests on: the container has no route to a nameserver, so the
// /etc/hosts file Coi writes is its only way to turn a name into an address. Give
// it any resolver and it can learn an address the firewall has never seen — the
// exact host/container divergence that made allowlist mode flap against rotating
// cloud frontends.
//
// It takes two chains, and missing either leaves the hole wide open:
//
//   - forward, for an off-box resolver like 8.8.8.8;
//   - input, for the bridge's own dnsmasq — that traffic is addressed to the HOST,
//     so it is delivered via the input hook and never traverses the forward chain
//     at all. This is the easy one to forget, and forgetting it would silently
//     make everything else pointless.
func TestApplyAllowlist_BlocksDNSInBothChains(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })

	applyTestAllowlist(t, f, nil)

	forward := nftDump(t)
	if !strings.Contains(forward, "dport 53") {
		t.Errorf("forward chain must reject DNS to off-box resolvers\n%s", forward)
	}

	// The DNS reject has to precede the set-accept rules. A resolver that happens
	// to sit inside an allowlisted CIDR would otherwise be reachable on port 53
	// and could hand the container any address it liked.
	dnsAt := strings.Index(forward, "dport 53")
	// The port-scoped set backs the L4 accept, which is the FIRST set-accept rule —
	// so it is the one the DNS/metadata rejects must precede.
	setAt := strings.Index(forward, "@"+staticPortSetName(testContainerIP))
	if dnsAt == -1 || setAt == -1 || dnsAt > setAt {
		t.Errorf("the DNS reject must come BEFORE the allowlist set rules, or a resolver inside an "+
			"allowlisted CIDR stays reachable on port 53\n%s", forward)
	}

	// H1 regression: the RFC1918 / link-local (cloud-metadata) reject must ALSO
	// precede the set-accept rules. An allowlisted name that resolves (or is
	// rebound) to 169.254.169.254 or an RFC1918 address would otherwise be matched
	// by the set-accept before the reject runs — a path to the metadata endpoint
	// (credential theft) or internal hosts.
	metaAt := strings.Index(forward, "169.254.0.0/16")
	if metaAt == -1 || metaAt > setAt {
		t.Errorf("the RFC1918/metadata reject must come BEFORE the allowlist set rules, or an "+
			"allowlisted name resolving into a private/metadata range reaches it\n%s", forward)
	}

	out, err := exec.Command("sudo", "-n", "nft", "list", "chain", "ip", "coi", "input").CombinedOutput()
	if err != nil {
		t.Fatalf("the coi input chain must exist — without it the container simply asks the bridge's "+
			"dnsmasq and resolves whatever it likes: %v", err)
	}
	input := string(out)
	if !strings.Contains(input, testContainerIP) || !strings.Contains(input, "dport 53") {
		t.Errorf("input chain must block the container's DNS to the bridge resolver\n%s", input)
	}
}

// TestAllowDynamicIPs_IsIdempotent verifies that re-adding an address refreshes
// its timeout rather than failing, so the refresher can run repeatedly.
func TestAllowDynamicIPs_IsIdempotent(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })
	applyTestAllowlist(t, f, nil)

	for i := 0; i < 3; i++ {
		if err := f.AllowDynamicIPsPorts([]string{"172.217.112.4"}, allPortsRange(), 300, testRefreshInterval); err != nil {
			t.Fatalf("AllowDynamicIPs call %d: %v", i+1, err)
		}
	}

	if got := len(f.dynSeenSnapshot()); got != 1 {
		t.Errorf("expected 1 tracked address, got %d", got)
	}
	if !strings.Contains(nftDump(t), "172.217.112.4") {
		t.Error("the address should be present after repeated adds")
	}
}

// TestAllowDynamicIPs_ConcurrentCallersNeverAnswerBeforeInstall guards the
// install-before-use invariant under concurrency.
//
// An earlier version recorded addresses in its bookkeeping map, released the
// lock, and only then shelled out to nft — so a second caller saw them as already
// installed, skipped the nft call, and returned while the first caller's exec was
// still running. Anything acting on that return would have been working with an
// address the kernel did not yet have.
func TestAllowDynamicIPs_ConcurrentCallersNeverAnswerBeforeInstall(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })
	applyTestAllowlist(t, f, nil)

	const goroutines = 8
	ips := []string{"172.217.112.4", "172.217.113.4"}

	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	missing := make([]string, goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start // maximise overlap
			if err := f.AllowDynamicIPsPorts(ips, allPortsRange(), 300, testRefreshInterval); err != nil {
				errs[n] = err
				return
			}
			// AllowDynamicIPs has returned, so the kernel must already hold every
			// address this caller was told about.
			out, err := exec.Command("sudo", "-n", "nft", "list", "set", "ip", "coi",
				dynamicSetName(testContainerIP)).CombinedOutput()
			if err != nil {
				errs[n] = err
				return
			}
			for _, ip := range ips {
				if !strings.Contains(string(out), ip) {
					missing[n] = ip
					return
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if missing[i] != "" {
			t.Errorf("goroutine %d returned from AllowDynamicIPs while %s was still absent from the "+
				"kernel set — a caller acting on that return would use an address the firewall rejects",
				i, missing[i])
		}
	}
}

// TestDeleteCOIFilterRulesForIP_RemovesEverything guards the teardown path that
// kill, orphan cleanup and setup's stale-rule purge all share.
//
// Allowlist mode installs state in three places — forward rules, the input-chain
// DNS block, and two nft sets — but the shared by-IP teardown originally knew only
// about the forward rules, so the rest accumulated on the host across sessions.
func TestDeleteCOIFilterRulesForIP_RemovesEverything(t *testing.T) {
	skipUnlessNft(t)

	f := NewNftManager(testContainerIP, testGatewayIP)
	t.Cleanup(func() { _ = DeleteCOIFilterRulesForIP(testContainerIP) })

	applyTestAllowlist(t, f, []string{"8.8.8.8/32"})
	if err := f.AllowDynamicIPsPorts([]string{"172.217.112.4"}, allPortsRange(), 300, testRefreshInterval); err != nil {
		t.Fatalf("AllowDynamicIPs: %v", err)
	}

	if err := DeleteCOIFilterRulesForIP(testContainerIP); err != nil {
		t.Fatalf("DeleteCOIFilterRulesForIP: %v", err)
	}

	dump := nftDump(t)
	if strings.Contains(dump, testContainerIP) {
		t.Errorf("forward rules for %s survived teardown\n%s", testContainerIP, dump)
	}
	for _, set := range []string{staticSetName(testContainerIP), dynamicSetName(testContainerIP)} {
		if strings.Contains(dump, set) {
			t.Errorf("set %s leaked — it would accumulate on the host across sessions\n%s", set, dump)
		}
	}

	input, err := exec.Command("sudo", "-n", "nft", "list", "chain", "ip", "coi", "input").CombinedOutput()
	if err == nil && strings.Contains(string(input), testContainerIP) {
		t.Errorf("the input-chain DNS block leaked\n%s", input)
	}

	// Teardown must be idempotent: orphan cleanup can race a normal teardown.
	if err := DeleteCOIFilterRulesForIP(testContainerIP); err != nil {
		t.Errorf("second teardown should be a no-op, got: %v", err)
	}
}

// dynSeenSnapshot returns the dynamic addresses this manager believes it has
// installed. Test-only accessor (integration tier); lives here so it isn't dead
// production code once the default build excludes the integration tests.
func (f *NftManager) dynSeenSnapshot() map[string]time.Time {
	f.dynMu.Lock()
	defer f.dynMu.Unlock()
	out := make(map[string]time.Time, len(f.dynSeen))
	for k, v := range f.dynSeen {
		out[k] = v
	}
	return out
}
