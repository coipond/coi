package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// fakeNftSudo puts a `sudo` on PATH that records every nft call (and the
// script of `nft -f -`) in the returned log, and answers
// `nft -a list chain ip coi forward|input` with the chain's listing; an empty
// listing is a missing chain. Every other call prints nothing.
func fakeNftSudo(t *testing.T, forward, input string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	listings := map[string]string{"forward": forward, "input": input}
	answers := ""
	for _, chain := range []string{"forward", "input"} {
		answer := `echo "Error: No such file or directory" >&2; exit 1`
		if listings[chain] != "" {
			listPath := filepath.Join(dir, chain+".txt")
			if err := os.WriteFile(listPath, []byte(listings[chain]), 0o600); err != nil {
				t.Fatal(err)
			}
			answer = fmt.Sprintf("cat %q", listPath)
		}
		answers += fmt.Sprintf("\"-a list chain ip coi %s\") %s ;;\n", chain, answer)
	}
	script := fmt.Sprintf(`#!/bin/sh
shift 2
echo "$*" >> %q
case "$*" in
"-f -") cat >> %q ;;
%sesac
exit 0
`, logPath, logPath, answers)
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := SudoEnabled()
	SetSudoAllowed(true)
	t.Cleanup(func() { SetSudoAllowed(prev) })
	return logPath
}

func readCalls(t *testing.T, logPath string) string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func stubHostAddrs(t *testing.T, addrs ...string) {
	t.Helper()
	prev := hostIPv4Addrs
	hostIPv4Addrs = func() map[string]bool {
		m := make(map[string]bool)
		for _, a := range addrs {
			m[a] = true
		}
		return m
	}
	t.Cleanup(func() { hostIPv4Addrs = prev })
}

// A previous session's rules for the IP, in both chains.
const (
	staleForwardListing = `table ip coi {
	chain forward { # handle 1
		type filter hook forward priority 10; policy accept;
		ip saddr 10.0.0.2 accept comment "coi-10.0.0.2" # handle 5
	}
}`
	staleInputListing = `table ip coi {
	chain input { # handle 3
		type filter hook input priority filter; policy accept;
		ip saddr 10.0.0.2 ip daddr 10.0.0.1 meta l4proto { tcp, udp } th dport { 8080 } accept comment "coi-10.0.0.2" # handle 7
		ip saddr 10.0.0.2 reject comment "coi-10.0.0.2" # handle 8
	}
}`
)

// A restart replaces the old input rules (a host accept from an earlier
// session must not stay open) in the same transaction as the new rules.
func TestApplyRestrictedReplacing_ReplacesInputRules(t *testing.T) {
	logPath := fakeNftSudo(t, staleForwardListing, staleInputListing)
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeRestricted}, logger.NewDiscard())
	m.nft = NewNftManager("10.0.0.2", "10.0.0.1")
	if err := m.applyRestrictedReplacing("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	for _, want := range []string{
		"delete rule ip coi forward handle 5",
		"delete rule ip coi input handle 7",
		"delete rule ip coi input handle 8",
		`add rule ip coi input ip saddr 10.0.0.2 reject comment "coi-10.0.0.2"`,
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in nft calls:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "add chain ip coi input") {
		t.Errorf("the input chain exists; it must not be added again:\n%s", calls)
	}
}

// Kill, orphan cleanup and container delete remove the input rules too.
func TestDeleteCOIFilterRulesForIP_RemovesInputRules(t *testing.T) {
	logPath := fakeNftSudo(t, staleForwardListing, staleInputListing)
	if err := DeleteCOIFilterRulesForIP("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	for _, want := range []string{
		"delete rule ip coi forward handle 5",
		"delete rule ip coi input handle 7",
		"delete rule ip coi input handle 8",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in nft calls:\n%s", want, calls)
		}
	}
}

// A [[network.hosts]] entry that names a host address opens it on the input
// chain on the entry's ports only; without ports it stays closed.
func TestApplyHostFirewall_HostAddress(t *testing.T) {
	logPath := fakeNftSudo(t, "", "")
	stubHostAddrs(t, "192.168.77.1")

	entry := config.HostEntry{IP: "192.168.77.1", Hostnames: []string{"h"}, Ports: []int{8080}}
	if err := applyHostFirewall(config.NetworkModeRestricted, false, "10.0.0.2", entry, nil); err != nil {
		t.Fatal(err)
	}
	want := "insert rule ip coi input ip saddr 10.0.0.2 ip daddr 192.168.77.1 meta l4proto { tcp, udp } th dport { 8080 } accept"
	if calls := readCalls(t, logPath); !strings.Contains(calls, want) {
		t.Errorf("missing %q in nft calls:\n%s", want, calls)
	}

	logPath = fakeNftSudo(t, "", "")
	entry.Ports = nil
	if err := applyHostFirewall(config.NetworkModeRestricted, false, "10.0.0.2", entry, nil); err != nil {
		t.Fatal(err)
	}
	if calls := readCalls(t, logPath); strings.Contains(calls, "coi input") {
		t.Errorf("an entry without ports must not open the host:\n%s", calls)
	}
}

func TestCheckHostPortsEnforceable_HostAddress(t *testing.T) {
	stubHostAddrs(t, "203.0.113.9", "192.168.77.1")
	cases := []struct {
		name       string
		mode       config.NetworkMode
		allowLocal bool
		entry      config.HostEntry
		ok         bool
	}{
		{"restricted, public host address with ports", config.NetworkModeRestricted, false, config.HostEntry{IP: "203.0.113.9", Ports: []int{8080}}, true},
		{"allowlist with LAN access, private host address with ports", config.NetworkModeAllowlist, true, config.HostEntry{IP: "192.168.77.1", Ports: []int{8080}}, true},
		{"allowlist, host address on port 53", config.NetworkModeAllowlist, false, config.HostEntry{IP: "203.0.113.9", Ports: []int{53}}, false},
		{"restricted, public non-host address with ports", config.NetworkModeRestricted, false, config.HostEntry{IP: "198.51.100.7", Ports: []int{8080}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkHostPortsEnforceable(tc.mode, tc.allowLocal, tc.entry, nil)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// A name that resolves to a host address is warned about once.
func TestWarnResolvedHostAddrs(t *testing.T) {
	stubHostAddrs(t, "10.0.0.1")
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeAllowlist}, logger.NewDiscard())
	m.warnResolvedHostAddrs(map[string][]string{"svc.test": {"10.0.0.1", "1.1.1.1"}})
	if !m.hostAddrWarned["10.0.0.1"] || m.hostAddrWarned["1.1.1.1"] || len(m.hostAddrWarned) != 1 {
		t.Errorf("warned = %v", m.hostAddrWarned)
	}

	on := true
	m = NewManager(&config.NetworkConfig{Mode: config.NetworkModeAllowlist, AllowHostAccess: &on}, logger.NewDiscard())
	m.warnResolvedHostAddrs(map[string][]string{"svc.test": {"10.0.0.1"}})
	if len(m.hostAddrWarned) != 0 {
		t.Errorf("allow_host_access must not warn, got %v", m.hostAddrWarned)
	}
}

// syncResolved (install and every refresh) is what calls the warning.
func TestSyncResolved_WarnsOnHostAddress(t *testing.T) {
	stubHostAddrs(t, "10.0.0.1")
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeAllowlist}, logger.NewDiscard())
	m.nft = &stubNft{}
	m.resolver = NewResolver(&IPCache{Domains: map[string][]string{}, TTLs: map[string]uint32{}})
	if err := m.syncResolved(map[string][]string{"svc.test": {"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if !m.hostAddrWarned["10.0.0.1"] {
		t.Errorf("syncResolved must warn about a host address, warned = %v", m.hostAddrWarned)
	}
}

// The rules come from one `list chain` call per chain, never `list table`.
func TestCOIChainRules_ListsEachChain(t *testing.T) {
	logPath := fakeNftSudo(t, staleForwardListing, staleInputListing)
	rules, chains, err := coiChainRules("coi-10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !chains["forward"] || !chains["input"] || len(chains) != 2 {
		t.Errorf("chains = %v", chains)
	}
	if f := rules["forward"]; len(f) != 1 || f[0].handle != "5" {
		t.Errorf("forward = %+v", f)
	}
	if in := rules["input"]; len(in) != 2 || in[0].handle != "7" || in[1].handle != "8" {
		t.Errorf("input = %+v", in)
	}
	want := "-a list chain ip coi forward\n-a list chain ip coi input\n"
	if calls := readCalls(t, logPath); calls != want {
		t.Errorf("nft calls = %q, want %q", calls, want)
	}
}

// A missing input chain is absent, not an error; a missing table holds
// nothing.
func TestCOIChainRules_MissingChain(t *testing.T) {
	fakeNftSudo(t, staleForwardListing, "")
	rules, chains, err := coiChainRules("coi-10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if !chains["forward"] || chains["input"] {
		t.Errorf("chains = %v", chains)
	}
	if len(rules["forward"]) != 1 || len(rules["input"]) != 0 {
		t.Errorf("rules = %+v", rules)
	}

	fakeNftSudo(t, "", "")
	rules, chains, err = coiChainRules("coi-10.0.0.2")
	if err != nil || len(rules) != 0 || len(chains) != 0 {
		t.Errorf("missing table: rules = %+v, chains = %v, err = %v", rules, chains, err)
	}
}

// Without an input chain, restricted mode adds it in the same transaction as
// the rules, after deleting the old forward rule.
func TestApplyRestrictedReplacing_AddsMissingInputChain(t *testing.T) {
	logPath := fakeNftSudo(t, staleForwardListing, "")
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeRestricted}, logger.NewDiscard())
	m.nft = NewNftManager("10.0.0.2", "10.0.0.1")
	if err := m.applyRestrictedReplacing("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	del := strings.Index(calls, "delete rule ip coi forward handle 5")
	add := strings.Index(calls, "add chain ip coi input")
	reject := strings.Index(calls, `add rule ip coi input ip saddr 10.0.0.2 reject comment "coi-10.0.0.2"`)
	if del < 0 || add < del || reject < add {
		t.Errorf("want delete, add chain, input rules in order in nft calls:\n%s", calls)
	}
	if strings.Contains(calls, "-a list table") {
		t.Errorf("must not list the rules of the whole table:\n%s", calls)
	}
}
