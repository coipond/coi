package network

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoiBridgeRulesListed(t *testing.T) {
	const in = "-A FORWARD -i incusbr0 -m comment --comment coi-bridge-forward -j ACCEPT\n"
	const out = "-A FORWARD -o incusbr0 -m comment --comment coi-bridge-forward -j ACCEPT\n"
	cases := []struct {
		name  string
		rules string
		want  bool
	}{
		{"both", "-P FORWARD DROP\n" + out + in, true},
		{"in only", "-P FORWARD DROP\n" + in, false},
		{"out only", "-P FORWARD DROP\n" + out, false},
		{"commented non-accept", "-P FORWARD DROP\n" + strings.ReplaceAll(in+out, "-j ACCEPT", "-j LOG"), false},
		{"none", "-P FORWARD ACCEPT\n", false},
		{"uncommented accepts", "-P FORWARD DROP\n-A FORWARD -i incusbr0 -j ACCEPT\n-A FORWARD -o incusbr0 -j ACCEPT\n", false},
		{"another bridge", "-P FORWARD DROP\n" + strings.ReplaceAll(in+out, "incusbr0", "lxdbr0"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := coiBridgeRulesListed(c.rules, "incusbr0"); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Listings as `nft list chain ip filter FORWARD` prints iptables-nft's chain:
// no rule comments, two spaces before the counter.
func TestClassifyNftForward(t *testing.T) {
	chain := func(policy string, rules ...string) string {
		s := "table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy " + policy + ";\n"
		for _, r := range rules {
			s += "\t\t" + r + "\n"
		}
		return s + "\t}\n}\n"
	}
	cases := []struct {
		name    string
		listing string
		want    bridgeForwardState
	}{
		{"policy accept", chain("accept"), bridgeForwardOK},
		{"policy drop", chain("drop", `counter packets 4 bytes 240 jump DOCKER-USER`), bridgeForwardNeedsRules},
		{"drop with bridge accepts", chain("drop",
			`oifname "incusbr0"  counter packets 0 bytes 0 accept`,
			`iifname "incusbr0"  counter packets 0 bytes 0 accept`), bridgeForwardOK},
		{"native rule comments", chain("drop",
			`iifname "incusbr0" accept comment "coi-bridge-forward"`,
			`oifname "incusbr0" accept comment "coi-bridge-forward"`), bridgeForwardOK},
		{"drop with one direction only", chain("drop", `iifname "incusbr0"  counter packets 0 bytes 0 accept`), bridgeForwardNeedsRules},
		{"accept then reject all", chain("accept", `counter packets 0 bytes 0 reject with icmp host-prohibited`), bridgeForwardNeedsRules},
		{"conditional drop only", chain("accept", `iifname "docker0" counter packets 0 bytes 0 drop`), bridgeForwardOK},
		{"no chain header", "", bridgeForwardUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyNftForward(c.listing, "incusbr0"); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

// fakeForwardHost puts fake `sudo` and `iptables` on PATH. sudoCase holds
// shell `case` arms on the command sudo runs (its `-n` dropped); unmatched
// commands exit 0. Every sudo call is logged. Returns the log path.
func fakeForwardHost(t *testing.T, iptablesVersion, sudoCase string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sudo.log")
	sudo := fmt.Sprintf("#!/bin/sh\nshift\necho \"$*\" >> %q\ncase \"$*\" in\n%s\nesac\nexit 0\n", logPath, sudoCase)
	iptables := fmt.Sprintf("#!/bin/sh\necho %q\n", iptablesVersion)
	for name, script := range map[string]string{"sudo": sudo, "iptables": iptables} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	prevSudo := SudoEnabled()
	SetSudoAllowed(true)
	bridgeNameMu.Lock()
	prevBridge := bridgeName
	bridgeName = "incusbr0"
	bridgeNameMu.Unlock()
	resetBridgeForwardEnsured()
	t.Cleanup(func() {
		SetSudoAllowed(prevSudo)
		bridgeNameMu.Lock()
		bridgeName = prevBridge
		bridgeNameMu.Unlock()
		resetBridgeForwardEnsured()
	})
	return logPath
}

// resetBridgeForwardEnsured lets EnsureBridgeInTrustedZone act again.
func resetBridgeForwardEnsured() {
	bridgeForwardMu.Lock()
	bridgeForwardEnsured = false
	bridgeForwardMu.Unlock()
}

func sudoCalls(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

const (
	nftIptables    = "iptables v1.8.10 (nf_tables)"
	legacyIptables = "iptables v1.8.10 (legacy)"
	// sudoRefusesIptables is a sudoers rule that grants nft but not iptables.
	sudoRefusesIptables = `iptables*) echo "sudo: a password is required" >&2; exit 1 ;;`
)

const coiRulesListed = `"iptables -S FORWARD") printf -- '-P FORWARD DROP\n-A FORWARD -o incusbr0 -m comment --comment coi-bridge-forward -j ACCEPT\n-A FORWARD -i incusbr0 -m comment --comment coi-bridge-forward -j ACCEPT\n' ;;`

// coi's rules already in place: one read, no change, no warning.
func TestEnsureBridgeInTrustedZone_RulesListedAddsNothing(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, coiRulesListed)

	changed, bridge, err := EnsureBridgeInTrustedZone()
	if err != nil || changed || bridge != "incusbr0" {
		t.Fatalf("got (%v, %q, %v), want (false, incusbr0, nil)", changed, bridge, err)
	}
	if calls := sudoCalls(t, logPath); len(calls) != 1 || calls[0] != "iptables -S FORWARD" {
		t.Errorf("want only the FORWARD read, got %q", calls)
	}
}

// With sudo for iptables, the rules go in even on policy ACCEPT: a DROP set
// later by Docker or ufw must not cut running containers off.
func TestEnsureBridgeInTrustedZone_PolicyAcceptStillAddsRulesWithIptablesSudo(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, `"iptables -S FORWARD") echo "-P FORWARD ACCEPT" ;;
"iptables -C"*) exit 1 ;;`)

	if changed, _, err := EnsureBridgeInTrustedZone(); err != nil || !changed {
		t.Fatalf("got (%v, %v), want rules added", changed, err)
	}
	if n := insertedRules(t, logPath); n != 2 {
		t.Errorf("want both bridge rules inserted, got %d", n)
	}
}

// changed means a rule was inserted, not that the read missed one.
func TestEnsureBridgeInTrustedZone_NoInsertReportsNoChange(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, `"iptables -S FORWARD") echo "-P FORWARD DROP" ;;`)

	if changed, _, err := EnsureBridgeInTrustedZone(); err != nil || changed {
		t.Fatalf("got (%v, %v), want no change: -C found both rules", changed, err)
	}
	if n := insertedRules(t, logPath); n != 0 {
		t.Errorf("want no insert, got %d", n)
	}
}

func insertedRules(t *testing.T, logPath string) int {
	t.Helper()
	n := 0
	for _, c := range sudoCalls(t, logPath) {
		if strings.HasPrefix(c, "iptables -I FORWARD") && strings.Contains(c, "coi-bridge-forward") {
			n++
		}
	}
	return n
}

// The reported host: sudo grants nft only, firewalld trusts the bridge, the
// FORWARD policy is ACCEPT. The chain is read through nft; nothing is changed.
func TestEnsureBridgeInTrustedZone_NftOnlySudoReadsChainThroughNft(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, sudoRefusesIptables+`
"nft list chain ip filter FORWARD") printf 'table ip filter {\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n}\n' ;;`)

	changed, _, err := EnsureBridgeInTrustedZone()
	if err != nil || changed {
		t.Fatalf("got (%v, %v), want no change and no error", changed, err)
	}
	for _, c := range sudoCalls(t, logPath) {
		if strings.HasPrefix(c, "iptables -I") || strings.HasPrefix(c, "iptables -C") {
			t.Errorf("must not probe or add iptables rules, ran %q", c)
		}
	}
}

// No iptables-nft FORWARD chain at all: nothing in iptables drops traffic.
func TestEnsureBridgeInTrustedZone_NftOnlySudoNoForwardChain(t *testing.T) {
	fakeForwardHost(t, nftIptables, sudoRefusesIptables+`
"nft list chain ip filter FORWARD") echo "Error: No such file or directory" >&2; exit 1 ;;`)

	if changed, _, err := EnsureBridgeInTrustedZone(); err != nil || changed {
		t.Fatalf("got (%v, %v), want no change and no error", changed, err)
	}
}

// A chain coi cannot read is not a missing rule: no privileged change is
// tried, and the one error says why.
func TestEnsureBridgeInTrustedZone_UnreadableChainIsNotMissingRules(t *testing.T) {
	logPath := fakeForwardHost(t, legacyIptables, sudoRefusesIptables)

	changed, _, err := EnsureBridgeInTrustedZone()
	if changed || !errors.Is(err, errBridgeForwardUninspectable) {
		t.Fatalf("got (%v, %v), want errBridgeForwardUninspectable", changed, err)
	}
	if !strings.Contains(err.Error(), "a password is required") {
		t.Errorf("error should name the sudo refusal, got %v", err)
	}
	if calls := sudoCalls(t, logPath); len(calls) != 1 {
		t.Errorf("want only the failed read, got %q", calls)
	}
}

// Forwarding that really drops the bridge's traffic still gets coi's rules.
func TestEnsureBridgeInTrustedZone_PolicyDropAddsRules(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, `"iptables -S FORWARD") echo "-P FORWARD DROP" ;;
"iptables -C"*) exit 1 ;;`)

	if changed, _, err := EnsureBridgeInTrustedZone(); err != nil || !changed {
		t.Fatalf("got (%v, %v), want rules added", changed, err)
	}
	if n := insertedRules(t, logPath); n != 2 {
		t.Errorf("want both bridge rules inserted, got %d", n)
	}
}

// nft-only sudo on a chain that drops: one error that says so, and no
// iptables change is tried (sudo would refuse it).
func TestEnsureBridgeInTrustedZone_NftOnlySudoDroppingChainReports(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, sudoRefusesIptables+`
"nft list chain ip filter FORWARD") printf '\t\ttype filter hook forward priority filter; policy drop;\n' ;;`)

	changed, _, err := EnsureBridgeInTrustedZone()
	if changed || err == nil || !strings.Contains(err.Error(), "drops incusbr0's traffic") {
		t.Fatalf("got (%v, %v), want the dropping chain reported", changed, err)
	}
	for _, c := range sudoCalls(t, logPath) {
		if strings.HasPrefix(c, "iptables -I") || strings.HasPrefix(c, "iptables -C") {
			t.Errorf("must not probe or add iptables rules, ran %q", c)
		}
	}
}

// One launch calls it from several phases: it acts and reports once.
func TestEnsureBridgeInTrustedZone_ReportsOncePerProcess(t *testing.T) {
	logPath := fakeForwardHost(t, legacyIptables, sudoRefusesIptables)

	if _, _, err := EnsureBridgeInTrustedZone(); err == nil {
		t.Fatal("first call should report the unreadable chain")
	}
	changed, bridge, err := EnsureBridgeInTrustedZone()
	if err != nil || changed || bridge != "incusbr0" {
		t.Errorf("second call: got (%v, %q, %v), want (false, incusbr0, nil)", changed, bridge, err)
	}
	if calls := sudoCalls(t, logPath); len(calls) != 1 {
		t.Errorf("second call must not run sudo again, got %q", calls)
	}
}

func TestEnsureBridgeInTrustedZone_SudoDisabledRunsNoSudo(t *testing.T) {
	logPath := fakeForwardHost(t, nftIptables, "")
	SetSudoAllowed(false)

	if changed, _, err := EnsureBridgeInTrustedZone(); err != nil || changed {
		t.Fatalf("got (%v, %v), want no change and no error", changed, err)
	}
	if calls := sudoCalls(t, logPath); calls != nil {
		t.Errorf("use_sudo=false must not invoke sudo, ran %q", calls)
	}
}
