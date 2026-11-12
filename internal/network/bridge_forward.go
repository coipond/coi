package network

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// bridgeForwardState is what the host's FORWARD chain does with traffic
// forwarded to and from the Incus bridge.
type bridgeForwardState string

const (
	// bridgeForwardOK: the chain already accepts the bridge's traffic.
	bridgeForwardOK bridgeForwardState = "ok"
	// bridgeForwardNeedsRules: the chain would drop it without coi's rules.
	bridgeForwardNeedsRules bridgeForwardState = "needs-rules"
	// bridgeForwardUnknown: the chain could not be read. Not proof that
	// rules are missing.
	bridgeForwardUnknown bridgeForwardState = "unknown"
)

const bridgeForwardComment = "coi-bridge-forward"

// errBridgeForwardUninspectable marks a FORWARD chain coi could not read.
var errBridgeForwardUninspectable = errors.New("could not inspect the FORWARD chain")

// bridgeForwardEnsured makes EnsureBridgeInTrustedZone act (and report) once
// per process and bridge: one launch calls it from several phases.
var (
	bridgeForwardMu      sync.Mutex
	bridgeForwardEnsured = map[string]bool{}
)

// ensureBridgeForwardOnce is ensureBridgeForward, once per process for bridge.
func ensureBridgeForwardOnce(bridge string) (bool, string, error) {
	bridgeForwardMu.Lock()
	defer bridgeForwardMu.Unlock()
	if bridgeForwardEnsured[bridge] {
		return false, bridge, nil
	}
	bridgeForwardEnsured[bridge] = true
	changed, err := ensureBridgeForward(bridge)
	return changed, bridge, err
}

// ensureBridgeForward installs coi's FORWARD rules for bridge. When sudo runs
// iptables, it adds missing rules even if the chain accepts today, so a policy
// DROP set later (Docker, ufw) does not cut running containers off. When sudo
// refuses iptables, it reads the chain through nft and asks for nothing when
// the chain accepts the bridge's traffic.
func ensureBridgeForward(bridge string) (bool, error) {
	if !SudoEnabled() {
		return false, nil
	}
	out, err := exec.Command("sudo", "-n", "iptables", "-S", "FORWARD").CombinedOutput()
	if err == nil {
		if coiBridgeRulesListed(string(out), bridge) {
			return false, nil
		}
		return insertIptablesBridgeRules(bridge)
	}
	iptErr := fmt.Errorf("iptables -S FORWARD: %s", outputOrError(out, err))
	switch inspectForwardThroughNft(bridge) {
	case bridgeForwardOK:
		return false, nil
	case bridgeForwardNeedsRules:
		return false, fmt.Errorf("the FORWARD chain drops %s's traffic and coi cannot add rules: %w", bridge, iptErr)
	}
	return false, fmt.Errorf("%w for %s, no rules added: %w", errBridgeForwardUninspectable, bridge, iptErr)
}

// inspectForwardThroughNft reads the iptables FORWARD chain through nft, which
// coi's sudo rule allows, when iptables is the nf_tables variant (or absent).
func inspectForwardThroughNft(bridge string) bridgeForwardState {
	if !forwardChainInNft() {
		return bridgeForwardUnknown
	}
	listing, err := runNFTCommand("list", "chain", "ip", "filter", "FORWARD")
	if err == nil {
		return classifyNftForward(string(listing), bridge)
	}
	if strings.Contains(err.Error(), "No such file or directory") {
		return bridgeForwardOK // no iptables FORWARD chain, nothing drops
	}
	return bridgeForwardUnknown
}

// forwardChainInNft reports whether nft sees the iptables FORWARD chain:
// iptables is not installed or is the nf_tables variant (not legacy).
func forwardChainInNft() bool {
	if !IptablesAvailable() {
		return true
	}
	out, err := exec.Command("iptables", "-V").Output()
	return err == nil && strings.Contains(string(out), "nf_tables")
}

// forwardRule is one FORWARD rule reduced to what matters for the bridge:
// an ACCEPT of all traffic in from it or out to it, or a verdict with no match.
type forwardRule struct {
	bridgeIn, bridgeOut bool
	verdict             string
}

// coiBridgeRulesListed reports whether `iptables -S FORWARD` output has both
// of coi's rules for bridge.
func coiBridgeRulesListed(rules, bridge string) bool {
	var in, out bool
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || f[1] != "FORWARD" ||
			!strings.Contains(line, "--comment "+bridgeForwardComment) || !hasFlag(f, "-j", "ACCEPT") {
			continue
		}
		in = in || hasFlag(f, "-i", bridge)
		out = out || hasFlag(f, "-o", bridge)
	}
	return in && out
}

func hasFlag(fields []string, flag, value string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == flag && fields[i+1] == value {
			return true
		}
	}
	return false
}

// nftNoiseRe matches the parts of an nft rule that change nothing here.
var nftNoiseRe = regexp.MustCompile(`\s*\bcounter(?: packets \d+ bytes \d+)?|\s*\bcomment "[^"]*"`)

// classifyNftForward reads `nft list chain ip filter FORWARD` output: the
// chain iptables-nft manages (nft does not print its rules' comments).
func classifyNftForward(listing, bridge string) bridgeForwardState {
	var policy string
	var parsed []forwardRule
	for _, line := range strings.Split(listing, "\n") {
		line = strings.Join(strings.Fields(nftNoiseRe.ReplaceAllString(line, "")), " ")
		if rest, ok := strings.CutPrefix(line, "type filter hook forward"); ok {
			if _, p, found := strings.Cut(rest, "policy "); found {
				policy = strings.ToUpper(strings.TrimSuffix(p, ";"))
			}
			continue
		}
		switch line {
		case `iifname "` + bridge + `" accept`:
			parsed = append(parsed, forwardRule{bridgeIn: true})
		case `oifname "` + bridge + `" accept`:
			parsed = append(parsed, forwardRule{bridgeOut: true})
		case "accept", "drop":
			parsed = append(parsed, forwardRule{verdict: strings.ToUpper(line)})
		default:
			if line == "reject" || strings.HasPrefix(line, "reject ") {
				parsed = append(parsed, forwardRule{verdict: "REJECT"})
			}
		}
	}
	return forwardStateOf(parsed, policy)
}

// forwardStateOf walks the rules in order: the bridge's traffic is accepted
// once both directions are, and the first verdict with no match decides for
// what is left. Past all rules, the chain policy decides.
func forwardStateOf(rules []forwardRule, policy string) bridgeForwardState {
	var in, out bool
	for _, r := range rules {
		in = in || r.bridgeIn
		out = out || r.bridgeOut
		if in && out {
			return bridgeForwardOK
		}
		switch r.verdict {
		case "ACCEPT":
			return bridgeForwardOK
		case "DROP", "REJECT":
			return bridgeForwardNeedsRules
		}
	}
	switch policy {
	case "ACCEPT":
		return bridgeForwardOK
	case "":
		return bridgeForwardUnknown
	default:
		return bridgeForwardNeedsRules
	}
}

// outputOrError is the first line of a failed command's output, or err when
// it printed nothing.
func outputOrError(out []byte, err error) string {
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return err.Error()
}
