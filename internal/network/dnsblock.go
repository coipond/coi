package network

import (
	"fmt"
	"strings"
)

// In allowlist mode the container has no DNS at all. Its only way to turn a name
// into an address is the /etc/hosts block Coi writes (see hosts.go), which holds
// exactly the addresses Coi also installed in the firewall.
//
// That equality is the whole design. Leave the container any route to a
// nameserver and it can resolve a name to an address the firewall has never seen
// — which is precisely the divergence that made allowlist mode flap against
// rotating cloud frontends in the first place.
//
// Blocking DNS takes two chains, and missing either one leaves the hole wide open:
//
//   - forward: a query to an off-box resolver (8.8.8.8) is routed through the
//     host, so the forward chain sees it. The reject must sit BEFORE the set
//     rules — a resolver inside an allowlisted CIDR would otherwise be reachable
//     on port 53.
//   - input: a query to the bridge's own dnsmasq is addressed to the host, so it
//     is delivered via the input hook and NEVER traverses the forward chain. Only
//     an input rule can stop it. This is the one that is easy to forget, and the
//     one that would silently make everything above pointless.

// ensureCOIInputChain creates the input chain in the ip coi table.
//
// A drop in any base chain is terminal, so this chain does not need to outrank
// Incus's or ufw's input rules — it only needs to exist. Priority filter keeps it
// alongside the usual filtering.
func ensureCOIInputChain() error {
	if _, err := runNFTCommand("add", "table", "ip", "coi"); err != nil {
		return fmt.Errorf("failed to create nft table ip coi: %w", err)
	}
	// `nft add chain` with a hook spec fails if the chain already exists.
	if _, err := runNFTCommand("list", "chain", "ip", "coi", "input"); err == nil {
		return nil
	}
	if _, err := runNFTCommand("add", "chain", "ip", "coi", "input",
		"{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", "accept", ";", "}"); err != nil {
		return fmt.Errorf("failed to create nft chain ip coi input: %w", err)
	}
	return nil
}

// blockDNS denies the container every route to a nameserver.
func (f *NftManager) blockDNS() error {
	if f.containerIP == "" {
		return nil
	}

	// Off-box resolvers: forwarded, so the forward chain catches them. Rejected
	// rather than dropped so a lookup fails immediately instead of hanging for the
	// resolver's full timeout.
	if err := f.addRuleWithMatch(f.containerIP, "0.0.0.0/0",
		[]string{"meta", "l4proto", "{", "tcp,", "udp", "}", "th", "dport", "53"}, "reject"); err != nil {
		return fmt.Errorf("failed to add DNS block rule (forward): %w", err)
	}

	// The bridge's own resolver: addressed to the host, so it bypasses the forward
	// chain entirely and needs an input rule. Without this the container just asks
	// dnsmasq and resolves whatever it likes.
	if err := ensureCOIInputChain(); err != nil {
		return err
	}
	if _, err := runNFTCommand(
		"add", "rule", "ip", "coi", "input",
		"ip", "saddr", f.containerIP,
		"meta", "l4proto", "{", "tcp,", "udp", "}",
		"th", "dport", "53",
		"reject",
		"comment", fmt.Sprintf(`"coi-%s"`, f.containerIP),
	); err != nil {
		return fmt.Errorf("failed to add DNS block rule (input): %w", err)
	}
	return nil
}

// removeInputRulesForIP drops the container's rules from the coi input chain.
func removeInputRulesForIP(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	return deleteNFTRulesInChain("coi", "input", "coi-"+containerIP)
}

// deleteNFTRulesInChain removes every rule carrying comment from the given
// table/chain in the ip family.
func deleteNFTRulesInChain(table, chain, comment string) error {
	output, err := runNFTCommand("-a", "list", "chain", "ip", table, chain)
	if err != nil {
		return nil // chain doesn't exist — nothing to remove
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, fmt.Sprintf("comment %q", comment)) {
			continue
		}
		if h := extractNFTHandle(line); h != "" {
			if _, delErr := runNFTCommand("delete", "rule", "ip", table, chain, "handle", h); delErr != nil {
				logWarnf("Warning: failed to delete nft rule handle %s from %s/%s: %v", h, table, chain, delErr)
			}
		}
	}
	return nil
}
