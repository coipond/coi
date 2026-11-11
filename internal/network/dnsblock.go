package network

import (
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/config"
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

// tcpReset is the match and verdict of the rule that goes before each reject.
//
// The kernel rate-limits ICMP errors per destination (net.ipv4.icmp_ratelimit),
// and a plain reject answers TCP with ICMP port-unreachable too. A container
// whose blocked TCP retries use up that budget gets no reply for a blocked DNS
// query and waits out the resolver timeout. A TCP reset is not rate-limited.
var tcpReset = []string{"meta", "l4proto", "tcp", "reject", "with", "tcp", "reset"}

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
	if _, err := runNFTCommand(addInputChainCmd()...); err != nil {
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
	var cmds [][]string
	for _, verdict := range [][]string{tcpReset, {"reject"}} {
		args := []string{
			"add", "rule", "ip", "coi", "input",
			"ip", "saddr", f.containerIP,
			"meta", "l4proto", "{", "tcp,", "udp", "}",
			"th", "dport", "53",
		}
		args = append(args, verdict...)
		cmds = append(cmds, append(args, "comment", fmt.Sprintf(`"coi-%s"`, f.containerIP)))
	}
	if err := runNFTScript(cmds); err != nil {
		return fmt.Errorf("failed to add DNS block rule (input): %w", err)
	}
	return nil
}

// stopResolverCmd stops systemd-resolved in the container until its next boot
// (a runtime mask, so socket activation cannot start it again).
//
// With DNS blocked, resolved still retries the blocked bridge resolver for every
// name not in /etc/hosts, and each rejected UDP query uses up the ICMP budget
// (see tcpReset). Stopped, resolved sends nothing, and a lookup through its stub
// fails at once on the container's loopback. /etc/hosts keeps answering through
// nss-files.
const stopResolverCmd = "if systemctl cat systemd-resolved.service >/dev/null 2>&1; then " +
	"systemctl mask --runtime systemd-resolved.service && " +
	"systemctl stop systemd-resolved.service 'systemd-resolved-*.socket'; fi"

// restoreResolverCmd undoes stopResolverCmd, for a container that is still
// running from an allowlist session and is now set up in another mode.
const restoreResolverCmd = "if [ -L /run/systemd/system/systemd-resolved.service ]; then " +
	"systemctl unmask --runtime systemd-resolved.service && systemctl start systemd-resolved.service; fi"

// nssHostsSaved holds the container's own "hosts:" line(s) of nsswitch.conf
// while filesOnlyHostsCmd is in effect (empty: the file had none).
const nssHostsSaved = "/etc/coi/nsswitch-hosts"

// filesOnlyHostsCmd makes name lookups in the container read /etc/hosts only:
// it sets "hosts: files" in nsswitch.conf and saves the old line.
//
// Without it a name not in /etc/hosts falls through to the dns module and sends
// a query to the resolver stub on 127.0.0.53. That query cannot leave the
// container, but its socket is a connection the security monitor sees.
//
// The file is edited in place, not covered by a mount, so package scripts and
// editors can still replace it. A systemd unit undoes the change at the next
// boot (before sysinit.target, so before coi's setup), as a persistent container
// restarted in open mode gets no in-container step.
const filesOnlyHostsCmd = "if [ -f /etc/nsswitch.conf ] && [ ! -e " + nssHostsSaved + " ]; then\n" +
	"mkdir -p /etc/coi && " +
	"{ [ ! -d /etc/systemd/system ] || { mkdir -p /etc/systemd/system/sysinit.target.wants && " +
	"cat >/etc/coi/nss-restore.sh <<'COI_SCRIPT' && cat >/etc/systemd/system/coi-nss-restore.service <<'COI_UNIT' && " +
	"ln -sf ../coi-nss-restore.service /etc/systemd/system/sysinit.target.wants/coi-nss-restore.service; }; } && " +
	"{ grep '^hosts:' /etc/nsswitch.conf || true; } >" + nssHostsSaved + " && " +
	"if grep -q '^hosts:' /etc/nsswitch.conf; then sed -i 's/^hosts:.*/hosts: files/' /etc/nsswitch.conf; " +
	"else echo 'hosts: files' >>/etc/nsswitch.conf; fi\n" +
	restoreHostsCmd + "\nCOI_SCRIPT\n" +
	nssRestoreUnit + "COI_UNIT\nfi"

// restoreHostsCmd undoes filesOnlyHostsCmd: it puts the saved "hosts:" line
// back and keeps every other change made to the file since.
const restoreHostsCmd = "if [ -e " + nssHostsSaved + " ]; then " +
	"sed -i -e '/^hosts:/{r " + nssHostsSaved + "' -e 'd' -e '}' /etc/nsswitch.conf && " +
	"{ grep -q '^hosts:' /etc/nsswitch.conf || cat " + nssHostsSaved + " >>/etc/nsswitch.conf; } && " +
	"rm -f " + nssHostsSaved + "; fi"

// nssRestoreUnit runs restoreHostsCmd at boot (a no-op once nothing is saved).
const nssRestoreUnit = "[Unit]\n" +
	"Description=Undo coi allowlist name lookup (hosts: files)\n" +
	"DefaultDependencies=no\n" +
	"After=local-fs.target\n" +
	"Before=sysinit.target\n" +
	"ConditionPathExists=" + nssHostsSaved + "\n" +
	"\n" +
	"[Service]\n" +
	"Type=oneshot\n" +
	"ExecStart=/bin/sh /etc/coi/nss-restore.sh\n" +
	"\n" +
	"[Install]\n" +
	"WantedBy=sysinit.target\n"

// containerNetCmd is the in-container part of a mode's network setup, as one
// exec.
func containerNetCmd(mode config.NetworkMode) string {
	switch mode {
	case config.NetworkModeAllowlist:
		return allSteps(disableIPv6Cmd, stopResolverCmd, filesOnlyHostsCmd)
	case config.NetworkModeRestricted:
		return allSteps(disableIPv6Cmd, restoreResolverCmd, restoreHostsCmd)
	default:
		return allSteps(restoreResolverCmd, restoreHostsCmd)
	}
}

// prepareContainer runs containerNetCmd for the manager's mode. Best effort:
// the firewall is the enforced boundary.
func (m *Manager) prepareContainer(containerName string) {
	if err := execInContainer(containerName, containerNetCmd(m.config.Mode)); err != nil {
		m.logger.Errorf("Warning: failed to prepare the container's network (IPv6, resolver, name lookup): %v", err)
	}
}

// removeInputRulesForIP drops the container's rules from the coi input chain.
func removeInputRulesForIP(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	cmds, err := deleteInputRuleCmds("coi-" + containerIP)
	if err != nil || len(cmds) == 0 {
		return nil // chain unreadable or no rules — nothing to remove
	}
	// One transaction for all of the container's rules. If it fails (a rule
	// vanished meanwhile), delete them one by one.
	if runNFTScript(cmds) == nil {
		return nil
	}
	return deleteNFTRulesInChain("coi", "input", "coi-"+containerIP)
}

// addInputChainCmd returns the nft command that creates the coi input chain
// (see ensureCOIInputChain).
func addInputChainCmd() []string {
	return []string{
		"add", "chain", "ip", "coi", "input",
		"{", "type", "filter", "hook", "input", "priority", "filter", ";", "policy", "accept", ";", "}",
	}
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
