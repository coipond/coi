package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mensfeld/code-on-incus/internal/config"
	"github.com/mensfeld/code-on-incus/internal/container"
)

// Allowlist mode makes the container's name resolution deterministic instead of
// live: Coi resolves the allowed domains on the host, installs those addresses in
// the firewall, and writes the SAME addresses into the container's /etc/hosts.
// All DNS egress is then blocked (see the port-53 rules in nft_filter.go), so the
// hosts file Coi wrote is the container's only way to turn a name into an address.
//
// This is what kills the original bug at the root. The old design resolved on the
// host, pinned the result, and left the container to resolve the same name
// independently — and for any domain behind a rotating pool of frontend addresses
// (every Google API endpoint) the container routinely got a different member of
// the pool, one the firewall had never seen. The two sides disagreed, the packet
// hit the default reject, and the agent died mid-task with "Unable to connect".
//
// Here there is only one source of truth. The container cannot resolve a name to
// an address the firewall does not already trust, because there is nowhere else
// for an address to come from. Nothing has to stay running for that to hold: the
// hosts file and the nft set are both already in place and they already agree, so
// the guarantee survives `coi` exiting, the user detaching from tmux, or the
// process being killed. Stale-but-consistent is a working container; the thing
// that broke was fresh-but-divergent.
//
// An agent with root inside the container can of course overwrite /etc/hosts. That
// costs it its own name resolution and gains it nothing — the firewall is still
// the boundary, and an address it invents is an address the firewall rejects. The
// failure is closed and self-inflicted.
const (
	hostsBeginMarker = "# BEGIN coi allowlist (managed by coi — edits will be overwritten)"
	hostsEndMarker   = "# END coi allowlist"

	// Static user host entries ([[network.hosts]] and `coi hosts`, #605) live in
	// their OWN managed block, independent of the allowlist block above, so the
	// two never clobber each other. The two blocks are written independently; on
	// the rare name that appears in both, glibc's first-match resolution picks
	// whichever block is earlier in the file (the allowlist block, written at
	// setup, precedes a user block appended later) — collisions are expected to
	// be a non-case, since allowlisted domains and user host names don't overlap.
	userHostsBeginMarker = "# BEGIN coi hosts (managed by coi — edits will be overwritten)"
	userHostsEndMarker   = "# END coi hosts"
)

// renderHostsBlock builds the managed block for the container's /etc/hosts.
// One line per address, so a name backed by several frontend addresses gives the
// resolver all of them to choose between — exactly the set the firewall allows.
// Pure, so it can be tested without a container.
func renderHostsBlock(domainIPs map[string][]string) string {
	domains := make([]string, 0, len(domainIPs))
	for domain := range domainIPs {
		domains = append(domains, domain)
	}
	sort.Strings(domains) // deterministic output: no spurious rewrites

	var b strings.Builder
	b.WriteString(hostsBeginMarker)
	b.WriteString("\n")
	for _, domain := range domains {
		ips := append([]string(nil), domainIPs[domain]...)
		sort.Strings(ips)
		for _, ip := range ips {
			fmt.Fprintf(&b, "%s\t%s\n", ip, domain)
		}
	}
	b.WriteString(hostsEndMarker)
	return b.String()
}

// WriteAllowlistHosts replaces the Coi-managed block in the container's
// /etc/hosts with the given name→address mappings, leaving everything outside the
// markers (localhost, the container's own name) untouched.
//
// The file is rewritten in place via `cat >` rather than `mv` so the inode,
// ownership and permissions survive — some resolvers hold the file open, and
// swapping the inode under them is how you get a container that resolves nothing
// until it is restarted.
func WriteAllowlistHosts(containerName string, domainIPs map[string][]string) error {
	return replaceManagedHostsBlock(containerName, hostsBeginMarker, hostsEndMarker, renderHostsBlock(domainIPs))
}

// renderUserHostsBlock builds the managed block for static user host entries
// ([[network.hosts]] / `coi hosts`). One line per entry: `IP\tname1 name2 …`.
// Pure and deterministic (sorted) so it can be tested and produces no spurious
// rewrites.
func renderUserHostsBlock(entries []config.HostEntry) string {
	sorted := append([]config.HostEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IP < sorted[j].IP })

	var b strings.Builder
	b.WriteString(userHostsBeginMarker)
	b.WriteString("\n")
	for _, e := range sorted {
		names := append([]string(nil), e.Hostnames...)
		sort.Strings(names)
		fmt.Fprintf(&b, "%s\t%s\n", e.IP, strings.Join(names, " "))
	}
	b.WriteString(userHostsEndMarker)
	return b.String()
}

// WriteUserHosts replaces the Coi user-hosts block in the container's /etc/hosts
// with the given entries (an empty slice clears the block), leaving the allowlist
// block and everything else untouched. Works on a running container.
func WriteUserHosts(containerName string, entries []config.HostEntry) error {
	return replaceManagedHostsBlock(containerName, userHostsBeginMarker, userHostsEndMarker, renderUserHostsBlock(entries))
}

// replaceManagedHostsBlock rewrites the container's /etc/hosts in place, replacing
// the block delimited by beginMarker/endMarker with `block` and leaving everything
// outside those markers (localhost, the container's own name, OTHER managed
// blocks) untouched.
//
// The file is rewritten in place via `cat >` rather than `mv` so the inode,
// ownership and permissions survive — some resolvers hold the file open, and
// swapping the inode under them is how you get a container that resolves nothing
// until it is restarted.
func replaceManagedHostsBlock(containerName, beginMarker, endMarker, block string) error {
	// Strip the previous Coi-managed block, then append a fresh one. awk is used
	// deliberately instead of a sed '/BEGIN/,/END/d' range: a sed range deletes
	// through to end-of-file when the END marker is missing, so a truncated or
	// hand-mangled block would take every line after it — including the user's own
	// entries — with it. This awk removes ONLY a properly terminated BEGIN..END
	// block and re-emits an unterminated one untouched, so nothing outside a
	// well-formed block is ever lost. The markers are passed as -v values and
	// matched with index()==1 (literal prefix), so their parentheses and em dash
	// need no regex escaping.
	//
	// The heredoc is quoted ('COI_HOSTS_EOF') so the shell performs no expansion
	// on the content — a domain is not a shell word and must not be treated as one.
	script := fmt.Sprintf(`set -e
tmp=$(mktemp)
awk -v b=%s -v e=%s '
  index($0, b) == 1 { inblock = 1; buf = $0 ORS; next }
  inblock && index($0, e) == 1 { inblock = 0; buf = ""; next }
  inblock { buf = buf $0 ORS; next }
  { print }
  END { if (inblock) printf "%%s", buf }
' /etc/hosts > "$tmp"
cat >> "$tmp" <<'COI_HOSTS_EOF'
%s
COI_HOSTS_EOF
cat "$tmp" > /etc/hosts
rm -f "$tmp"
`, shellSingleQuote(beginMarker), shellSingleQuote(endMarker), block)

	mgr := container.NewManager(containerName)
	if _, err := mgr.ExecCommand(script, container.ExecCommandOptions{Capture: true}); err != nil {
		return fmt.Errorf("failed to write hosts entries: %w", err)
	}
	return nil
}

// shellSingleQuote wraps s in single quotes for safe use as a single shell word,
// escaping any embedded single quote. The hosts markers contain spaces and
// parentheses, so they must be quoted before being passed as awk -v values.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
