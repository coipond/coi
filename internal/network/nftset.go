package network

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Allowlist mode keeps a container's permitted destinations in two nft sets
// rather than in one rule per address:
//
//	coi_s_<ip>  static  — literal IPs and CIDRs from allowed_domains. Permanent.
//	coi_d_<ip>  dynamic — addresses learned from DNS answers Coi itself served.
//	                      Each element carries a timeout.
//
// Four rules reference the sets (an L4 rule and a rate-limited ICMP rule per
// set) and never change for the life of the container. Updating the allowlist
// is then an element operation, not a rule rewrite.
//
// This is what closes the fail-closed window the old ReplaceAllowlist
// documented: it appended fresh accept rules *behind* the still-present default
// reject, so a newly-resolved address stayed unreachable until every stale
// handle had been deleted, one sudo-nft exec at a time. With sets there are no
// rules to swap — an added element takes effect atomically, immediately.
//
// Dynamic elements carry a timeout rather than being replaced wholesale so that
// an address rotating out of DNS keeps working for a grace period. Large cloud
// frontends (every Google API endpoint, for instance) round-robin over a pool
// far bigger than any single answer, so a strict replace would keep evicting
// addresses that are still perfectly live and still in use by an open session.
const (
	// dnsElementGrace is the safety margin an element is given ON TOP OF the
	// refresh interval, so it never expires in the gap before the refresher
	// renews it (see elementTimeout). A TTL of 0 — which is what Cloudflare serves
	// for api.anthropic.com — still yields at least a full grace period rather than
	// an element that expires the moment it is installed.
	dnsElementGrace = 10 * time.Minute
	// dnsElementMaxTimeout caps how long a stale address can linger.
	dnsElementMaxTimeout = 12 * time.Hour
)

// nftIdent converts a container IP into a legal nft set identifier.
func nftIdent(containerIP string) string {
	return strings.ReplaceAll(containerIP, ".", "_")
}

func staticSetName(containerIP string) string  { return "coi_s_" + nftIdent(containerIP) }
func dynamicSetName(containerIP string) string { return "coi_d_" + nftIdent(containerIP) }

// The port-scoped (Phase 3) counterparts: concatenated ipv4_addr . inet_service
// sets that carry each destination's permitted ports. The address-only sets above
// stay populated in parallel — they back the per-host ICMP-echo rule (ICMP has no
// port) and CurrentAllowlistCIDRs (the security monitor), both of which are
// per-address. The tuple sets below back only the L4 accept rules.
func staticPortSetName(containerIP string) string  { return "coi_sp_" + nftIdent(containerIP) }
func dynamicPortSetName(containerIP string) string { return "coi_dp_" + nftIdent(containerIP) }

// elementTimeout derives a dynamic element's lifetime from a DNS answer's TTL
// and the interval at which the refresher will re-confirm it.
//
// The element MUST outlive the refresh that renews it. If it expired first it
// would drop out of the firewall while /etc/hosts still pointed at the address,
// so the container would resolve an allowlisted name and have the connection
// rejected — the exact host/container divergence this mode exists to prevent. So
// the lifetime is the TTL plus BOTH a fixed grace and the refresh interval
// itself: even a TTL-0 answer with the interval at its configured cap expires a
// full grace period AFTER the refresh that would have renewed it, never before.
//
// refreshInterval <= 0 means the refresher is disabled. Nothing will ever re-add
// the element, so it is installed permanently (timeout 0) — matching the old
// static-rule behaviour where turning refresh off pinned the allowlist for the
// life of the container, rather than letting it silently lapse after the grace.
func elementTimeout(ttl uint32, refreshInterval time.Duration) time.Duration {
	if refreshInterval <= 0 {
		return 0 // permanent: there is no refresher to renew it
	}
	d := time.Duration(ttl)*time.Second + refreshInterval + dnsElementGrace
	// The cap bounds how long a genuinely dead address lingers, but it must never
	// fall below one refresh-plus-grace, or a long configured interval would
	// recreate the very expiry gap this function exists to close.
	maxTimeout := dnsElementMaxTimeout
	if floor := refreshInterval + dnsElementGrace; floor > maxTimeout {
		maxTimeout = floor
	}
	if d > maxTimeout {
		d = maxTimeout
	}
	return d
}

// ensureAllowlistSets creates the container's static and dynamic sets.
// `nft add set` is idempotent, so this is safe to call repeatedly.
func (f *NftManager) ensureAllowlistSets() error {
	if err := ensureCOITableAndChain(); err != nil {
		return err
	}
	// The static set holds CIDRs, so it needs `flags interval`. The dynamic set
	// holds /32s with per-element expiry, so it needs `flags timeout`. They are
	// kept separate deliberately: combining interval and timeout flags in one
	// set is poorly supported across kernel versions.
	//
	// `auto-merge` is required, not cosmetic: without it the kernel rejects a set
	// whose elements overlap or duplicate ("conflicting intervals specified"), and
	// AddStaticIPs adds every literal entry in one transaction. A perfectly ordinary
	// config — a CIDR plus an address inside it ("142.250.0.0/15" + one of its
	// endpoints), two overlapping published ranges, or the same IP written as both
	// "8.8.8.8" and "8.8.8.8/32" — would otherwise fail the whole transaction, and
	// because setup is fail-closed the container would launch with no egress at all.
	// auto-merge collapses overlaps and duplicates into the covering interval.
	if _, err := runNFTCommand("add", "set", "ip", "coi", staticSetName(f.containerIP),
		"{", "type", "ipv4_addr", ";", "flags", "interval", ";", "auto-merge", ";", "}"); err != nil {
		return fmt.Errorf("failed to create static allowlist set: %w", err)
	}
	if _, err := runNFTCommand("add", "set", "ip", "coi", dynamicSetName(f.containerIP),
		"{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"); err != nil {
		return fmt.Errorf("failed to create dynamic allowlist set: %w", err)
	}
	// Port-scoped concatenated sets (Phase 3). Same interval/timeout split and the
	// same auto-merge rationale as above, now over (address . port) tuples so
	// overlapping ranges or a CIDR-plus-contained-address collapse instead of
	// failing the whole fail-closed transaction.
	if _, err := runNFTCommand("add", "set", "ip", "coi", staticPortSetName(f.containerIP),
		"{", "type", "ipv4_addr", ".", "inet_service", ";", "flags", "interval", ";", "auto-merge", ";", "}"); err != nil {
		return fmt.Errorf("failed to create static port-scoped allowlist set: %w", err)
	}
	// The dynamic port set needs `flags interval` in addition to `timeout`: a name
	// that inherited "all ports" installs the RANGE 1-65535, and nft refuses range
	// elements in a non-interval set. auto-merge collapses the rare overlap when two
	// names resolve to the same address with overlapping port ranges, so a
	// fail-closed transaction never aborts on "conflicting intervals". (Concatenated
	// interval+timeout sets need a modern kernel — the same ~5.6+ the port-scoped
	// sets already require.)
	if _, err := runNFTCommand("add", "set", "ip", "coi", dynamicPortSetName(f.containerIP),
		"{", "type", "ipv4_addr", ".", "inet_service", ";", "flags", "interval", ",", "timeout", ";", "auto-merge", ";", "}"); err != nil {
		return fmt.Errorf("failed to create dynamic port-scoped allowlist set: %w", err)
	}
	return nil
}

// addSetElements adds elements to one of the container's sets. For the dynamic
// set, re-adding an element that is already present updates its timeout rather
// than failing, which is what makes refresh idempotent and cheap.
func (f *NftManager) addSetElements(setName string, elements []string) error {
	if len(elements) == 0 {
		return nil
	}
	args := []string{"add", "element", "ip", "coi", setName, "{", strings.Join(elements, ", "), "}"}
	if _, err := runNFTCommand(args...); err != nil {
		return fmt.Errorf("failed to add elements to %s: %w", setName, err)
	}
	return nil
}

// AddStaticIPs installs the literal address entries from allowed_domains.
// These never expire — the user named them explicitly.
func (f *NftManager) AddStaticIPs(cidrs []string) error {
	if f.containerIP == "" || len(cidrs) == 0 {
		return nil
	}
	sorted := append([]string(nil), cidrs...)
	sort.Strings(sorted) // deterministic, for tests and for readable nft output
	return f.addSetElements(staticSetName(f.containerIP), sorted)
}

// AddStaticTuples installs the port-scoped (address . port) elements for the
// literal allowed_domains entries into the static concatenated set. globalPorts is
// the resolved global allowed_ports (empty = all ports), applied to any entry that
// named no port of its own. Like AddStaticIPs these never expire.
func (f *NftManager) AddStaticTuples(tuples []staticTuple, globalPorts []portRange) error {
	if f.containerIP == "" || len(tuples) == 0 {
		return nil
	}
	var elements []string
	for _, t := range tuples {
		for _, r := range resolvePorts(t.Ports, globalPorts) {
			elements = append(elements, portTupleElem(t.CIDR, r))
		}
	}
	sort.Strings(elements) // deterministic nft output; auto-merge handles overlaps
	return f.addSetElements(staticPortSetName(f.containerIP), elements)
}

// AllowDynamicIPsPorts adds DNS-learned addresses to BOTH the dynamic address set
// (backing ICMP + the security monitor) and the dynamic port-scoped set (backing
// the L4 accepts, one element per address × port-range), sized so each element
// outlives the refresh that will renew it (see elementTimeout). ports is that
// name's permitted set, already resolved through the global-allowed_ports fallback
// (empty is treated as all ports). refreshInterval is the cadence the refresher
// will use — or <= 0 when refresh is disabled, in which case the elements are
// installed permanently. It returns only once the kernel has the addresses, so a
// caller that writes them into the container's /etc/hosts afterwards knows the
// firewall already trusts what it is about to hand over.
//
// The lock is deliberately held across the nft calls. Setup installs the initial
// answers while the background refresher may already be re-resolving on its own
// goroutine, so two calls that touch the same address can overlap. An earlier
// version recorded the addresses in dynSeen, released the lock, and only then
// shelled out to nft — which let a concurrent caller see them as "already
// installed", skip the nft call, and proceed while the first exec was still in
// flight. The container could then be handed an address the kernel set did not
// contain yet: the original bug, reproduced with a smaller window. Serialising
// here costs one exec's latency and buys the invariant the whole design rests on.
//
// dynSeen / dynSeenTuples are what keep this cheap: they record what has already
// been installed and when it expires, so re-syncing a name whose elements still
// have most of their life left costs no exec at all. A permanent element carries
// the zero time: it is never pruned and never re-added.
func (f *NftManager) AllowDynamicIPsPorts(ips []string, ports []portRange, ttl uint32, refreshInterval time.Duration) error {
	if f.containerIP == "" || len(ips) == 0 {
		return nil
	}
	if len(ports) == 0 {
		ports = allPortsRange()
	}

	timeout := elementTimeout(ttl, refreshInterval) // 0 == permanent

	f.dynMu.Lock()
	defer f.dynMu.Unlock()

	if f.dynSeen == nil {
		f.dynSeen = make(map[string]time.Time)
	}
	if f.dynSeenTuples == nil {
		f.dynSeenTuples = make(map[string]time.Time)
	}
	now := time.Now()

	// Address set (backs ICMP + the security monitor): one element per address.
	if err := f.syncDynamicSetLocked(dynamicSetName(f.containerIP), ips, timeout, f.dynSeen, now); err != nil {
		return err
	}
	// Port-scoped set (backs the L4 accepts): one element per (address, port-range).
	tupleKeys := make([]string, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, r := range ports {
			tupleKeys = append(tupleKeys, portTupleElem(ip, r))
		}
	}
	return f.syncDynamicSetLocked(dynamicPortSetName(f.containerIP), tupleKeys, timeout, f.dynSeenTuples, now)
}

// syncDynamicSetLocked installs `keys` into a timeout set, skipping any element
// still fresh per `seen`, and records the new expiries. It is the shared core of
// the dynamic path — the caller holds dynMu and passes the set-specific seen map,
// so the address set and the port-scoped set stay in lockstep under one lock.
//
// The base element string (an address, or an "addr . port" tuple) is also the
// seen-map key; the timeout attribute is appended only in the nft command. See
// AllowDynamicIPsPorts' predecessor for why the exec must not race a concurrent
// caller — serialising under dynMu is what buys the firewall-before-hosts invariant.
func (f *NftManager) syncDynamicSetLocked(setName string, keys []string, timeout time.Duration, seen map[string]time.Time, now time.Time) error {
	// Drop elements whose kernel entries have already expired. Permanent elements
	// carry a zero expiry and are never pruned; without this the map only grows.
	for k, expiry := range seen {
		if !expiry.IsZero() && now.After(expiry) {
			delete(seen, k)
		}
	}

	var stale []string
	for _, k := range keys {
		expiry, known := seen[k]
		switch {
		case !known:
			stale = append(stale, k)
		case expiry.IsZero():
			// already installed permanently — nothing to renew
		case now.After(expiry.Add(-timeout / 2)):
			// past half its life — re-add to reset the kernel timeout so a live
			// element never expires while still in use
			stale = append(stale, k)
		}
	}
	if len(stale) == 0 {
		return nil
	}

	secs := int(timeout.Seconds())
	elements := make([]string, 0, len(stale))
	for _, k := range stale {
		if timeout <= 0 {
			elements = append(elements, k) // permanent: no timeout attribute
		} else {
			elements = append(elements, fmt.Sprintf("%s timeout %ds", k, secs))
		}
	}

	if err := f.addSetElements(setName, elements); err != nil {
		return err
	}

	// Record only after the kernel has them, so a failed exec cannot leave an
	// element marked as installed when it is not.
	for _, k := range stale {
		if timeout <= 0 {
			seen[k] = time.Time{}
		} else {
			seen[k] = now.Add(timeout)
		}
	}
	return nil
}

// CurrentAllowlistCIDRs returns the addresses actually installed in a container's
// allowlist sets right now — the static (literal) set and the dynamic (DNS-learned)
// set combined, as CIDR strings.
//
// This is the firewall's live source of truth. The security monitor consumes it so
// its "is this connection allowed?" decision is made against the exact set the
// firewall enforces, instead of a second, independent DNS resolution that drifts
// from it the moment a rotating cloud frontend hands out a different pool member —
// which would otherwise flag a perfectly legitimate connection and, under
// auto_pause_on_high, pause the container mid-task.
//
// Best-effort and fail-open for the CALLER's fallback: a missing set (open/
// restricted mode, or teardown in progress) yields no elements and no error, so a
// caller can distinguish "empty allowlist" from "could not read" and keep its own
// snapshot on error.
func CurrentAllowlistCIDRs(containerIP string) ([]string, error) {
	if containerIP == "" {
		return nil, nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, set := range []string{staticSetName(containerIP), dynamicSetName(containerIP)} {
		output, err := runNFTCommand("-j", "list", "set", "ip", "coi", set)
		if err != nil {
			if isNftNotFound(err) {
				continue // set not created for this container/mode — not an error
			}
			return nil, fmt.Errorf("failed to read allowlist set %s: %w", set, err)
		}
		cidrs, perr := parseNftSetElemCIDRs(output)
		if perr != nil {
			return nil, fmt.Errorf("failed to parse allowlist set %s: %w", set, perr)
		}
		for _, c := range cidrs {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out, nil
}

// parseNftSetElemCIDRs extracts the element addresses from `nft -j list set …`
// output as CIDR strings. nft renders each element as one of three shapes: a bare
// string ("8.8.8.8"), a prefix object ({"prefix":{"addr","len"}}), or a
// timeout-wrapped element ({"elem":{"val": …}}) whose val is itself one of the
// first two. A bare address is normalised to /32.
func parseNftSetElemCIDRs(jsonOutput []byte) ([]string, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(jsonOutput, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, obj := range doc.Nftables {
		if obj.Set == nil {
			continue
		}
		for _, raw := range obj.Set.Elem {
			if c := nftElemToCIDR(raw); c != "" {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// nftElemToCIDR resolves one raw set element (in any of nft's three JSON shapes)
// to a CIDR string, or "" if it carries no address.
func nftElemToCIDR(raw json.RawMessage) string {
	// Bare address string.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.Contains(s, "/") {
			return s
		}
		return s + "/32"
	}
	var m struct {
		Prefix *struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
		Elem *struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if m.Prefix != nil {
		return fmt.Sprintf("%s/%d", m.Prefix.Addr, m.Prefix.Len)
	}
	if m.Elem != nil {
		return nftElemToCIDR(m.Elem.Val) // timeout-wrapped: unwrap and recurse
	}
	return ""
}

// removeAllowlistSetsForIP deletes a container's allowlist sets.
//
// Rules referencing a set must be gone first or the kernel refuses with EBUSY,
// so callers delete rules before calling this. A set that was never created (a
// container in open or restricted mode) is not an error during teardown.
func removeAllowlistSetsForIP(containerIP string) error {
	if containerIP == "" {
		return nil
	}
	// One listing tells which of the four sets exist, so the common case
	// (open/restricted, no sets) costs one call instead of four failing deletes.
	listing, listErr := runNFTCommand("list", "table", "ip", "coi")
	var firstErr error
	for _, name := range []string{
		staticSetName(containerIP), dynamicSetName(containerIP),
		staticPortSetName(containerIP), dynamicPortSetName(containerIP),
	} {
		if listErr == nil && !strings.Contains(string(listing), "set "+name+" ") {
			continue
		}
		if _, err := runNFTCommand("delete", "set", "ip", "coi", name); err != nil {
			if isNftNotFound(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			logWarnf("Warning: failed to delete nft set %s: %v", name, err)
		}
	}
	return firstErr
}

// isNftNotFound reports whether an nft error means "it isn't there", which is
// success as far as teardown is concerned.
func isNftNotFound(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "No such file") || strings.Contains(msg, "does not exist")
}

// dynAllower is the slice of NftManager the resolver/refresher path needs to
// install DNS-learned addresses (and their per-name ports). Keeping it narrow lets
// the Manager's sync path be tested with a stub in place of real nft.
type dynAllower interface {
	AllowDynamicIPsPorts(ips []string, ports []portRange, ttl uint32, refreshInterval time.Duration) error
}

var _ dynAllower = (*NftManager)(nil)
