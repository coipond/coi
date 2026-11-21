package network

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Phase 3 (per-destination port scoping) primitives. Where allowed_ports (Phase 2,
// egress.go) caps every destination with one global port set, allowed_domains
// entries may each carry their own ports — "github.com:443",
// "198.51.100.0/24:22", "svc:8000-8100" — which allowlist mode enforces via nft
// concatenated sets (ipv4_addr . inet_service). Private (RFC1918, link-local)
// entries are rejected unless allow_local_network_access, which opens the whole
// RFC1918 LAN, so their ports limit nothing; an address of the host itself is
// the exception (allowlistHostAccepts). These helpers parse the `dest:ports`
// syntax and render the address·port tuples that go into those sets.

// portRange is an inclusive destination-port interval. A single port has Lo==Hi.
type portRange struct{ Lo, Hi uint16 }

// nftValue renders the range as an nft inet_service value: "443" or "8000-8100".
func (r portRange) nftValue() string {
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// allPortsRange is the "no cap" port set — every real TCP/UDP port. Used when an
// entry has no explicit ports and no global allowed_ports applies, so a bare
// allowed_domains entry stays reachable on all ports as it was before Phase 3.
func allPortsRange() []portRange { return []portRange{{Lo: 1, Hi: 65535}} }

// intsToPortRanges lifts the Phase 2 global allowed_ports ([]int) into ranges,
// one single-port range each. The ints are already validated (1..65535); the
// bounds guard makes that explicit (and satisfies the overflow-conversion linter),
// skipping any stray out-of-range value rather than wrapping it.
func intsToPortRanges(ports []int) []portRange {
	out := make([]portRange, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		out = append(out, portRange{Lo: uint16(p), Hi: uint16(p)})
	}
	return out
}

// resolvePorts applies the precedence the user chose: an entry's own ports win;
// otherwise it inherits the global allowed_ports; otherwise all ports. The result
// is always non-empty, so callers never emit a portless (unreachable) tuple.
func resolvePorts(entryPorts, globalPorts []portRange) []portRange {
	if len(entryPorts) > 0 {
		return entryPorts
	}
	if len(globalPorts) > 0 {
		return globalPorts
	}
	return allPortsRange()
}

// parsePortSpec parses the port part of an allowed_domains entry — a comma list of
// single ports and/or lo-hi ranges ("443", "80,443", "8000-8100", "80,8000-8100")
// — into deduplicated, sorted ranges. Every port must be 1..65535 and every range
// must have hi>=lo; anything else is an error so setup fails closed rather than
// installing a surprising rule.
func parsePortSpec(spec string) ([]portRange, error) {
	fields := strings.Split(spec, ",")
	ranges := make([]portRange, 0, len(fields))
	seen := make(map[portRange]bool)
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			return nil, fmt.Errorf("empty port in %q", spec)
		}
		var r portRange
		if lo, hi, ok := strings.Cut(f, "-"); ok {
			l, err := parsePort(lo)
			if err != nil {
				return nil, err
			}
			h, err := parsePort(hi)
			if err != nil {
				return nil, err
			}
			if h < l {
				return nil, fmt.Errorf("port range %q is inverted (%d-%d)", f, l, h)
			}
			r = portRange{Lo: l, Hi: h}
		} else {
			p, err := parsePort(f)
			if err != nil {
				return nil, err
			}
			r = portRange{Lo: p, Hi: p}
		}
		if !seen[r] {
			seen[r] = true
			ranges = append(ranges, r)
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Lo != ranges[j].Lo {
			return ranges[i].Lo < ranges[j].Lo
		}
		return ranges[i].Hi < ranges[j].Hi
	})
	return ranges, nil
}

// parsePort parses a single 1..65535 port.
func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid port number", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is out of range (1-65535)", n)
	}
	return uint16(n), nil
}

// splitDestPorts splits an allowed_domains entry into its destination and optional
// port spec. The destination (IPv4 address, IPv4 CIDR, or hostname) never contains
// a colon, so the first colon unambiguously begins the ports. Returns hasPort=false
// (and nil ports) when the entry carries no ":".
func splitDestPorts(entry string) (dest string, ports []portRange, hasPort bool, err error) {
	// An IPv6 literal is riddled with colons; splitting it on the first one would
	// mangle it into a bogus port. Catch it up front so the user gets the real
	// reason (IPv4-only) instead of a confusing port-parse error.
	if isIPv6Entry(entry) {
		return "", nil, false, fmt.Errorf("%q is an IPv6 address; allowed_domains is IPv4-only", entry)
	}
	dest, spec, found := strings.Cut(entry, ":")
	if !found {
		return entry, nil, false, nil
	}
	if dest == "" {
		return "", nil, false, fmt.Errorf("entry %q has no destination before ':'", entry)
	}
	ports, err = parsePortSpec(spec)
	if err != nil {
		return "", nil, false, fmt.Errorf("in %q: %w", entry, err)
	}
	return dest, ports, true, nil
}

// isIPv6Entry reports whether an allowed_domains entry is an IPv6 address or CIDR.
func isIPv6Entry(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.To4() == nil
	}
	return false
}

// portTupleElem renders one concatenated set element: "<cidr> . <port-or-range>",
// e.g. "10.0.0.0/8 . 22" or "192.168.1.50/32 . 443-8443". The dynamic-set timeout
// attribute, when any, is appended by the set-sync layer.
func portTupleElem(cidr string, r portRange) string {
	return cidr + " . " + r.nftValue()
}
