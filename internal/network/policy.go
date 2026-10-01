package network

import (
	"fmt"
	"net"
	"strings"
)

// AllowPolicy is the compiled form of [network] allowed_domains.
//
// It splits the configured entries into the two things allowlist mode treats
// differently:
//
//   - Literal addresses (raw IPv4, CIDR) go straight into the container's static
//     nft set. They involve no name resolution at all.
//   - Names are resolved once, on the host. Their addresses go into the dynamic
//     nft set AND into the container's /etc/hosts. With DNS egress blocked, that
//     hosts file is the container's only route from a name to an address — so the
//     two sides cannot disagree, and the container cannot reach an address the
//     firewall has not already been given.
type AllowPolicy struct {
	staticCIDRs []string
	staticTups  []staticTuple
	exact       map[string]bool
	names       []string
	namePorts   map[string][]portRange
}

// staticTuple is a literal address entry paired with the ports it may be reached
// on. Ports is nil when the allowed_domains entry named no port — meaning "inherit
// the global allowed_ports (else all ports)", resolved at set-build time.
type staticTuple struct {
	CIDR  string
	Ports []portRange
}

// NewAllowPolicy compiles allowed_domains entries into an AllowPolicy.
//
// Accepted entry forms (each optionally suffixed with :ports — a comma list of
// single ports and/or lo-hi ranges, e.g. ":443", ":80,443", ":8000-8100"):
//
//	1.2.3.4              raw IPv4 address
//	10.0.0.0/8           IPv4 CIDR
//	api.example.com      exact hostname
//	github.com:443       hostname reachable only on 443
//	192.168.1.50:8080    address reachable only on 8080
//
// A per-entry port set scopes that destination (Phase 3); an entry with no port
// inherits the global allowed_ports, else all ports. Wildcards are rejected — see
// the error text below for why, and for what to write instead.
func NewAllowPolicy(entries []string) (*AllowPolicy, error) {
	p := &AllowPolicy{exact: make(map[string]bool), namePorts: make(map[string][]portRange)}

	for _, raw := range entries {
		dest, ports, _, err := splitDestPorts(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid entry in allowed_domains: %w", err)
		}
		entry := strings.ToLower(dest)
		entry = strings.TrimSuffix(entry, ".")
		if entry == "" {
			continue
		}

		switch {
		case strings.Contains(entry, "/"):
			ip, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q in allowed_domains: %w", raw, err)
			}
			// To4() alone is not enough: it returns non-nil for IPv4-mapped IPv6
			// networks such as ::ffff:0:0/96, which ParseCIDR normalises to
			// 0.0.0.0/0. A 4-byte net.IP is the only reliable IPv4 signal.
			if ip.To4() == nil || len(ipNet.IP) != net.IPv4len {
				return nil, fmt.Errorf("%q is an IPv6 CIDR; allowed_domains is IPv4-only", raw)
			}
			p.staticCIDRs = append(p.staticCIDRs, ipNet.String())
			p.staticTups = append(p.staticTups, staticTuple{CIDR: ipNet.String(), Ports: ports})

		case net.ParseIP(entry) != nil:
			ip := net.ParseIP(entry)
			if ip.To4() == nil {
				return nil, fmt.Errorf("%q is an IPv6 address; allowed_domains is IPv4-only", raw)
			}
			cidr := ip.To4().String() + "/32"
			p.staticCIDRs = append(p.staticCIDRs, cidr)
			p.staticTups = append(p.staticTups, staticTuple{CIDR: cidr, Ports: ports})

		case strings.Contains(entry, "*"):
			// Wildcards cannot be honoured, so they are rejected rather than
			// quietly mishandled.
			//
			// Allowlist mode resolves each name up front and writes the answer into
			// the container's /etc/hosts, which — with DNS blocked — is the only
			// place the container can get an address from. A wildcard has no answer
			// to write: you cannot know which subdomains will be asked for, so there
			// is nothing to put in the file and nothing to put in the firewall.
			// Supporting one would require a live resolver running for the whole life
			// of the container, which is exactly the moving part this design removes.
			//
			// The previous implementation pretended otherwise: it stripped the "*."
			// and resolved the BASE domain, whose addresses have no overlap at all
			// with the subdomains actually dialled (googleapis.com resolves to
			// 142.250.130.x; us-central1-aiplatform.googleapis.com to 172.217.112-119.4).
			// The result was a firewall that permitted a set of addresses nothing
			// would ever connect to, and a user who believed they were covered.
			// Failing loudly is strictly better than that.
			return nil, fmt.Errorf(
				"wildcard %q in allowed_domains is not supported: allowlist mode resolves each name up front, "+
					"so it cannot know which subdomains a wildcard will cover. List the exact hostnames "+
					"(for example \"us-central1-aiplatform.googleapis.com\", \"oauth2.googleapis.com\"), "+
					"or allow the provider's published IP ranges as CIDRs (for example \"142.250.0.0/15\")", raw)

		default:
			p.exact[entry] = true
			p.names = append(p.names, entry)
			p.namePorts[entry] = ports
		}
	}

	return p, nil
}

// StaticCIDRs returns the literal address entries, in CIDR form, for the static
// (address-only) nft set. Raw IPs come back as /32. Ports are not carried here —
// this set backs ICMP reachability and the security monitor, which are per-address.
func (p *AllowPolicy) StaticCIDRs() []string { return p.staticCIDRs }

// staticTuples returns the literal address entries paired with their per-entry
// ports (nil = inherit global), for the port-scoped concatenated nft set.
func (p *AllowPolicy) staticTuples() []staticTuple { return p.staticTups }

// Names returns the hostname entries. These are resolved on the host; the answers
// go into both the container's dynamic nft set and its /etc/hosts.
func (p *AllowPolicy) Names() []string { return p.names }

// portsForName returns the per-entry ports configured for a hostname (nil =
// inherit global), keyed by the same normalised name Names() returns.
func (p *AllowPolicy) portsForName(name string) []portRange { return p.namePorts[name] }
