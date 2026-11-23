package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// runtimeHostPortsKey records the ports of each `coi hosts add --ports` entry on
// the container ("<ip>=<port>,<port> ..."), so the monitors in the session's own
// coi process see that runtime permit. ApplyUserHosts clears it at setup, with
// the firewall it describes.
const runtimeHostPortsKey = "user.coi.host_ports"

// ExplicitPortPermits answers "did the user name this exact port for this
// destination?" for the monitors' suspicious-port check. Unlike EgressPermits it
// ignores inherited ports: only a [[network.hosts]] entry with its own ports (in
// config, or added with `coi hosts add --ports`), or an allowed_domains entry
// with a :ports suffix, counts. A host entry without ports, the global
// allowed_ports and allow_local_network_access do not.
//
// A name entry follows the addresses the firewall installs for it: Start
// re-reads the container's IP cache, which the allowlist refresher saves with
// every answer it installs. Every address seen for the name stays permitted, as
// the firewall keeps a rotated-out address for a grace period.
type ExplicitPortPermits struct {
	containerName string
	static        []explicitPortPermit
	namePorts     map[string][]portRange

	mu   sync.RWMutex
	seen map[string]bool // name + " " + address, already in live
	live []explicitPortPermit
	// runtime holds the `coi hosts add --ports` entries; nil until read.
	runtime []explicitPortPermit
}

type explicitPortPermit struct {
	dst   *net.IPNet
	ports []portRange
}

// loadNameAddresses returns the addresses the firewall installed for each
// allowlisted name of the container (its saved IP cache).
var loadNameAddresses = func(containerName string) (map[string][]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cache, err := NewCacheManager(homeDir).Load(containerName)
	if err != nil {
		return nil, err
	}
	return cache.Domains, nil
}

// readRuntimeHostPorts returns the container's runtimeHostPortsKey value.
var readRuntimeHostPorts = func(containerName string) (string, error) {
	return container.ConfigGetUncached(context.Background(), containerName, runtimeHostPortsKey)
}

// NewExplicitPortPermits collects the explicit port permits of containerName
// from the [[network.hosts]] entries and, in allowlist mode, from the compiled
// allowed_domains policy (nil otherwise). resolved maps each policy name to the
// addresses the monitor resolved for it at start; Start adds later ones.
func NewExplicitPortPermits(containerName string, hosts []config.HostEntry, policy *AllowPolicy, resolved map[string][]string) *ExplicitPortPermits {
	p := &ExplicitPortPermits{containerName: containerName, namePorts: map[string][]portRange{}, seen: map[string]bool{}}
	p.static = hostEntryPermits(hosts)
	if policy == nil {
		return p
	}
	for _, t := range policy.staticTuples() {
		if len(t.Ports) == 0 {
			continue
		}
		if dst := parseHostOrCIDR(t.CIDR); dst != nil {
			p.static = append(p.static, explicitPortPermit{dst: dst, ports: t.Ports})
		}
	}
	for _, name := range policy.Names() {
		if ports := policy.portsForName(name); len(ports) > 0 {
			p.namePorts[name] = ports
		}
	}
	p.addNameAddresses(resolved)
	return p
}

// Start reads the name addresses and runtime host ports now and then every
// interval until ctx is done.
func (p *ExplicitPortPermits) Start(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			p.refresh()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (p *ExplicitPortPermits) refresh() {
	if len(p.namePorts) > 0 {
		if domains, err := loadNameAddresses(p.containerName); err == nil {
			p.addNameAddresses(domains)
		}
	}
	value, err := readRuntimeHostPorts(p.containerName)
	if err != nil {
		return // keep the last good read
	}
	runtime := hostEntryPermits(parseRuntimeHostPorts(value))
	p.mu.Lock()
	p.runtime = runtime
	p.mu.Unlock()
}

func (p *ExplicitPortPermits) addNameAddresses(domains map[string][]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, ports := range p.namePorts {
		for _, addr := range domains[name] {
			key := name + " " + addr
			if p.seen[key] {
				continue
			}
			if dst := parseHostOrCIDR(addr); dst != nil {
				p.seen[key] = true
				p.live = append(p.live, explicitPortPermit{dst: dst, ports: ports})
			}
		}
	}
}

// Permits reports whether proto ("tcp"/"udp", any case; "tcp6"/"udp6" too)
// traffic to ip:port has an explicit port permit.
func (p *ExplicitPortPermits) Permits(proto, ipStr string, port int) bool {
	proto = strings.TrimSuffix(strings.ToLower(proto), "6")
	if proto != "tcp" && proto != "udp" {
		return false
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	if permitsAny(p.static, ip, port) {
		return true
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return permitsAny(p.live, ip, port) || permitsAny(p.runtime, ip, port)
}

func permitsAny(entries []explicitPortPermit, ip net.IP, port int) bool {
	for _, e := range entries {
		if !e.dst.Contains(ip) {
			continue
		}
		for _, r := range e.ports {
			if port >= int(r.Lo) && port <= int(r.Hi) {
				return true
			}
		}
	}
	return false
}

// hostEntryPermits returns the permits of the host entries that carry ports.
func hostEntryPermits(hosts []config.HostEntry) []explicitPortPermit {
	var out []explicitPortPermit
	for _, h := range hosts {
		if len(h.Ports) == 0 {
			continue
		}
		if dst := parseHostOrCIDR(h.IP); dst != nil {
			out = append(out, explicitPortPermit{dst: dst, ports: intsToPortRanges(h.Ports)})
		}
	}
	return out
}

// formatRuntimeHostPorts renders entries with ports as a runtimeHostPortsKey
// value.
func formatRuntimeHostPorts(entries []config.HostEntry) string {
	var fields []string
	for _, e := range entries {
		if len(e.Ports) == 0 {
			continue
		}
		ports := make([]string, len(e.Ports))
		for i, port := range e.Ports {
			ports[i] = strconv.Itoa(port)
		}
		fields = append(fields, fmt.Sprintf("%s=%s", e.IP, strings.Join(ports, ",")))
	}
	return strings.Join(fields, " ")
}

// parseRuntimeHostPorts reads a runtimeHostPortsKey value. A malformed field is
// skipped, which can only leave a port without its permit.
func parseRuntimeHostPorts(value string) []config.HostEntry {
	var out []config.HostEntry
	for _, field := range strings.Fields(value) {
		ip, list, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		var ports []int
		for _, s := range strings.Split(list, ",") {
			if port, err := strconv.Atoi(s); err == nil && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
		if len(ports) > 0 {
			out = append(out, config.HostEntry{IP: ip, Ports: ports})
		}
	}
	return out
}

// parseHostOrCIDR reads an IPv4 address (as a /32) or an IPv4 CIDR.
func parseHostOrCIDR(s string) *net.IPNet {
	if strings.Contains(s, "/") {
		ip, n, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			return nil
		}
		return n
	}
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
}
