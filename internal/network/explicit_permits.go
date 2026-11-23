package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
)

// runtimeHostPortsPath is the host file that records the ports of each
// `coi hosts add --ports` entry of a container ("<ip>=<port>,<port> ..."), so
// the monitors in the session's own coi process see that runtime permit. It
// sits next to the container's IP cache. ClearRuntimeHostPorts removes it at
// every session setup, with the firewall it describes.
func runtimeHostPortsPath(containerName string) string {
	return filepath.Join(defaultCacheManager().cacheDir, containerName+".host-ports")
}

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
// the firewall keeps a rotated-out address for a grace period. The runtime
// entries are read from their host record only when a suspicious port has no
// other permit, at most once per runtimeHostPortsTTL.
type ExplicitPortPermits struct {
	containerName string
	static        []explicitPortPermit
	namePorts     map[string][]portRange

	mu   sync.RWMutex
	seen map[string]bool // name + " " + address, already in live
	live []explicitPortPermit

	// runtimeMu guards the `coi hosts add --ports` entries and when they were
	// last read (zero: never).
	runtimeMu   sync.Mutex
	runtime     []explicitPortPermit
	runtimeRead time.Time
}

// runtimeHostPortsTTL is how long a read of the runtime host ports is reused.
const runtimeHostPortsTTL = 5 * time.Second

type explicitPortPermit struct {
	dst   *net.IPNet
	ports []portRange
}

// loadNameAddresses returns the addresses the firewall installed for each
// allowlisted name of the container (its saved IP cache).
var loadNameAddresses = func(containerName string) (map[string][]string, error) {
	cache, err := defaultCacheManager().Load(containerName)
	if err != nil {
		return nil, err
	}
	return cache.Domains, nil
}

// readRuntimeHostPorts returns the container's runtime host ports record
// (empty when there is none).
var readRuntimeHostPorts = func(containerName string) (string, error) {
	data, err := os.ReadFile(runtimeHostPortsPath(containerName))
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(data), err
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

// Start reads the name addresses now and then every interval until ctx is
// done. Without a name entry with ports there is nothing to read.
func (p *ExplicitPortPermits) Start(ctx context.Context, interval time.Duration) {
	if len(p.namePorts) == 0 {
		return
	}
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
	if domains, err := loadNameAddresses(p.containerName); err == nil {
		p.addNameAddresses(domains)
	}
}

// runtimePermits reports whether a `coi hosts add --ports` entry permits
// ip:port, reading the record when the last read is older than
// runtimeHostPortsTTL. A failed read keeps the last good entries.
func (p *ExplicitPortPermits) runtimePermits(ip net.IP, port int) bool {
	p.runtimeMu.Lock()
	defer p.runtimeMu.Unlock()
	if time.Since(p.runtimeRead) >= runtimeHostPortsTTL {
		p.runtimeRead = time.Now()
		if value, err := readRuntimeHostPorts(p.containerName); err == nil {
			p.runtime = hostEntryPermits(parseRuntimeHostPorts(value))
		}
	}
	return permitsAny(p.runtime, ip, port)
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
	live := permitsAny(p.live, ip, port)
	p.mu.RUnlock()
	return live || p.runtimePermits(ip, port)
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

// formatRuntimeHostPorts renders entries with ports as a runtime host ports
// record.
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

// parseRuntimeHostPorts reads a runtime host ports record. A malformed field is
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
