package session

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/mensfeld/coi/internal/tool"
)

// Auto-allocation layout for published host ports (#558): each workspace gets
// a stable 100-port neighborhood derived from its hash (the same identity
// container names use), each slot a 10-port block inside it, each published
// port one index of that block:
//
//	host = 20000 + (hash % 400)*100 + (slot-1)*10 + index
//
// Deterministic with no coordination state: parallel slots of one workspace
// and different workspaces sharing a profile land on distinct, stable ports
// by construction. The pool occupies the block's first indices and is
// identity-mapped (container port == host port), so the agent and the user
// use the SAME number. A busy port (unrelated host process, or the rare
// cross-workspace hash collision) is skipped forward within the block for
// auto entries; pinned entries never move — they abort the session instead.
const (
	autoPortBase     = 20000
	neighborhoods    = 400
	neighborhoodSize = 100
	slotStride       = 10
)

// PublishedPort describes one resolved (and, after publish, live) port
// mapping, for env exposure and the sandbox context file.
type PublishedPort struct {
	Name          string
	HostPort      int
	ContainerPort int
	Listen        string // host listen address, e.g. "127.0.0.1"
	EnvVar        string // COI_PORT_<NAME> for map entries; "" for pool ports (exposed via COI_PORTS)
	Pool          bool   // true for identity-mapped pool ports
	DeviceName    string
}

// AllocateHostPort computes the deterministic host port for the index-th
// entry of the given workspace and slot.
func AllocateHostPort(workspacePath, sessionName string, slot, index int) int {
	h := IdentityHash(workspacePath, sessionName)
	n, err := strconv.ParseUint(h[:4], 16, 32)
	if err != nil {
		n = 0 // cannot happen for a hex hash; keep allocation total anyway
	}
	neighborhood := int(n) % neighborhoods
	return autoPortBase + neighborhood*neighborhoodSize + (slot-1)*slotStride + index
}

// portEnvVar converts a port name to its env var: COI_PORT_<NAME>, with
// non-alphanumerics mapped to underscores.
func portEnvVar(name string) string {
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, name)
	return "COI_PORT_" + strings.ToUpper(mapped)
}

func portDeviceName(name string) string {
	return "coi-port-" + strings.ToLower(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, name))
}

// DescribeDroppedPort renders a trust-gated dropped port for warnings. The
// dropped pool is reported by FilterTrusted as a synthetic entry with
// ContainerPort 0, which would otherwise print as a nonsensical
// `"pool(3)" container:0`.
func DescribeDroppedPort(p PortEntry) string {
	if p.ContainerPort == 0 {
		return "port " + p.Name // synthetic pool entry, e.g. "pool of 3 ports"
	}
	return fmt.Sprintf("port %q (container:%d)", p.Name, p.ContainerPort)
}

// hostPortFree bind-probes a host port. Overridable in unit tests.
var hostPortFree = func(listen string, port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort(listen, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// ResolvePorts turns a PortConfig into concrete host-port assignments,
// bind-probing each candidate on the host BEFORE any container work:
//
//   - pinned map entries (Host > 0) are probed exactly; a taken pinned port
//     is a hard error — a pin means pin.
//   - pool ports and auto map entries take their deterministic slot-block
//     index, skipping forward within the block when a port happens to be
//     busy (the actual numbers are announced via env and the context file
//     every session, so exactness is a nicety, not a contract).
//
// The probe is a UX layer, not a guarantee: another process can grab a port
// between this check and the proxy device binding, in which case the publish
// step still fails loudly for that entry.
func ResolvePorts(pc *PortConfig, workspacePath, sessionName string, slot int) ([]PublishedPort, error) {
	if !pc.HasPorts() {
		return nil, nil
	}

	// The allocation layout only holds for slots inside one workspace
	// neighborhood; a larger (or non-positive) slot would silently compute
	// ports inside ANOTHER workspace's block. Container naming tolerates any
	// --slot value, so this is checked here, where it becomes harmful.
	if maxSlots := neighborhoodSize / slotStride; slot < 1 || slot > maxSlots {
		return nil, fmt.Errorf("[ports] requires a slot between 1 and %d (got %d): auto-allocated ports are laid out in per-slot blocks of %d", maxSlots, slot, slotStride)
	}

	autoNeeded := pc.Pool
	for _, e := range pc.Ports {
		if e.HostPort == 0 {
			autoNeeded++
		}
	}
	if autoNeeded > slotStride {
		return nil, fmt.Errorf("[ports] declares %d auto-allocated ports (pool %d + %d unpinned map entries); at most %d per slot — pin 'host' explicitly for the rest",
			autoNeeded, pc.Pool, autoNeeded-pc.Pool, slotStride)
	}

	var resolved []PublishedPort
	nextIdx := 0
	takeAuto := func(listen string) (int, error) {
		for ; nextIdx < slotStride; nextIdx++ {
			candidate := AllocateHostPort(workspacePath, sessionName, slot, nextIdx)
			if hostPortFree(listen, candidate) {
				nextIdx++
				return candidate, nil
			}
		}
		return 0, fmt.Errorf("no free port left in this slot's block (%d-%d) — other processes are using them",
			AllocateHostPort(workspacePath, sessionName, slot, 0), AllocateHostPort(workspacePath, sessionName, slot, slotStride-1))
	}

	// Pool first: identity-mapped, so the agent binds the very number the
	// user opens on localhost.
	for i := 0; i < pc.Pool; i++ {
		port, err := takeAuto("127.0.0.1")
		if err != nil {
			return nil, fmt.Errorf("port pool: %w", err)
		}
		resolved = append(resolved, PublishedPort{
			Name:          fmt.Sprintf("pool-%d", i+1),
			HostPort:      port,
			ContainerPort: port, // identity mapping
			Listen:        "127.0.0.1",
			Pool:          true,
			DeviceName:    portDeviceName(fmt.Sprintf("pool-%d", i+1)),
		})
	}

	// Device and env names are derived from entry names by a LOSSY mapping
	// (non-alphanumerics collapse), and merged configs can carry entries from
	// several scopes that per-profile validation never saw together — so
	// near-duplicates ("web_1" vs "web-1", or a literal "pool-1" vs the
	// pool's synthetic device) must be a hard error here, not a silent
	// last-writer-wins clobber at publish time.
	seenDevice := map[string]string{}
	seenEnv := map[string]string{}
	for _, p := range resolved { // the pool's synthetic names claim theirs first
		seenDevice[p.DeviceName] = p.Name
	}
	for _, e := range pc.Ports {
		if prev, ok := seenDevice[portDeviceName(e.Name)]; ok {
			return nil, fmt.Errorf("ports.map %q collides with %q: both map to device %q — rename one", e.Name, prev, portDeviceName(e.Name))
		}
		seenDevice[portDeviceName(e.Name)] = e.Name
		if prev, ok := seenEnv[portEnvVar(e.Name)]; ok {
			return nil, fmt.Errorf("ports.map %q collides with %q: both map to env var %s — rename one", e.Name, prev, portEnvVar(e.Name))
		}
		seenEnv[portEnvVar(e.Name)] = e.Name
	}

	for _, e := range pc.Ports {
		listen := e.Listen
		if listen == "" {
			listen = "127.0.0.1"
		}
		host := e.HostPort
		if host > 0 {
			if !hostPortFree(listen, host) {
				return nil, fmt.Errorf("host port %d (ports.map %q) is already in use — free it or change the pin", host, e.Name)
			}
		} else {
			var err error
			host, err = takeAuto(listen)
			if err != nil {
				return nil, fmt.Errorf("ports.map %q: %w", e.Name, err)
			}
		}
		resolved = append(resolved, PublishedPort{
			Name:          e.Name,
			HostPort:      host,
			ContainerPort: e.ContainerPort,
			Listen:        listen,
			EnvVar:        portEnvVar(e.Name),
			DeviceName:    portDeviceName(e.Name),
		})
	}
	return resolved, nil
}

// portPublisher is the slice of the container API port publishing needs;
// kept small so it can be faked in unit tests (like socketForwarder).
type portPublisher interface {
	AddHostPortDevice(name, listenAddr string, hostPort, containerPort int) error
}

// portDeviceScrubber is the container API slice RemoveStalePortDevices needs.
type portDeviceScrubber interface {
	ListDevices() ([]string, error)
	RemoveDevice(name string) error
}

// RemoveStalePortDevices strips ALL coi-port-* proxy devices from a reused
// container BEFORE ports are resolved. This matters twice over: the previous
// session's devices re-bind their host ports the moment the container runs,
// so a later bind-probe would see the session's OWN ports as busy (pinned
// entries would hard-fail every reuse, pool numbers would drift); and devices
// whose entries were renamed, deleted, or newly dropped by the trust gate
// would otherwise keep publishing forever. The current session's devices are
// re-added by PublishResolvedPorts. No-op on containers without port devices.
func RemoveStalePortDevices(mgr portDeviceScrubber, logger func(string)) {
	devices, err := mgr.ListDevices()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not list devices to clean stale port publications: %v", err))
		return
	}
	for _, d := range devices {
		if strings.HasPrefix(d, "coi-port-") {
			if err := mgr.RemoveDevice(d); err != nil {
				logger(fmt.Sprintf("Warning: could not remove stale port device %s: %v", d, err))
			}
		}
	}
}

// PublishResolvedPorts attaches a proxy device per resolved port and returns
// the live set plus the session env: COI_PORT_<NAME> per map entry and
// COI_PORTS with the space-separated pool numbers. Per-entry failures (a
// port grabbed since the preflight) are logged as warnings, not fatal — the
// entry is simply absent so env and context stay truthful. Reused containers
// have their previous port devices stripped up front (RemoveStalePortDevices,
// before the bind-probe), so publishing is a plain add.
func PublishResolvedPorts(mgr portPublisher, resolved []PublishedPort, logger func(string)) ([]PublishedPort, map[string]string) {
	if len(resolved) == 0 {
		return nil, nil
	}
	var published []PublishedPort
	env := map[string]string{}
	var poolPorts []string
	for _, p := range resolved {
		if err := mgr.AddHostPortDevice(p.DeviceName, p.Listen, p.HostPort, p.ContainerPort); err != nil {
			logger(fmt.Sprintf("Warning: could not publish port %q (%s:%d -> container:%d): %v — was the host port grabbed since preflight?",
				p.Name, p.Listen, p.HostPort, p.ContainerPort, err))
			continue
		}
		published = append(published, p)
		if p.Pool {
			poolPorts = append(poolPorts, strconv.Itoa(p.HostPort))
			logger(fmt.Sprintf("Published pool port: localhost:%d <-> container:%d", p.HostPort, p.ContainerPort))
		} else {
			env[p.EnvVar] = strconv.Itoa(p.HostPort)
			logger(fmt.Sprintf("Published port %q: %s:%d -> container:%d (%s)", p.Name, p.Listen, p.HostPort, p.ContainerPort, p.EnvVar))
		}
	}
	if len(poolPorts) > 0 {
		env["COI_PORTS"] = strings.Join(poolPorts, " ")
	}
	return published, env
}

// publishedPortInfos converts the session's published ports into the tool
// package's context-file shape.
func publishedPortInfos(ports []PublishedPort) []tool.PortInfo {
	out := make([]tool.PortInfo, 0, len(ports))
	for _, p := range ports {
		out = append(out, tool.PortInfo{
			Name:          p.Name,
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Listen:        p.Listen,
			Pool:          p.Pool,
			EnvVar:        p.EnvVar,
		})
	}
	return out
}
