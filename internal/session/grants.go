package session

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/tool"
)

// Grants is the effective reach of a session: what from the host the container
// can see, write, connect to, or hold. It is built from the setup state after
// every phase ran (trust gating applied, failed socket forwards dropped,
// protected paths expanded), so it reports what was granted, not what was
// configured. Printed once at `coi shell` start.
type Grants struct {
	WorkspaceHost string
	Mounts        []MountEntry      // extra [[mounts]], after trust gating
	Sockets       []SocketEntry     // sockets actually forwarded (incl. the SSH agent)
	Credentials   []CredentialEntry // [[credentials]] whose host file exists (copied in)
	Hosts         []config.HostEntry
	LANAccess     bool // allow_local_network_access
	LANBlocked    bool // block_private_networks
	MetadataBlock bool // block_metadata_endpoint

	// EnvCommands are the names of [defaults] env_commands variables. They are
	// minted by the CLI at launch, after Setup, so the caller fills them in.
	EnvCommands []string

	Context tool.ContextInfo
}

// buildGrants collects the session's effective grants from the setup state.
func buildGrants(result *SetupResult, opts SetupOptions, forwardedSockets []SocketEntry) *Grants {
	g := &Grants{
		WorkspaceHost: opts.WorkspacePath,
		Sockets:       forwardedSockets,
		Context:       contextInfoFor(result, opts),
	}
	if opts.MountConfig != nil {
		g.Mounts = opts.MountConfig.Mounts
	}
	if opts.CredentialConfig != nil {
		for _, c := range opts.CredentialConfig.Entries {
			// seedHostFile skips a missing host file, so only an existing one
			// was copied in.
			if _, err := os.Stat(c.HostPath); err == nil {
				g.Credentials = append(g.Credentials, c)
			}
		}
	}
	if nc := opts.Network.Config; nc != nil {
		g.Hosts = nc.Hosts
		g.LANAccess = config.BoolVal(nc.AllowLocalNetworkAccess)
		g.LANBlocked = config.BoolVal(nc.BlockPrivateNetworks)
		g.MetadataBlock = config.BoolVal(nc.BlockMetadataEndpoint)
	}
	return g
}

// Render formats the grants as an aligned block for the terminal. The core
// grant categories are always listed, with "none" when empty, so an absent
// grant is stated rather than implied; limits, ports and credentials appear
// only when set. Environment variables are listed by name, never value.
func (g *Grants) Render() string {
	info := g.Context
	var rows [][2]string
	add := func(label string, lines ...string) {
		for i, l := range lines {
			if i > 0 {
				label = ""
			}
			rows = append(rows, [2]string{label, l})
		}
	}

	add("Workspace", fmt.Sprintf("%s -> %s (read-write)", g.WorkspaceHost, info.WorkspacePath))

	if len(g.Mounts) == 0 {
		add("Mounts", "none")
	} else {
		var lines []string
		for _, m := range g.Mounts {
			lines = append(lines, fmt.Sprintf("%s -> %s (%s)", m.HostPath, m.ContainerPath, rwLabel(m.Readonly)))
		}
		add("Mounts", lines...)
	}

	// Same existence filter as the setup log line: a configured path missing
	// from the workspace has nothing to protect.
	if shown := GetProtectedPathsForLogging(g.WorkspaceHost, info.ProtectedPaths); len(shown) == 0 {
		add("Protected", "none")
	} else {
		add("Protected", strings.Join(shown, ", ")+" (read-only)")
	}

	add("Network", g.networkLines()...)

	if len(info.PublishedPorts) > 0 {
		add("Ports", portLines(info.PublishedPorts)...)
	}

	if len(g.Sockets) == 0 {
		add("Sockets", "none")
	} else {
		var lines []string
		for _, s := range g.Sockets {
			l := fmt.Sprintf("%s -> %s", s.HostPath, s.ContainerPath)
			if s.EnvVar != "" {
				l += " (" + s.EnvVar + ")"
			}
			lines = append(lines, l)
		}
		add("Sockets", lines...)
	}

	envLine := "none"
	if len(info.ForwardedEnvVars) > 0 {
		envLine = strings.Join(info.ForwardedEnvVars, ", ") + " (from host)"
	}
	add("Env", envLine)
	if len(g.EnvCommands) > 0 {
		add("", strings.Join(g.EnvCommands, ", ")+" (env_commands)")
	}

	if len(g.Credentials) > 0 {
		var lines []string
		for _, c := range g.Credentials {
			lines = append(lines, fmt.Sprintf("%s -> %s", c.HostPath, credentialDest(c, info.HomeDir)))
		}
		add("Credentials", lines...)
	}

	user := "non-root"
	if info.RunAsRoot {
		user = "root"
	}
	docker := "available"
	if info.DockerUnavailable {
		docker = "unavailable"
	}
	add("Agent", fmt.Sprintf("runs as %s, Docker %s", user, docker))

	var limits []string
	if info.CPULimit != "" {
		limits = append(limits, "cpu "+info.CPULimit)
	}
	if info.MemoryLimit != "" {
		limits = append(limits, "memory "+info.MemoryLimit)
	}
	if info.MaxDuration != "" {
		limits = append(limits, "max duration "+info.MaxDuration)
	}
	if len(limits) > 0 {
		add("Limits", strings.Join(limits, ", "))
	}

	width := 0
	for _, r := range rows {
		width = max(width, len(r[0]))
	}
	var b strings.Builder
	b.WriteString("Effective grants:\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, r[0], r[1])
	}
	return b.String()
}

// networkLines describes egress: the mode, then what it lets through.
func (g *Grants) networkLines() []string {
	info := g.Context
	var lines []string
	switch config.NetworkMode(info.NetworkMode) {
	case "", config.NetworkModeOpen:
		return []string{"open (no egress filtering)"}
	case config.NetworkModeAllowlist:
		dests := "nothing"
		if len(info.AllowedDomains) > 0 {
			dests = strings.Join(info.AllowedDomains, ", ")
		}
		lines = append(lines, "allowlist: "+dests)
	case config.NetworkModeRestricted:
		var notes []string
		switch {
		case g.LANAccess:
			notes = append(notes, "LAN allowed")
		case g.LANBlocked:
			notes = append(notes, "LAN blocked")
		default:
			notes = append(notes, "LAN not blocked")
		}
		if g.MetadataBlock {
			notes = append(notes, "metadata endpoint blocked")
		}
		lines = append(lines, "restricted: internet ("+strings.Join(notes, ", ")+")")
	default:
		lines = append(lines, info.NetworkMode)
	}
	if g.LANAccess && config.NetworkMode(info.NetworkMode) == config.NetworkModeAllowlist {
		lines = append(lines, "LAN allowed")
	}
	if len(info.AllowedPorts) > 0 {
		lines = append(lines, "ports "+joinInts(info.AllowedPorts)+" only")
	}
	if len(info.DNSServers) > 0 {
		lines = append(lines, "DNS pinned to "+strings.Join(info.DNSServers, ", "))
	}
	for _, h := range g.Hosts {
		l := "host " + h.IP
		if len(h.Hostnames) > 0 {
			l += " (" + strings.Join(h.Hostnames, ", ") + ")"
		}
		if len(h.Ports) > 0 {
			l += " on ports " + joinInts(h.Ports)
		}
		lines = append(lines, l)
	}
	return lines
}

func portLines(ports []tool.PortInfo) []string {
	var lines, pool []string
	for _, p := range ports {
		if p.Pool {
			pool = append(pool, strconv.Itoa(p.HostPort))
			continue
		}
		listen := p.Listen
		if listen == "" {
			listen = "127.0.0.1"
		}
		lines = append(lines, fmt.Sprintf("%s: container %d -> host %s:%d", p.Name, p.ContainerPort, listen, p.HostPort))
	}
	if len(pool) > 0 {
		lines = append(lines, "pool: "+strings.Join(pool, ", ")+" (same number on host)")
	}
	return lines
}

func credentialDest(c CredentialEntry, homeDir string) string {
	if strings.HasPrefix(c.ContainerPath, "/") || homeDir == "" {
		return c.ContainerPath
	}
	return strings.TrimSuffix(homeDir, "/") + "/" + c.ContainerPath
}

func rwLabel(readonly bool) string {
	if readonly {
		return "read-only"
	}
	return "read-write"
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

// SortedKeys returns m's keys in order, for listing env var names.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
