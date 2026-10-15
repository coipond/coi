package session

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// Grants is the effective reach of a session: what from the host the container
// can see, write, connect to, or hold. Each category comes from what setup
// actually applied, not from config: mounts and protections are read back from
// the container's disk devices (so a reused container's leftover mounts show,
// and a protection mount that failed doesn't), sockets and credentials are the
// ones forwarded and copied. Printed once at `coi shell` start.
type Grants struct {
	Workspace MountGrant
	Mounts    []MountGrant // every other host disk device: [[mounts]], the worktree common dir, ...
	Protected []string     // read-only overlays (protected paths, worktree git internals)
	Masked    []string     // secret_paths hidden from the container
	// DevicesUnread is set when the container's devices could not be read, so
	// Mounts/Protected fell back to the configured lists.
	DevicesUnread bool

	Sockets     []SocketEntry // sockets actually forwarded (incl. the SSH agent)
	Credentials []CredentialGrant

	Hosts         []config.HostEntry
	LANAccess     bool // allow_local_network_access
	LANBlocked    bool // block_private_networks
	MetadataBlock bool // block_metadata_endpoint

	Env EnvGrants

	Context tool.ContextInfo
}

// MountGrant is a host path visible in the container.
type MountGrant struct {
	HostPath, ContainerPath string
	Readonly                bool
}

// CredentialGrant is a host file copied into the container. Earlier marks one
// this launch didn't copy but that is still there from an earlier session (a
// reused container).
type CredentialGrant struct {
	HostPath, ContainerPath string
	Earlier                 bool
}

// EnvGrants names the environment variables that carry host or config values
// into the container, by source. Names only: the report never shows values.
type EnvGrants struct {
	FromHost   []string // forward_env
	Minted     []string // env_commands
	Configured []string // [defaults] environment (incl. profile environment)
}

// WithEnv returns a copy of g with Env replaced. The caller resolves the
// container env after Setup (env_commands run then), so it supplies the
// authoritative names without mutating the shared SetupResult.Grants.
func (g *Grants) WithEnv(env EnvGrants) *Grants {
	c := *g
	c.Env = env
	return &c
}

// buildGrants collects the session's effective grants once setup has run.
func buildGrants(st *setupState) *Grants {
	opts := st.opts
	info := st.contextInfo
	info.ProfileContext = "" // the report never shows it; don't carry the text
	g := &Grants{
		Sockets: st.forwardedSockets,
		Env:     EnvGrants{FromHost: info.ForwardedEnvVars},
		Context: info,
	}

	var disks map[string]container.DiskDevice
	var err error
	if lister, ok := st.result.Manager.(diskDeviceLister); ok {
		disks, err = lister.DiskDevices()
	}
	if disks != nil && err == nil {
		g.Workspace, g.Mounts, g.Protected, g.Masked = classifyDisks(disks, info.WorkspacePath)
	} else {
		g.DevicesUnread = true
		g.Workspace = MountGrant{HostPath: opts.WorkspacePath, ContainerPath: info.WorkspacePath}
		if opts.MountConfig != nil {
			for _, m := range opts.MountConfig.Mounts {
				g.Mounts = append(g.Mounts, MountGrant{m.HostPath, m.ContainerPath, m.Readonly})
			}
		}
		// Same existence filter as the setup log line.
		g.Protected = GetProtectedPathsForLogging(opts.WorkspacePath, opts.Security.ProtectedPaths)
	}

	for _, c := range st.copiedCredentials {
		g.Credentials = append(g.Credentials, CredentialGrant{HostPath: c.HostPath, ContainerPath: c.ContainerPath})
	}
	if !st.credentialsSeeded && opts.CredentialConfig != nil && len(opts.CredentialConfig.Entries) > 0 {
		g.Credentials = earlierCredentials(st.result.Manager, opts.CredentialConfig.Entries, st.result.HomeDir)
	}

	if nc := opts.Network.Config; nc != nil {
		g.Hosts = nc.Hosts
		g.LANAccess = config.BoolVal(nc.AllowLocalNetworkAccess)
		g.LANBlocked = config.BoolVal(nc.BlockPrivateNetworks)
		g.MetadataBlock = config.BoolVal(nc.BlockMetadataEndpoint)
	}
	return g
}

// classifyDisks sorts the container's disk devices into grant categories by
// the device families setup creates. Anything not recognized as a coi
// protection is a mount, so a device added outside coi is still reported.
func classifyDisks(disks map[string]container.DiskDevice, workspace string) (ws MountGrant, mounts []MountGrant, protected, masked []string) {
	for name, d := range disks {
		switch {
		case d.Source == "":
			// Pool-backed (the root disk): nothing from the host.
		case name == "workspace":
			ws = MountGrant{d.Source, d.Path, d.Readonly}
		case name == gitReadonlyDeviceName:
			// coi's generated read-only gitconfig, not host data.
		case strings.HasPrefix(name, protectDevicePrefix), strings.HasPrefix(name, gitcDevicePrefix):
			protected = append(protected, displayPath(d.Path, workspace))
		case strings.HasPrefix(name, maskDevicePrefix):
			masked = append(masked, displayPath(d.Path, workspace))
		default:
			mounts = append(mounts, MountGrant{d.Source, d.Path, d.Readonly})
		}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].ContainerPath < mounts[j].ContainerPath })
	sort.Strings(protected)
	sort.Strings(masked)
	return ws, mounts, protected, masked
}

// displayPath shows a container path relative to the workspace when under it.
func displayPath(p, workspace string) string {
	if workspace != "" {
		if rel := strings.TrimPrefix(p, strings.TrimSuffix(workspace, "/")+"/"); rel != p {
			return rel
		}
	}
	return p
}

// earlierCredentials reports, for a launch that copied no credentials (a
// reused container), the configured destinations still present in the
// container from an earlier session. One exec checks them all.
func earlierCredentials(mgr container.ContainerManager, entries []CredentialEntry, homeDir string) []CredentialGrant {
	args := []string{"sh", "-c", `for p; do [ -e "$p" ] && printf '%s\n' "$p"; done`, "sh"}
	for _, e := range entries {
		args = append(args, credentialDestPath(e, homeDir))
	}
	out, err := mgr.ExecArgsCapture(args, container.ExecCommandOptions{})
	if err != nil && out == "" {
		return nil
	}
	present := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		present[strings.TrimSpace(line)] = true
	}
	var grants []CredentialGrant
	for _, e := range entries {
		if dest := credentialDestPath(e, homeDir); present[dest] {
			grants = append(grants, CredentialGrant{HostPath: e.HostPath, ContainerPath: dest, Earlier: true})
		}
	}
	return grants
}

// Render formats the grants as an aligned block for the terminal. The core
// grant categories are always listed, with "none" when empty, so an absent
// grant is stated rather than implied; masks, ports, credentials and limits
// appear only when set. Environment variables are listed by name, never value.
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

	add("Workspace", fmt.Sprintf("%s -> %s (%s)", g.Workspace.HostPath, g.Workspace.ContainerPath, rwLabel(g.Workspace.Readonly)))

	mounts := []string{"none"}
	if len(g.Mounts) > 0 {
		mounts = nil
		for _, m := range g.Mounts {
			mounts = append(mounts, fmt.Sprintf("%s -> %s (%s)", m.HostPath, m.ContainerPath, rwLabel(m.Readonly)))
		}
	}
	if g.DevicesUnread {
		mounts = append(mounts, "(could not read the container's devices; showing configured mounts)")
	}
	add("Mounts", mounts...)

	if len(g.Protected) == 0 {
		add("Protected", "none")
	} else {
		add("Protected", strings.Join(g.Protected, ", ")+" (read-only)")
	}
	if len(g.Masked) > 0 {
		add("Masked", strings.Join(g.Masked, ", ")+" (hidden)")
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

	var env []string
	for _, src := range []struct {
		names []string
		label string
	}{{g.Env.FromHost, "from host"}, {g.Env.Minted, "env_commands"}, {g.Env.Configured, "set by config"}} {
		if len(src.names) > 0 {
			env = append(env, strings.Join(src.names, ", ")+" ("+src.label+")")
		}
	}
	if len(env) == 0 {
		env = []string{"none"}
	}
	add("Env", env...)

	if len(g.Credentials) > 0 {
		var lines []string
		for _, c := range g.Credentials {
			l := fmt.Sprintf("%s -> %s", c.HostPath, c.ContainerPath)
			if c.Earlier {
				l += " (from an earlier session, not refreshed)"
			}
			lines = append(lines, l)
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

// networkLines describes egress: the mode, then what it lets through. Port
// caps and DNS pins are shown only in the modes whose firewall enforces them,
// as the sandbox context does.
func (g *Grants) networkLines() []string {
	info := g.Context
	mode := config.NetworkMode(info.NetworkMode)
	var lines []string
	metadata := "metadata endpoint not blocked"
	if g.MetadataBlock {
		metadata = "metadata endpoint blocked"
	}
	switch mode {
	case "", config.NetworkModeOpen:
		lines = append(lines, "open (no egress filtering)")
	case config.NetworkModeAllowlist:
		dests := "nothing"
		if len(info.AllowedDomains) > 0 {
			dests = strings.Join(info.AllowedDomains, ", ")
		}
		lines = append(lines, "allowlist: "+dests)
		if g.LANAccess {
			// Allowlist mode skips its private/link-local rejects entirely when
			// local access is on, whatever block_metadata_endpoint says.
			lines = append(lines, "LAN allowed (metadata endpoint not blocked)")
		}
	case config.NetworkModeRestricted:
		lan := "LAN not blocked"
		switch {
		case g.LANAccess:
			lan = "LAN allowed"
		case g.LANBlocked:
			lan = "LAN blocked"
		}
		lines = append(lines, "restricted: internet ("+lan+", "+metadata+")")
	default:
		lines = append(lines, info.NetworkMode)
	}
	enforcing := mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist
	if enforcing && len(info.AllowedPorts) > 0 {
		lines = append(lines, "ports "+joinInts(info.AllowedPorts)+" only")
	}
	if mode == config.NetworkModeRestricted && len(info.DNSServers) > 0 {
		lines = append(lines, "DNS pinned to "+strings.Join(info.DNSServers, ", "))
	}
	for _, h := range g.Hosts {
		l := "host " + h.IP
		if len(h.Hostnames) > 0 {
			l += " (" + strings.Join(h.Hostnames, ", ") + ")"
		}
		if enforcing && len(h.Ports) > 0 {
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
