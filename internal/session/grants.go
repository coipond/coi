package session

import (
	"fmt"
	"path/filepath"
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
// the container's disk devices, profile-inherited ones included (so a reused
// container's leftover mounts show, and a protection mount that failed
// doesn't), sockets and copied files are the ones forwarded and pushed. Printed
// once at `coi shell` start.
type Grants struct {
	Workspace MountGrant
	Mounts    []MountGrant // every other host disk device: [[mounts]], the worktree common dir, Incus profile disks, ...
	Protected []string     // read-only overlays (protected paths, worktree git internals)
	Masked    []string     // secret_paths hidden from the container
	// DevicesUnread is set when the container's devices could not be read, so
	// Mounts/Protected/Masked fell back to what config asks for.
	DevicesUnread bool

	Sockets     []SocketEntry     // sockets actually forwarded (incl. the SSH agent)
	Credentials []CredentialGrant // [[credentials]] entries
	ToolFiles   []CredentialGrant // the tool's own config and login files (e.g. ~/.claude/.credentials.json)

	Network NetworkGrants
	Ports   []tool.PortInfo

	// Env is filled by the caller (WithEnv): env_commands run after Setup.
	Env EnvGrants

	RunAsRoot         bool
	DockerUnavailable bool
	CPULimit          string
	MemoryLimit       string
	MaxDuration       string
}

// MountGrant is a host path visible in the container.
type MountGrant struct {
	HostPath, ContainerPath string
	Readonly                bool
}

// CredentialGrant is a host file copied into the container. Earlier marks one
// this launch didn't copy that is already in the (reused or resumed) container.
type CredentialGrant struct {
	HostPath, ContainerPath string
	Earlier                 bool
}

// NetworkGrants is the egress the firewall was set up with. Network setup is
// fatal on failure (rules and [[network.hosts]] alike), so a session that
// reaches the report runs with exactly this.
type NetworkGrants struct {
	Mode           string
	AllowedDomains []string
	AllowedPorts   []int
	DNSServers     []string
	Hosts          []config.HostEntry
	LANAccess      bool // allow_local_network_access
	LANBlocked     bool // block_private_networks
	MetadataBlock  bool // block_metadata_endpoint
}

// EnvGrants names the environment variables that carry host or config values
// into the container, by the source that set them. Names only: the report
// never shows values.
type EnvGrants struct {
	FromHost   []string // forward_env
	Minted     []string // env_commands
	Configured []string // [defaults] environment (incl. profile environment)
}

// WithEnv returns a copy of g with Env set. The caller resolves the container
// env after Setup (env_commands run then), so it supplies the names without
// mutating the shared SetupResult.Grants.
func (g *Grants) WithEnv(env EnvGrants) *Grants {
	c := *g
	c.Env = env
	return &c
}

// expandedDiskLister is implemented by *container.Manager; kept out of
// container.ContainerManager so test fakes needn't grow it.
type expandedDiskLister interface {
	ExpandedDiskDevices() (map[string]container.DiskDevice, error)
}

// buildGrants collects the session's effective grants once setup has run.
func buildGrants(st *setupState) *Grants {
	opts := st.opts
	info := st.contextInfo
	g := &Grants{
		Sockets:           st.forwardedSockets,
		Ports:             info.PublishedPorts,
		RunAsRoot:         info.RunAsRoot,
		DockerUnavailable: info.DockerUnavailable,
		CPULimit:          info.CPULimit,
		MemoryLimit:       info.MemoryLimit,
		MaxDuration:       info.MaxDuration,
		Network: NetworkGrants{
			Mode:           info.NetworkMode,
			AllowedDomains: info.AllowedDomains,
			AllowedPorts:   info.AllowedPorts,
			DNSServers:     info.DNSServers,
		},
	}
	if nc := opts.Network.Config; nc != nil {
		g.Network.Hosts = nc.Hosts
		g.Network.LANAccess = config.BoolVal(nc.AllowLocalNetworkAccess)
		g.Network.LANBlocked = config.BoolVal(nc.BlockPrivateNetworks)
		g.Network.MetadataBlock = config.BoolVal(nc.BlockMetadataEndpoint)
	}

	var disks map[string]container.DiskDevice
	var err error
	if lister, ok := st.result.Manager.(expandedDiskLister); ok {
		disks, err = lister.ExpandedDiskDevices()
	}
	if disks != nil && err == nil {
		g.Workspace, g.Mounts, g.Protected, g.Masked = classifyDisks(disks, info.WorkspacePath)
	} else {
		g.DevicesUnread = true
		configuredDisks(g, opts, info.WorkspacePath)
	}

	g.Credentials = grantsOf(st.copiedCredentials)
	g.ToolFiles = grantsOf(st.toolFiles)
	// Only a reused or resumed container can hold files copied by an earlier
	// session; a fresh one can't, so it skips the probe.
	if st.skipLaunch || opts.ResumeFromID != "" {
		creds, tools := uncopiedCandidates(st)
		present := presentInContainer(st.result.Manager, append(append([]CredentialGrant{}, creds...), tools...))
		g.Credentials = append(g.Credentials, filterPresent(creds, present)...)
		g.ToolFiles = append(g.ToolFiles, filterPresent(tools, present)...)
	}
	return g
}

// configuredDisks fills the disk categories from config when the container's
// devices can't be read: the workspace, [[mounts]], a worktree's common dir,
// existing protected paths and secret masks.
func configuredDisks(g *Grants, opts SetupOptions, containerWorkspace string) {
	g.Workspace = MountGrant{HostPath: opts.WorkspacePath, ContainerPath: containerWorkspace}
	if opts.MountConfig != nil {
		for _, m := range opts.MountConfig.Mounts {
			g.Mounts = append(g.Mounts, MountGrant{m.HostPath, m.ContainerPath, m.Readonly})
		}
	}
	// Same existence filter as the setup log line.
	g.Protected = GetProtectedPathsForLogging(opts.WorkspacePath, opts.Security.ProtectedPaths)
	if layout, err := ResolveGitWorktree(opts.WorkspacePath); err == nil && layout != nil {
		g.Mounts = append(g.Mounts, MountGrant{layout.CommonDir, layout.CommonDir, false})
		g.Protected = append(g.Protected, "git internals of "+layout.CommonDir)
	}
	masks, _ := expandSecretPaths(opts.WorkspacePath, opts.Security.SecretPaths)
	for _, m := range masks {
		g.Masked = append(g.Masked, m.relPath)
	}
}

// classifyDisks sorts the container's disk devices into grant categories by
// the device families setup creates. Anything not recognized as a coi
// protection is a mount, so a device added outside coi (or inherited from an
// Incus profile) is still reported.
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

func grantsOf(entries []CredentialEntry) []CredentialGrant {
	var out []CredentialGrant
	for _, e := range entries {
		out = append(out, CredentialGrant{HostPath: e.HostPath, ContainerPath: e.ContainerPath})
	}
	return out
}

// uncopiedCandidates lists the files a reused or resumed container may still
// hold from an earlier session: the configured [[credentials]] destinations and
// the tool's config files that this launch did not copy.
func uncopiedCandidates(st *setupState) (creds, tools []CredentialGrant) {
	copied := map[string]bool{}
	for _, e := range append(append([]CredentialEntry{}, st.copiedCredentials...), st.toolFiles...) {
		copied[e.ContainerPath] = true
	}
	add := func(list *[]CredentialGrant, host, dest string) {
		if !copied[dest] {
			copied[dest] = true
			*list = append(*list, CredentialGrant{HostPath: host, ContainerPath: dest, Earlier: true})
		}
	}
	home := st.result.HomeDir
	if cc := st.opts.CredentialConfig; cc != nil {
		for _, e := range cc.Entries {
			add(&creds, e.HostPath, credentialDestPath(e, home))
		}
	}
	tcf, ok := st.opts.Tool.(tool.ToolWithConfigDirFiles)
	if ok && st.opts.CLIConfigPath != "" && home != "" {
		for _, f := range tcf.EssentialConfigFiles() {
			add(&tools, filepath.Join(st.opts.CLIConfigPath, f), filepath.Join(home, tcf.ConfigDirName(), f))
		}
		if state := tcf.StateConfigFileName(); state != "" {
			add(&tools, filepath.Join(filepath.Dir(st.opts.CLIConfigPath), state), filepath.Join(home, state))
		}
	}
	return creds, tools
}

// presentInContainer reports which candidate destinations exist in the
// container, with one exec for all of them.
func presentInContainer(mgr container.ContainerManager, candidates []CredentialGrant) map[string]bool {
	present := map[string]bool{}
	if len(candidates) == 0 {
		return present
	}
	args := []string{"sh", "-c", `for p; do [ -e "$p" ] && printf '%s\n' "$p"; done`, "sh"}
	for _, c := range candidates {
		args = append(args, c.ContainerPath)
	}
	// The loop exits non-zero when the last path is absent; the output is
	// still the list of present paths.
	out, _ := mgr.ExecArgsCapture(args, container.ExecCommandOptions{})
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			present[line] = true
		}
	}
	return present
}

func filterPresent(candidates []CredentialGrant, present map[string]bool) []CredentialGrant {
	var out []CredentialGrant
	for _, c := range candidates {
		if present[c.ContainerPath] {
			out = append(out, c)
		}
	}
	return out
}

// Render formats the grants as an aligned block for the terminal. The core
// grant categories are always listed, with "none" when empty, so an absent
// grant is stated rather than implied; masks, ports, copied files and limits
// appear only when set. Environment variables are listed by name, never value.
func (g *Grants) Render() string {
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
		mounts = append(mounts, "(could not read the container's devices; showing what config asks for)")
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

	if len(g.Ports) > 0 {
		add("Ports", portLines(g.Ports)...)
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

	if len(g.ToolFiles) > 0 {
		add("Tool config", copiedLines(g.ToolFiles)...)
	}
	if len(g.Credentials) > 0 {
		add("Credentials", copiedLines(g.Credentials)...)
	}

	user := "non-root"
	if g.RunAsRoot {
		user = "root"
	}
	docker := "available"
	if g.DockerUnavailable {
		docker = "unavailable"
	}
	add("Agent", fmt.Sprintf("runs as %s, Docker %s", user, docker))

	var limits []string
	if g.CPULimit != "" {
		limits = append(limits, "cpu "+g.CPULimit)
	}
	if g.MemoryLimit != "" {
		limits = append(limits, "memory "+g.MemoryLimit)
	}
	if g.MaxDuration != "" {
		limits = append(limits, "max duration "+g.MaxDuration)
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

func copiedLines(files []CredentialGrant) []string {
	var lines []string
	for _, c := range files {
		l := fmt.Sprintf("%s -> %s", c.HostPath, c.ContainerPath)
		if c.Earlier {
			l += " (already in the container, not copied this launch)"
		}
		lines = append(lines, l)
	}
	return lines
}

// networkLines describes egress: the mode, then what it lets through. Port
// caps and DNS pins are shown only in the modes whose firewall enforces them,
// as the sandbox context does.
func (g *Grants) networkLines() []string {
	n := g.Network
	mode := config.NetworkMode(n.Mode)
	var lines []string
	switch mode {
	case "", config.NetworkModeOpen:
		lines = append(lines, "open (no egress filtering)")
	case config.NetworkModeAllowlist:
		dests := "nothing"
		if len(n.AllowedDomains) > 0 {
			dests = strings.Join(n.AllowedDomains, ", ")
		}
		lines = append(lines, "allowlist: "+dests)
		// Allowlist mode keys its private/link-local handling off
		// allow_local_network_access alone: with it off, LAN and metadata are
		// rejected; with it on, neither is, whatever the block_* settings say.
		if n.LANAccess {
			lines = append(lines, "LAN allowed (metadata endpoint not blocked)")
		} else {
			lines = append(lines, "LAN and metadata endpoint blocked")
		}
	case config.NetworkModeRestricted:
		lan := "LAN not blocked"
		switch {
		case n.LANAccess:
			lan = "LAN allowed"
		case n.LANBlocked:
			lan = "LAN blocked"
		}
		metadata := "metadata endpoint not blocked"
		if n.MetadataBlock {
			metadata = "metadata endpoint blocked"
		}
		lines = append(lines, "restricted: internet ("+lan+", "+metadata+")")
	default:
		lines = append(lines, n.Mode)
	}
	enforcing := mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist
	if enforcing && len(n.AllowedPorts) > 0 {
		lines = append(lines, "ports "+joinInts(n.AllowedPorts)+" only")
	}
	if mode == config.NetworkModeRestricted && len(n.DNSServers) > 0 {
		lines = append(lines, "DNS pinned to "+strings.Join(n.DNSServers, ", "))
	}
	for _, h := range n.Hosts {
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
