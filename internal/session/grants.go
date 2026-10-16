package session

import (
	"fmt"
	"os"
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
	// LeftoversUnchecked is set when a reused or resumed container could not
	// be checked for files an earlier session copied in, so Credentials and
	// ToolFiles list only this launch's copies.
	LeftoversUnchecked bool

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

// MountGrant is a host path, or an Incus storage volume, visible in the
// container.
type MountGrant struct {
	HostPath, ContainerPath string
	Readonly                bool
	// Pool is set for a storage-pool volume; HostPath then holds the volume
	// name, which is not a host path.
	Pool string
}

// source describes where the mount comes from.
func (m MountGrant) source() string {
	if m.Pool != "" {
		return "volume " + m.Pool + "/" + m.HostPath
	}
	return m.HostPath
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
// into the agent's environment, by the source that set them. Names only: the
// report never shows values.
type EnvGrants struct {
	// Set per exec by the caller (WithEnv), from the config env layers.
	FromHost   []string // forward_env
	Minted     []string // env_commands
	Configured []string // [defaults] environment (incl. profile environment)
	// Set by buildGrants.
	Tool      []string // the tool's own env from [tool] config, set on every launch
	Container []string // the container's environment.* (git identity, Incus profiles, ...)
	// Attaching is set when the tool is already running in a tmux session the
	// launch attaches to: it keeps the env it started with, so none of the
	// above was applied to it this launch.
	Attaching bool
}

// WithEnv returns a copy of g with the per-exec env layers set. The caller
// resolves them after Setup (env_commands run then), so it supplies the names
// without mutating the shared SetupResult.Grants. attaching marks a launch
// that only attaches to an already-running tool.
func (g *Grants) WithEnv(env EnvGrants, attaching bool) *Grants {
	c := *g
	c.Env.FromHost, c.Env.Minted, c.Env.Configured = env.FromHost, env.Minted, env.Configured
	c.Env.Attaching = attaching
	return &c
}

// appliedStateReader is implemented by *container.Manager; kept out of
// container.ContainerManager so test fakes needn't grow it.
type appliedStateReader interface {
	AppliedState() (container.AppliedState, error)
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

	// The container's applied config: disks (profile-inherited included), its
	// environment.* and whether nesting (which Docker needs) is on. A reused
	// container keeps what it was created with, so this, not the current
	// config, is what the agent has.
	var applied *container.AppliedState
	if r, ok := st.result.Manager.(appliedStateReader); ok {
		if a, err := r.AppliedState(); err == nil && a.Disks != nil {
			applied = &a
		}
	}
	if applied != nil {
		g.Workspace, g.Mounts, g.Protected, g.Masked = classifyDisks(applied.Disks, info.WorkspacePath)
		g.DockerUnavailable = !applied.Nesting
		g.Env.Container = applied.EnvNames
	} else {
		g.DevicesUnread = true
		configuredDisks(g, opts, info.WorkspacePath)
	}
	g.Env.Tool = toolEnvNames(opts.Tool, st.result.ContainerWorkspacePath)

	g.Credentials = grantsOf(st.copiedCredentials)
	g.ToolFiles = grantsOf(st.toolFiles)
	if lc := st.leftovers; lc.planned {
		g.LeftoversUnchecked = !lc.checked
		g.Credentials = append(g.Credentials, filterPresent(lc.creds, lc.present)...)
		g.ToolFiles = append(g.ToolFiles, filterPresent(lc.tools, lc.present)...)
	}
	return g
}

// toolEnvNames lists the env the tool sets for itself from its config (e.g. a
// profile's [tool] model or API settings); the shell passes it on every exec.
func toolEnvNames(t tool.Tool, workspacePath string) []string {
	twce, ok := t.(tool.ToolWithContainerEnv)
	if !ok {
		return nil
	}
	if workspacePath == "" {
		workspacePath = "/workspace"
	}
	var names []string
	for k := range twce.GetContainerEnv(workspacePath) {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// configuredDisks fills the disk categories from config when the container's
// devices can't be read: the workspace, [[mounts]], a worktree's common dir,
// protected paths and secret masks.
func configuredDisks(g *Grants, opts SetupOptions, containerWorkspace string) {
	g.Workspace = MountGrant{HostPath: opts.WorkspacePath, ContainerPath: containerWorkspace}
	if opts.MountConfig != nil {
		for _, m := range opts.MountConfig.Mounts {
			g.Mounts = append(g.Mounts, MountGrant{HostPath: m.HostPath, ContainerPath: m.ContainerPath, Readonly: m.Readonly})
		}
	}
	// Same existence filter as the setup log line. Setup has already
	// materialized placeholders for missing default paths (.vscode, ...), so
	// those exist by now and are listed, like their protect- devices would be.
	g.Protected = GetProtectedPathsForLogging(opts.WorkspacePath, opts.Security.ProtectedPaths)
	if layout, err := ResolveGitWorktree(opts.WorkspacePath); err == nil && layout != nil {
		g.Mounts = append(g.Mounts, MountGrant{HostPath: layout.CommonDir, ContainerPath: layout.CommonDir})
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
			// The root disk: nothing from the host.
		case name == "workspace":
			ws = MountGrant{HostPath: d.Source, ContainerPath: d.Path, Readonly: d.Readonly}
		case name == gitReadonlyDeviceName:
			// coi's generated read-only gitconfig, not host data.
		case strings.HasPrefix(name, protectDevicePrefix), strings.HasPrefix(name, gitcDevicePrefix):
			protected = append(protected, displayPath(d.Path, workspace))
		case strings.HasPrefix(name, maskDevicePrefix):
			masked = append(masked, displayPath(d.Path, workspace))
		default:
			// Includes storage-pool volumes (pool set, source naming the
			// volume): not host data, but storage the container shares with
			// whatever else attaches it, so still a grant.
			mounts = append(mounts, MountGrant{HostPath: d.Source, ContainerPath: d.Path, Readonly: d.Readonly, Pool: d.Pool})
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
	// Tool files only when the host has the file: the tool and coi's settings
	// merge also create files in its config dir (settings.json, CLAUDE.md),
	// which are not host copies. [[credentials]] destinations are the user's
	// own paths, so a stale copy of a since-deleted host file still counts.
	tcf, ok := st.opts.Tool.(tool.ToolWithConfigDirFiles)
	if ok && st.opts.CLIConfigPath != "" && home != "" {
		addIfOnHost := func(host, dest string) {
			if _, err := os.Stat(host); err == nil {
				add(&tools, host, dest)
			}
		}
		essential, state := toolHostFiles(st.opts.CLIConfigPath, home, tcf)
		for _, f := range append(essential, state) {
			if f.HostPath != "" {
				addIfOnHost(f.HostPath, f.ContainerPath)
			}
		}
	}
	return creds, tools
}

// leftoverCheck is the check, on a reused or resumed container, for files an
// earlier session copied in that this launch didn't.
type leftoverCheck struct {
	planned bool
	creds   []CredentialGrant
	tools   []CredentialGrant
	present map[string]bool
	checked bool // the check ran to the end
}

// Markers leftoverCheckOp prints.
const (
	leftoverPresentMarker = "coi:leftover-present:"
	leftoverCheckedMarker = "coi:leftovers-checked"
)

// planLeftoverCheck works out the candidates and returns the guest op that
// checks for them. Only a reused or resumed container can hold files copied by
// an earlier session, so a fresh one gets no op.
func (st *setupState) planLeftoverCheck() (guestOp, bool) {
	if !st.skipLaunch && st.opts.ResumeFromID == "" {
		return guestOp{}, false
	}
	creds, tools := uncopiedCandidates(st)
	if len(creds)+len(tools) == 0 {
		return guestOp{}, false
	}
	st.leftovers = leftoverCheck{planned: true, creds: creds, tools: tools}
	var paths []string
	for _, c := range append(append([]CredentialGrant{}, creds...), tools...) {
		paths = append(paths, c.ContainerPath)
	}
	return leftoverCheckOp(paths), true
}

// leftoverCheckOp prints a marker line for each path that exists, then a
// final marker, so the output tells "absent" apart from "never checked". It
// always succeeds, so it can't fail the batch it rides in.
func leftoverCheckOp(paths []string) guestOp {
	var b strings.Builder
	b.WriteString("for p in")
	for _, p := range paths {
		b.WriteString(" " + shellEscape(p))
	}
	fmt.Fprintf(&b, `; do [ -e "$p" ] && printf '%s%%s\n' "$p"; done; echo %s`, leftoverPresentMarker, leftoverCheckedMarker)
	return guestCmd(b.String())
}

// parse reads leftoverCheckOp's output from the batch's combined output.
func (lc *leftoverCheck) parse(out string) {
	if !lc.planned {
		return
	}
	lc.present = map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if p, ok := strings.CutPrefix(line, leftoverPresentMarker); ok {
			lc.present[p] = true
		} else if line == leftoverCheckedMarker {
			lc.checked = true
		}
	}
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
			mounts = append(mounts, fmt.Sprintf("%s -> %s (%s)", m.source(), m.ContainerPath, rwLabel(m.Readonly)))
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

	add("Env", g.envLines()...)

	if len(g.ToolFiles) > 0 {
		add("Tool config", copiedLines(g.ToolFiles)...)
	}
	creds := copiedLines(g.Credentials)
	if g.LeftoversUnchecked {
		creds = append(creds, "(could not check the container for files copied by earlier sessions)")
	}
	if len(creds) > 0 {
		add("Credentials", creds...)
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

// envLines lists each variable once, under the source the agent's value
// comes from: the tool's own env overrides the config layers (it is merged in
// last), and any per-exec value overrides the container's environment.*.
func (g *Grants) envLines() []string {
	if g.Env.Attaching {
		return []string{"unchanged: attaching to the running session, which keeps the env it started with"}
	}
	seen := map[string]bool{}
	var lines []string
	for _, src := range []struct {
		names []string
		label string
	}{
		{g.Env.Tool, "tool settings"},
		{g.Env.FromHost, "from host"},
		{g.Env.Minted, "env_commands"},
		{g.Env.Configured, "set by config"},
		{g.Env.Container, "container environment"},
	} {
		var names []string
		for _, n := range src.names {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			lines = append(lines, strings.Join(names, ", ")+" ("+src.label+")")
		}
	}
	if len(lines) == 0 {
		return []string{"none"}
	}
	return lines
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
