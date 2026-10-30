package session

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/limits"
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
	DockerUnavailable bool // follows the container's nesting, not config
	// DockerConfigDiffers is set when the container's nesting disagrees with
	// what the current config asks for: a reused container keeps what it was
	// created with until restarted, and an Incus profile can set nesting
	// itself, which a restart doesn't change. DockerSource says which (see
	// dockerSourceInstance and co.).
	DockerConfigDiffers bool
	DockerSource        string
	// DockerNotReconciled is set for an explicit --container attach, whose
	// restart deliberately leaves the container's config as it is.
	DockerNotReconciled bool
	// Limits are the resource limits the container runs with ("cpu 2",
	// "memory 4GiB", "disk read 10MB", ...); MaxDuration is per session.
	Limits      []string
	MaxDuration string
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
// this launch didn't copy that an earlier session did and that is still in the
// reused container; Changed marks such a copy whose content has changed in the
// container since (a refreshed token, or something else now at that path).
type CredentialGrant struct {
	HostPath, ContainerPath string
	Earlier, Changed        bool
	// Unverified marks an Earlier file in a container with no copy manifest
	// (created before coi recorded copies): it may or may not be a copy.
	Unverified bool
	// Restored marks a tool file put back from a saved session on resume.
	Restored bool
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
	// Launch says how the tool gets this env (see ToolLaunch).
	Launch ToolLaunch
}

// ToolLaunch is how a launch reaches the tool, which decides whether the env
// above reaches it.
type ToolLaunch int

const (
	// ToolStarted means the tool starts with this launch's env.
	ToolStarted ToolLaunch = iota
	// ToolAttached means attaching to the tool already running in tmux, which keeps
	// the env it started with; the session env is updated, so the names reach
	// panes opened from now on.
	ToolAttached
	// ToolSentToPane means a background launch into an existing tmux session types
	// the tool command into its pane, whose shell keeps its env; again only
	// new panes get the names.
	ToolSentToPane
)

// WithEnv returns a copy of g with the per-exec env layers set. The caller
// resolves them after Setup (env_commands run then), so it supplies the names
// without mutating the shared SetupResult.Grants.
func (g *Grants) WithEnv(env EnvGrants, launch ToolLaunch) *Grants {
	c := *g
	c.Env.FromHost, c.Env.Minted, c.Env.Configured = env.FromHost, env.Minted, env.Configured
	c.Env.Launch = launch
	return &c
}

// appliedStateReader is implemented by *container.Manager; kept out of
// container.ContainerManager so test fakes needn't grow it.
type appliedStateReader interface {
	AppliedState() (container.AppliedState, error)
}

// readAppliedState reads the container's applied config, or nil when it can't.
func readAppliedState(mgr container.ContainerManager) *container.AppliedState {
	if r, ok := mgr.(appliedStateReader); ok {
		if a, err := r.AppliedState(); err == nil && a.Disks != nil {
			return &a
		}
	}
	return nil
}

// startAppliedRead reads the applied config in the background. Setup calls it
// after its last instance-config write, so the read (one `incus config show
// --expanded`, cold after those writes) overlaps the file copies that follow
// instead of adding to startup; awaitApplied collects it.
func (st *setupState) startAppliedRead() {
	ch := make(chan *container.AppliedState, 1)
	mgr := st.result.Manager
	go func() { ch <- readAppliedState(mgr) }()
	st.appliedRead = sync.OnceValue(func() *container.AppliedState { return <-ch })
}

// awaitApplied returns the applied config, reading it now if no background
// read was started.
func (st *setupState) awaitApplied() *container.AppliedState {
	if st.appliedRead == nil {
		mgr := st.result.Manager
		st.appliedRead = sync.OnceValue(func() *container.AppliedState { return readAppliedState(mgr) })
	}
	st.result.applied = st.appliedRead()
	return st.result.applied
}

// nestingSourceReader is implemented by *container.Manager.
type nestingSourceReader interface {
	NestingSetLocally() (set, ok bool)
}

// Where a nesting setting that disagrees with config comes from, which
// decides what to tell the user.
const (
	dockerSourceInstance = "instance" // the container's own (or default) setting: a restart applies config
	dockerSourceProfile  = "profile"  // an Incus profile sets it (a restart overrides it only to enable Docker)
	dockerSourceUnknown  = ""         // couldn't tell
)

// dockerSource works out where the container's nesting comes from. Only
// called when it disagrees with config, so the extra read is rare.
func dockerSource(mgr container.ContainerManager, applied *container.AppliedState) string {
	if !applied.NestingSet {
		return dockerSourceInstance // unset: Incus's default, which the restart reconcile overrides
	}
	if r, ok := mgr.(nestingSourceReader); ok {
		if set, ok := r.NestingSetLocally(); ok {
			if set {
				return dockerSourceInstance
			}
			return dockerSourceProfile
		}
	}
	return dockerSourceUnknown
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
	// environment.*, nesting (which Docker needs) and limits. A reused
	// container keeps what it was created with, so this, not the current
	// config, is what the agent has.
	containerWorkspace := ContainerWorkspace(st.result)
	if applied := st.awaitApplied(); applied != nil {
		g.Workspace, g.Mounts, g.Protected, g.Masked = classifyDisks(applied.Disks, containerWorkspace)
		// DockerUnavailable stays info's, which already follows the applied
		// nesting (dockerUnavailable), so the context file can't disagree.
		g.DockerConfigDiffers = g.DockerUnavailable != !hardeningPolicyFrom(&opts).DockerEnabled()
		if g.DockerConfigDiffers {
			g.DockerSource = dockerSource(st.result.Manager, applied)
			g.DockerNotReconciled = opts.ContainerName != ""
		}
		g.Env.Container = applied.EnvNames
		// Limits are applied only when a container is created, so a reused
		// one runs with its own, whatever config says now. max_duration is
		// per session (the timeout monitor), so it stays from config.
		g.Limits = limitLines(applied.Limits, rootSizeEnforced(applied.RootPool))
	} else {
		g.DevicesUnread = true
		configuredDisks(g, opts, containerWorkspace, st.result.worktreeWritableHooks)
		if info.CPULimit != "" {
			g.Limits = append(g.Limits, "cpu "+info.CPULimit)
		}
		if info.MemoryLimit != "" {
			g.Limits = append(g.Limits, "memory "+info.MemoryLimit)
		}
	}
	g.Env.Tool = toolEnvNames(opts.Tool, containerWorkspace)

	g.Credentials = grantsOf(st.copiedCredentials)
	g.ToolFiles = grantsOf(st.toolFiles)
	for _, r := range st.liveRestored() {
		g.ToolFiles = append(g.ToolFiles, CredentialGrant{HostPath: r.HostPath, ContainerPath: r.ContainerPath, Restored: true})
	}
	if lc := st.leftovers; lc.planned {
		g.LeftoversUnchecked = !lc.checked
		g.Credentials = append(g.Credentials, lc.creds...)
		g.ToolFiles = append(g.ToolFiles, lc.tools...)
	}
	return g
}

// limitNames labels the container.LimitKeys for the report.
var limitNames = map[string]string{
	"limits.cpu":                "cpu",
	"limits.cpu.allowance":      "cpu allowance",
	"limits.cpu.priority":       "cpu priority",
	"limits.memory":             "memory",
	"limits.memory.enforce":     "memory enforce",
	"limits.memory.swap":        "swap",
	"limits.processes":          "processes",
	"root.limits.read":          "disk read",
	"root.limits.write":         "disk write",
	"root.limits.max":           "disk I/O",
	"root.limits.disk.priority": "disk priority",
	"root.size":                 "disk size",
}

// limitLines formats the limits the container runs with. Memory enforcement
// qualifies the memory limit: "soft" lets the container exceed it while the
// host has memory to spare (Incus's own default is hard), so it is shown with
// the limit; alone it caps nothing. Swap is listed only when turned off (on is
// the default). A root disk size is flagged when its pool can't enforce it.
func limitLines(limits map[string]string, sizeEnforced func() (bool, string)) []string {
	var lines []string
	for _, k := range container.LimitKeys {
		v, ok := limits[k]
		if !ok {
			continue
		}
		switch k {
		case "limits.memory":
			if limits["limits.memory.enforce"] == "soft" {
				v += " (soft: may be exceeded while the host has memory free)"
			}
		case "limits.memory.enforce":
			continue // shown with the memory limit
		case "limits.memory.swap":
			if v == "true" {
				continue
			}
		case "root.size":
			if sizeEnforced != nil {
				if enforced, why := sizeEnforced(); !enforced {
					v += " (" + why + ")"
				}
			}
		}
		lines = append(lines, limitNames[k]+" "+v)
	}
	return lines
}

// listStoragePools is container.ListStoragePools; a var so tests can fake it.
var listStoragePools = container.ListStoragePools

// rootSizeEnforced returns a check of whether the root disk's pool enforces a
// size quota, as coi's own [limits.disk] size requires (#728); a profile can
// set one on a pool that doesn't. The pool list is fetched only if asked, so
// only when a size is set.
func rootSizeEnforced(pool string) func() (bool, string) {
	return func() (bool, string) {
		pools, err := listStoragePools()
		if err != nil || pool == "" {
			return false, "could not check that its pool enforces it"
		}
		for _, p := range pools {
			if p.Name == pool {
				if limits.PoolDriverEnforcesQuota(p.Driver) {
					return true, ""
				}
				return false, "not enforced: pool " + pool + " uses the " + p.Driver + " driver"
			}
		}
		return false, "could not check that its pool enforces it"
	}
}

// toolEnvNames lists the env the tool sets for itself from its config (e.g. a
// profile's [tool] model or API settings); the shell passes it on every exec.
func toolEnvNames(t tool.Tool, workspacePath string) []string {
	var names []string
	for k := range ToolContainerEnv(t, workspacePath) {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ToolContainerEnv is the env the tool sets for itself (nil for a tool with
// none). The shell merges it into every exec and the grants report names it,
// so both get it from here.
func ToolContainerEnv(t tool.Tool, workspacePath string) map[string]string {
	if twce, ok := t.(tool.ToolWithContainerEnv); ok {
		return twce.GetContainerEnv(workspacePath)
	}
	return nil
}

// ContainerWorkspace is the workspace path in the container, /workspace for a
// result that doesn't record one (older containers).
func ContainerWorkspace(result *SetupResult) string {
	if result != nil && result.ContainerWorkspacePath != "" {
		return result.ContainerWorkspacePath
	}
	return "/workspace"
}

// configuredDisks fills the disk categories from config when the container's
// devices can't be read: the workspace, [[mounts]], a worktree's common dir,
// protected paths and secret masks.
func configuredDisks(g *Grants, opts SetupOptions, containerWorkspace string, writableHooks bool) {
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
		// The same paths setup protects (and the device read lists), so the
		// row keeps its shape whether or not the devices could be read.
		for _, rel := range commonDirProtectedPaths(layout.CommonDir, writableHooks, opts.Security.Config) {
			g.Protected = append(g.Protected, filepath.Join(layout.CommonDir, rel))
		}
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
		case isParentPin(name, d, disks["workspace"], workspace):
			// A dir already granted, mounted over itself: no new host data.
		// coi's protections and masks are always read-only; a writable disk
		// that merely shares the name prefix (e.g. from an Incus profile) is
		// a mount, and must be listed as one.
		case d.Readonly && (strings.HasPrefix(name, protectDevicePrefix) || strings.HasPrefix(name, gitcDevicePrefix)):
			protected = append(protected, displayPath(d.Path, workspace))
		case d.Readonly && strings.HasPrefix(name, maskDevicePrefix):
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

// isParentPin reports whether d is a parent pin from parentPinMounts: named
// after its path, and mounting a workspace dir (or a git common dir, mounted
// at its host path) at the same place, so a writable look-alike is a mount.
func isParentPin(name string, d, ws container.DiskDevice, workspace string) bool {
	if name != pinDeviceName(d.Path) {
		return false
	}
	if d.Source == d.Path {
		return true
	}
	rel := displayPath(d.Path, workspace)
	return ws.Source != "" && rel != d.Path && d.Source == filepath.Join(ws.Source, rel)
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

// Copy manifest kinds: which report row a recorded copy belongs to.
const (
	copyKindCredential = "c" // a [[credentials]] entry
	copyKindTool       = "t" // the tool's own config or login file
)

// copyRecord is a host file copied into the container this launch.
type copyRecord struct {
	kind string
	CredentialEntry
}

func copyRecords(kind string, entries []CredentialEntry) []copyRecord {
	var out []copyRecord
	for _, e := range entries {
		out = append(out, copyRecord{kind, e})
	}
	return out
}

// copyManifestPath is the file recording each host file coi copied into the
// container (after an optional copyManifestComplete line), one line per
// container path:
//
//	<sha256> <kind> <container path>\t<host path>
//
// the hash taken once setup's writes to the file were done. Root-owned,
// outside the home dir. The leftover check reads it, so files an earlier
// session copied are found even after config stopped naming them, a file the
// image, the tool or the agent put at the same path isn't mistaken for a copy,
// and a copy since changed is told apart from one still as copied. A var only
// so tests can point it at a temp file.
var copyManifestPath = "/var/lib/coi/copied-host-files"

// recordCopiesOp records this launch's copies in copyManifestPath, replacing
// any earlier line for the same container path. Best-effort: a failure only
// means a later reuse can't vouch for those files, so it never fails the
// batch it rides in.
func recordCopiesOp(copies []copyRecord) (guestOp, bool) {
	copies = manifestSafe(copies)
	if len(copies) == 0 {
		return guestOp{}, false
	}
	m := shellEscape(copyManifestPath)
	var b strings.Builder
	// Any earlier line for the path goes either way: this launch replaced
	// that file, so the old hash and host path no longer describe it. A new
	// line is written only with a real hash (the destination readable, and
	// the hash non-empty: the pipeline's status is cut's, so a failed
	// sha256sum alone wouldn't stop an empty one).
	fmt.Fprintf(&b, `{ mkdir -p %s && touch %s && rec() { h=; [ -r "$2" ] && h=$(sha256sum < "$2" | cut -c1-64); `+
		`P="$2" awk -F '\t' 'substr($1, 68) != ENVIRON["P"]' %s > %s.new || return 0; `+
		`[ -z "$h" ] || printf '%%s %%s %%s\t%%s\n' "$h" "$1" "$2" "$3" >> %s.new; mv -f %s.new %s; }`,
		shellEscape(filepath.Dir(copyManifestPath)), m, m, m, m, m, m)
	for _, c := range copies {
		fmt.Fprintf(&b, "; rec %s %s %s", c.kind, shellEscape(c.ContainerPath), shellEscape(c.HostPath))
	}
	b.WriteString("; } 2>/dev/null || true")
	return guestCmd(b.String()), true
}

// manifestSafe drops copies whose paths hold a tab or newline, which the
// manifest's line format can't carry; such a copy goes unrecorded rather than
// garbling the manifest and the report.
func manifestSafe(copies []copyRecord) []copyRecord {
	var out []copyRecord
	for _, c := range copies {
		if !strings.ContainsAny(c.ContainerPath+c.HostPath, "\t\n") {
			out = append(out, c)
		}
	}
	return out
}

// Markers leftoverCheckOp prints: "<marker><kind>\t<container path>\t<host path>".
const (
	leftoverSameMarker    = "coi:leftover-same:"    // recorded, content unchanged
	leftoverChangedMarker = "coi:leftover-changed:" // recorded, content changed since
	leftoverUnknownMarker = "coi:leftover-unknown:" // no manifest; present, origin unknown
	leftoverCheckedMarker = "coi:leftovers-checked"
)

// leftoverCheck is the check, on a reused container, for host files an
// earlier session copied in that this launch didn't.
type leftoverCheck struct {
	planned bool
	creds   []CredentialGrant
	tools   []CredentialGrant
	checked bool // the check ran to the end
}

// planLeftoverCheck returns the guest op that checks for leftovers. Only a
// reused container can hold files an earlier session copied (a resumed
// session in a new container gets its saved files back by restore, which
// the report lists itself), so a new container gets no op.
func (st *setupState) planLeftoverCheck() (guestOp, bool) {
	if !st.skipLaunch {
		return guestOp{}, false
	}
	st.leftovers = leftoverCheck{planned: true}
	var exclude []string
	for _, c := range st.copiesThisLaunch() {
		exclude = append(exclude, c.ContainerPath)
	}
	return leftoverCheckOp(exclude, st.unrecordedCandidates()), true
}

// unrecordedCandidates are the host files config would copy, for a container
// without a manifest (created before coi recorded copies): there, a file at
// one of these paths may or may not be a copy, so it is listed as such. Only
// files the host has: with no manifest to go by, that keeps an image's own
// files at a configured path out unless the host has one too.
func (st *setupState) unrecordedCandidates() []copyRecord {
	var out []copyRecord
	add := func(kind, host, dest string) {
		if _, err := os.Stat(host); err == nil {
			out = append(out, copyRecord{kind, CredentialEntry{HostPath: host, ContainerPath: dest}})
		}
	}
	home := st.result.HomeDir
	if cc := st.opts.CredentialConfig; cc != nil {
		for _, e := range cc.Entries {
			add(copyKindCredential, e.HostPath, credentialDestPath(e, home))
		}
	}
	tcf, ok := st.opts.Tool.(tool.ToolWithConfigDirFiles)
	if ok && st.opts.CLIConfigPath != "" && home != "" {
		essential, state := toolHostFiles(st.opts.CLIConfigPath, home, tcf)
		for _, f := range append(essential, state) {
			if f.HostPath != "" {
				add(copyKindTool, f.HostPath, f.ContainerPath)
			}
		}
	}
	return out
}

// copyManifestComplete is the manifest line marking a manifest that covers
// every copy since the container was created (coi created it with recording
// on). Without it, the container may hold copies older coi versions made
// unrecorded.
const copyManifestComplete = "#complete"

// markManifestCompleteOp marks the manifest complete; setup runs it in a
// container it just created, before recording anything.
func markManifestCompleteOp() guestOp {
	m := shellEscape(copyManifestPath)
	return guestCmd(fmt.Sprintf(`{ mkdir -p %s && { grep -qx '%s' %s 2>/dev/null || { { echo '%s'; cat %s 2>/dev/null; } > %s.new && mv -f %s.new %s; }; }; } 2>/dev/null || true`,
		shellEscape(filepath.Dir(copyManifestPath)), copyManifestComplete, m, copyManifestComplete, m, m, m, m))
}

// leftoverCheckOp scans the copy manifest for files copied by an earlier
// session (skipping those in exclude, copied this launch) that are still in
// the container, and prints a marker for each, telling unchanged from
// changed-since. Unless the manifest is marked complete (missing, or started
// on a container older coi versions copied into unrecorded), it also prints,
// for each candidate that exists and is neither excluded nor recorded, an
// origin-unknown marker. It ends with a final marker, so the output tells
// "nothing found" apart from "never checked", and always succeeds, so it
// can't fail the batch it rides in.
func leftoverCheckOp(exclude []string, candidates []copyRecord) guestOp {
	candidates = manifestSafe(candidates)
	m := shellEscape(copyManifestPath)
	var b strings.Builder
	b.WriteString("X=$(printf '%s\\n'")
	for _, p := range exclude {
		b.WriteString(" " + shellEscape(p))
	}
	b.WriteString("); R=; has() { printf '%s\\n' \"$2\" | grep -qxF -- \"$1\"; }; ")
	fmt.Fprintf(&b, `if [ -f %s ]; then while IFS='	' read -r a hp; do case $a in '#'*) continue ;; esac; `+
		`h=${a%%%% *}; r=${a#* }; k=${r%%%% *}; c=${r#* }; R="$R$c
"; `+
		`has "$c" "$X" && continue; [ -e "$c" ] || continue; `+
		`if [ "$(sha256sum < "$c" 2>/dev/null | cut -c1-64)" = "$h" ]; then mk=%s; else mk=%s; fi; `+
		`printf '%%s%%s\t%%s\t%%s\n' "$mk" "$k" "$c" "$hp"; done < %s; fi; `,
		m, leftoverSameMarker, leftoverChangedMarker, m)
	fmt.Fprintf(&b, `if ! grep -qx '%s' %s 2>/dev/null; then :`, copyManifestComplete, m)
	for _, c := range candidates {
		fmt.Fprintf(&b, `; c=%s; has "$c" "$X" || has "$c" "$R" || { [ -e "$c" ] && printf '%s%s\t%%s\t%%s\n' "$c" %s; }`,
			shellEscape(c.ContainerPath), leftoverUnknownMarker, c.kind, shellEscape(c.HostPath))
	}
	b.WriteString("; fi; echo " + leftoverCheckedMarker)
	return guestCmd(b.String())
}

// parse reads leftoverCheckOp's output from the batch's combined output.
func (lc *leftoverCheck) parse(out string) {
	if !lc.planned {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == leftoverCheckedMarker {
			lc.checked = true
			continue
		}
		var g CredentialGrant
		rest, ok := strings.CutPrefix(line, leftoverSameMarker)
		if !ok {
			if rest, ok = strings.CutPrefix(line, leftoverChangedMarker); ok {
				g.Changed = true
			} else if rest, ok = strings.CutPrefix(line, leftoverUnknownMarker); ok {
				g.Unverified = true
			}
		}
		f := strings.SplitN(rest, "\t", 3)
		if !ok || len(f) != 3 {
			continue
		}
		g.HostPath, g.ContainerPath, g.Earlier = f[2], f[1], true
		if f[0] == copyKindCredential {
			lc.creds = append(lc.creds, g)
		} else {
			lc.tools = append(lc.tools, g)
		}
	}
}

// copiesThisLaunch is every host file this launch put in the container, for
// the manifest: [[credentials]] and tool files copied, and tool files
// restored from a saved session (unless a fresh copy replaced them).
func (st *setupState) copiesThisLaunch() []copyRecord {
	out := append(copyRecords(copyKindCredential, st.copiedCredentials), copyRecords(copyKindTool, st.toolFiles)...)
	for _, r := range st.liveRestored() {
		out = append(out, copyRecord{copyKindTool, r})
	}
	return out
}

// liveRestored is the restored tool files no fresh copy replaced.
func (st *setupState) liveRestored() []CredentialEntry {
	copied := map[string]bool{}
	for _, e := range st.toolFiles {
		copied[e.ContainerPath] = true
	}
	var out []CredentialEntry
	for _, r := range st.restoredFiles {
		if !copied[r.ContainerPath] {
			out = append(out, r)
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

	if g.Workspace.HostPath == "" {
		// No device named "workspace" (a container coi didn't create);
		// whatever holds the workspace is listed under Mounts.
		add("Workspace", "none")
	} else {
		add("Workspace", fmt.Sprintf("%s -> %s (%s)", g.Workspace.HostPath, g.Workspace.ContainerPath, rwLabel(g.Workspace.Readonly)))
	}

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
	if g.DockerConfigDiffers {
		verb := "disables"
		if g.DockerUnavailable {
			verb = "enables"
		}
		// A restart reconciles the container's own nesting to config: with
		// Docker on it sets it, which overrides a profile; with Docker off it
		// only removes the container's own setting, so a profile's stays.
		// An explicit --container attach skips the reconcile altogether.
		switch {
		case g.DockerNotReconciled:
			docker += " (config " + verb + " it; not applied to a container named with --container)"
		case g.DockerSource == dockerSourceProfile && !g.DockerUnavailable:
			docker += " (an Incus profile enables nesting; config disables Docker)"
		case g.DockerSource == dockerSourceUnknown:
			docker += " (config " + verb + " it)"
		default:
			docker += " (config " + verb + " it; restart the container to apply)"
		}
	}
	add("Agent", fmt.Sprintf("runs as %s, Docker %s", user, docker))

	limits := append([]string{}, g.Limits...)
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
	var lines []string
	switch g.Env.Launch {
	case ToolAttached:
		lines = append(lines, "the running tool keeps the env it started with; new panes get:")
	case ToolSentToPane:
		lines = append(lines, "the tool starts in the existing pane, which keeps its env; new panes get:")
	}
	seen := map[string]bool{}
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
	if len(lines) == 0 || (g.Env.Launch != ToolStarted && len(lines) == 1) {
		lines = append(lines, "none")
	}
	return lines
}

func copiedLines(files []CredentialGrant) []string {
	var lines []string
	for _, c := range files {
		l := fmt.Sprintf("%s -> %s", c.HostPath, c.ContainerPath)
		switch {
		case c.Restored:
			l += " (restored from the saved session)"
		case c.Earlier && c.Unverified:
			l += " (in the container; it predates coi recording copies, so it may not be from the host)"
		case c.Earlier && c.Changed:
			l += " (copied by an earlier session, since changed in the container)"
		case c.Earlier:
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
