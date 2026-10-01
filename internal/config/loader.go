package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	coischema "github.com/coipond/coi/schema"
)

// Load loads configuration from all available sources
// Hierarchy (lowest to highest precedence):
// 1. Built-in defaults
// 2. User config (~/.coi/config.toml, or the file $COI_CONFIG points at)
// 3. Project config (./.coi/config.toml)
//
// There are no env-var config overrides: config-shaped settings live in
// config files and profiles only.
//
// Profile directories are scanned independently from config files.
// See GetProfileParentDirs() for the full list of scanned locations.
// Profiles from all scan locations are merged into a single namespace; if the
// same profile name is defined in more than one location Load() returns an
// error asking the user to resolve the conflict.
func Load() (_ *Config, err error) {
	// Every failure to load, parse, or validate config is a ConfigError, so the
	// CLI can distinguish "your config is wrong" from a runtime failure with one
	// errors.As. Wrapping once here covers all the return paths below without
	// annotating each; already-wrapped errors are not re-wrapped.
	defer func() {
		if err != nil {
			if _, ok := err.(*ConfigError); !ok {
				err = &ConfigError{Err: err}
			}
		}
	}()

	// Check for deprecated .coi.toml in project root
	if err := checkDeprecatedConfig(); err != nil {
		return nil, err
	}

	// Start with defaults
	cfg := GetDefaultConfig()

	// Scan profile directories from all known locations. Profiles are merged
	// into a single namespace; duplicate names across locations are rejected
	// by loadProfileDirectories so it's always clear which profile is used.
	for _, dir := range GetProfileParentDirs() {
		if err := loadProfileDirectories(cfg, dir, isTrustedProfileDir(dir)); err != nil {
			return nil, err
		}
	}

	// Load from config files (in order). The user config (~/.coi/config.toml) and
	// an explicit COI_CONFIG are trusted; the project config (<cwd>/.coi/config.toml)
	// is untrusted and sanitized before merging.
	paths := GetConfigPaths()
	for _, path := range paths {
		if err := loadConfigFileScoped(cfg, path, isTrustedConfigPath(path)); err != nil {
			// Only return error if file exists but can't be parsed
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
			}
			// File doesn't exist - that's OK, skip it
		}
	}

	// Inject built-in "default" profile (can be overridden by disk-based profiles)
	if _, exists := cfg.Profiles["default"]; !exists {
		cfg.Profiles["default"] = synthesizeDefaultProfile(cfg)
	}

	// Inject built-in "hardened" profile: a hardened preset for opening untrusted
	// repos (restricted network, secret masking, immutability, ephemeral,
	// no SSH-agent forwarding, monitoring). Overridable by a disk profile.
	if _, exists := cfg.Profiles["hardened"]; !exists {
		cfg.Profiles["hardened"] = synthesizeHardenedProfile()
	}

	// Resolve profile inheritance after all profiles are loaded from all levels
	if err := cfg.ResolveProfileInheritance(); err != nil {
		return nil, fmt.Errorf("profile inheritance error: %w", err)
	}

	stripUntrustedInheritedSessionNames(cfg)

	// Profiles are schema-validated, but the top-level config is not — and a
	// malformed session_name (trailing space, path separators, invisible
	// characters) would silently hash to a different identity than its
	// lookalike, recreating the fresh-container failure the feature exists to
	// prevent. Validate every name that survived trust gating.
	if err := validateSessionName(cfg.Container.SessionName); err != nil {
		return nil, err
	}
	for name, p := range cfg.Profiles {
		if err := validateSessionName(p.Container.SessionName); err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
	}

	// Ensure directories exist
	if err := ensureDirectories(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// OverlayProjectConfig loads the project config from the given workspace directory
// and merges it into cfg. This is used when launching via alias from a different
// directory, so the resolved workspace's .coi/config.toml is applied.
//
// The workspace .coi/config.toml is always project-scoped and therefore
// untrusted (it may be supplied by a cloned repo or planted by an in-container
// agent), so it is loaded with trusted=false and sanitized.
func (c *Config) OverlayProjectConfig(workspaceDir string) error {
	path := filepath.Join(workspaceDir, ".coi", "config.toml")
	return loadConfigFileScoped(c, path, false)
}

// isTrustedConfigPath reports whether a config path is user-controlled and
// therefore trusted: the user's ~/.coi/config.toml or an explicit COI_CONFIG.
// The project config (<cwd>/.coi/config.toml) is untrusted.
func isTrustedConfigPath(path string) bool {
	clean := filepath.Clean(path)
	if home, err := os.UserHomeDir(); err == nil {
		if clean == filepath.Clean(filepath.Join(home, ".coi", "config.toml")) {
			return true
		}
	}
	if env := os.Getenv("COI_CONFIG"); env != "" && clean == filepath.Clean(env) {
		return true
	}
	return false
}

// loadConfigFileScoped loads a TOML config file and merges it into cfg.
//
// trusted distinguishes config the user explicitly controls (~/.coi/config.toml
// and an explicit COI_CONFIG) from untrusted, project-scoped config (the
// workspace's .coi/config.toml). Untrusted config is sanitized before merging:
// any network setting that would WEAKEN isolation is dropped with a warning.
// This prevents a malicious repo — or an in-container agent that planted a
// .coi/config.toml — from silently turning off the private-network / metadata
// blocks on the next launch.
func loadConfigFileScoped(cfg *Config, path string, trusted bool) error {
	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		return err
	}

	// Parse TOML file
	var fileCfg Config
	if _, err := toml.DecodeFile(path, &fileCfg); err != nil {
		return err
	}

	// Detect pre-0.8.0 layouts and refuse to load with an actionable error.
	if err := checkDeprecatedConfigFields(path); err != nil {
		return err
	}

	if !trusted {
		sanitizeUntrustedConfig(&fileCfg, path)
		markUntrustedMounts(fileCfg.Mounts.Default, path)
		markUntrustedSockets(fileCfg.Sockets, path)
		markUntrustedPorts(&fileCfg.Ports, path)
		markUntrustedCredentials(fileCfg.Credentials, path)
	}

	configDir := filepath.Dir(path)

	// Resolve build script path relative to config file location
	if fileCfg.Container.Build.Script != "" {
		fileCfg.Container.Build.Script = resolveRelativePath(configDir, fileCfg.Container.Build.Script)
	}

	// Resolve [prompts] file= paths relative to the config file dir, like the
	// build script above (#701). Untrusted prompts were already stripped
	// wholesale by sanitizeUntrustedConfig, so only trusted entries reach here.
	resolvePromptFiles(fileCfg.Prompts, configDir)

	// Merge into main config
	cfg.Merge(&fileCfg)

	return nil
}

// sanitizeUntrustedConfig hardens a project-scoped (untrusted) config before it
// is merged. It refuses network settings that would weaken isolation relative to
// the secure defaults, leaving the stronger built-in/user values in place.
// Strengthening values are left intact.
func sanitizeUntrustedConfig(fileCfg *Config, path string) {
	sanitizeUntrustedNetwork(&fileCfg.Network, path)
	sanitizeUntrustedEnvCommands(&fileCfg.Defaults, path)
	sanitizeUntrustedDefaultProfile(&fileCfg.Defaults, path)
	sanitizeUntrustedSessionName(&fileCfg.Container, path)
	sanitizeUntrustedDocker(&fileCfg.Container, path)
	sanitizeUntrustedSecurity(&fileCfg.Security, path)
	sanitizeUntrustedGit(&fileCfg.Git, path)
	sanitizeUntrustedTool(&fileCfg.Tool, path)
	sanitizeUntrustedPrompts(fileCfg.Prompts, path)

	// Persistence is honored from project scope (not a protection downgrade —
	// the container stays fully sandboxed), but a cloned repo opting the user
	// into container reuse deserves a visible note: state from a previous
	// run's container (which executed repo-controlled code) is carried into
	// subsequent runs.
	if fileCfg.Container.Persistent != nil && *fileCfg.Container.Persistent {
		fmt.Fprintf(os.Stderr,
			"Note: project config %s enables persistent containers — container state is reused across runs\n", path)
	}
}

// warnUntrustedDowngrade reports that a protection-weakening field from an
// untrusted (project-scoped) source was ignored.
func warnUntrustedDowngrade(path, field string) {
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring '%s' in project config %s; removing read-only "+
			"protection is a security downgrade. Move it to ~/.coi/config.toml or "+
			"set COI_CONFIG to apply it.\n", field, path)
}

// sanitizeUntrustedTool drops [tool] fields that read an arbitrary HOST file and
// inject it into the container, since honoring them from an untrusted
// (project-scoped) config would let a cloned/agent-planted repo exfiltrate host
// secrets into the sandbox: e.g. context_file = "~/.ssh/id_rsa" lands the key in
// ~/SANDBOX_CONTEXT.md, and context_json_file = "~/.aws/credentials" lands it in
// ~/SANDBOX_CONTEXT.json — both readable by the in-container agent. Both are
// therefore honored only from trusted scope (~/.coi/config.toml or $COI_CONFIG).
// nil is a no-op.
func sanitizeUntrustedTool(tc *ToolConfig, path string) {
	if tc == nil {
		return
	}
	if tc.ContextFile != "" {
		warnUntrustedDowngrade(path, "tool.context_file")
		tc.ContextFile = ""
	}
	if tc.ContextJSONFile != "" {
		warnUntrustedDowngrade(path, "tool.context_json_file")
		tc.ContextJSONFile = ""
	}
}

// sanitizeUntrustedPrompts drops ALL [prompts] entries from an untrusted
// (project-scoped) source. A named prompt is exactly what `coi run --prompt-name
// X` feeds to the agent, so it must come only from trusted scope
// (~/.coi/config.toml / $COI_CONFIG): a cloned/agent-planted repo defining a
// prompt — whether it reads a host file (file = "~/.ssh/id_rsa") or is inline
// text redefining a name the user trusts — must never be honored. Handled the
// same way as [defaults] env_commands and the default-profile selector. nil is a
// no-op.
func sanitizeUntrustedPrompts(prompts map[string]PromptEntry, path string) {
	if len(prompts) == 0 {
		return
	}
	// One message per config (not per entry) — a project that ships several
	// prompts shouldn't spam a line for each on every coi command.
	names := make([]string, 0, len(prompts))
	for name := range prompts {
		names = append(names, name)
		delete(prompts, name)
	}
	sort.Strings(names)
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring [prompts] (%s) in project config %s; named prompts are "+
			"honored only from trusted config (~/.coi/config.toml or $COI_CONFIG).\n",
		strings.Join(names, ", "), path)
}

// resolvePromptFiles resolves each prompt entry's file= path relative to the
// config/profile directory (like [container.build] script). Inline-text entries
// are untouched; absolute and ~-prefixed paths pass through resolveRelativePath.
// Only trusted-scope prompts reach here — untrusted ones are stripped wholesale
// by sanitizeUntrustedPrompts before this runs.
func resolvePromptFiles(prompts map[string]PromptEntry, baseDir string) {
	for name, entry := range prompts {
		if entry.File != "" {
			entry.File = resolveRelativePath(baseDir, entry.File)
			prompts[name] = entry
		}
	}
}

// sanitizeUntrustedSecurity drops security-weakening fields from an untrusted
// source. A project config (or project-scoped profile) may *add* protections (via
// additional_protected_paths) but must never *remove* them, because honoring a
// downgrade from a cloned/agent-planted repo would let it turn off read-only
// protection of host-auto-executing files (e.g. .git/hooks, .claude/settings.json).
// Every field that can shrink the effective protected set is stripped so it is
// honored only from trusted-scope config (~/.coi/config.toml or $COI_CONFIG):
//   - disable_protection (removes ALL protections),
//   - protected_paths (a full replace that drops the defaults; untrusted sources
//     can still extend via additional_protected_paths),
//   - writable_paths (subtracts entries),
//   - host_immutable=false (disables the chattr +i hardening).
//
// nil is a no-op.
func sanitizeUntrustedSecurity(s *SecurityConfig, path string) {
	if s == nil {
		return
	}
	if s.DisableProtection {
		warnUntrustedDowngrade(path, "security.disable_protection")
		s.DisableProtection = false
	}
	if len(s.ProtectedPaths) > 0 {
		warnUntrustedDowngrade(path, "security.protected_paths")
		s.ProtectedPaths = nil
	}
	if len(s.WritablePaths) > 0 {
		warnUntrustedDowngrade(path, "security.writable_paths")
		s.WritablePaths = nil
	}
	if s.HostImmutable != nil && !*s.HostImmutable {
		// Only the disabling value is a downgrade; a strengthening true is dropped
		// too for simplicity (trusted config controls host-immutable).
		warnUntrustedDowngrade(path, "security.host_immutable")
	}
	s.HostImmutable = nil
	if s.ReduceKernelSurface != nil && !*s.ReduceKernelSurface {
		// Only false is a downgrade to warn about. Unlike [container] docker =
		// false — a narrow tightening (nesting off) that IS honored from
		// untrusted scope — reduce_kernel_surface is trusted-only in BOTH
		// directions because its effect is broad: on top of disabling Docker it
		// installs a security.syscalls.deny list (io_uring, bpf, userfaultfd,
		// keyring) that can break legitimate NON-Docker workloads in the
		// container. That blast radius, not merely "it turns Docker off", is
		// why a cloned repo must not be able to impose it (or lift it). The
		// strengthening true is therefore dropped silently.
		warnUntrustedDowngrade(path, "security.reduce_kernel_surface")
	}
	s.ReduceKernelSurface = nil
	if s.ReduceKernelSurfaceStrict != nil && !*s.ReduceKernelSurfaceStrict {
		// Trusted-only in both directions for the same reason as the base flag:
		// its deny list (which adds perf_event_open) alters container behavior
		// broadly, so a cloned repo must not be able to impose it or lift it.
		warnUntrustedDowngrade(path, "security.reduce_kernel_surface_strict")
	}
	s.ReduceKernelSurfaceStrict = nil
}

// sanitizeUntrustedGit drops git settings that weaken protection or would let an
// untrusted source pick the container's commit identity. Honored only from
// trusted-scope config:
//   - git.writable_hooks=true makes .git/hooks writable inside the container
//     (filterWritableGitHooks removes it from the read-only set).
//   - git.name / git.email choose the commit author installed in the container;
//     a cloned/agent-planted repo must not decide who its commits appear to be
//     authored by (the whole reason Coi reads only the host's *global* git
//     config, never project-local). Stripped so the field is honored only from
//     ~/.coi/config.toml / $COI_CONFIG.
//   - git.seed_host_identity governs reading the host identity; git-identity
//     behavior is entirely trusted-scope, so it is dropped from untrusted config
//     too (a project config must not flip whether the host identity is used).
//
// nil is a no-op.
func sanitizeUntrustedGit(g *GitConfig, path string) {
	if g == nil {
		return
	}
	if g.WritableHooks != nil {
		if *g.WritableHooks {
			warnUntrustedDowngrade(path, "git.writable_hooks")
		}
		g.WritableHooks = nil
	}
	if g.Name != "" || g.Email != "" {
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring 'git.name'/'git.email' in project config %s; a project "+
				"checkout must not choose the container commit identity. Move it to "+
				"~/.coi/config.toml or set COI_CONFIG to apply it.\n", path)
		g.Name = ""
		g.Email = ""
	}
	// A project config must not influence git-identity behavior at all; drop the
	// toggles silently (neither is a protection downgrade on its own — readonly
	// only ever tightens — but identity behavior is trusted-scope by design).
	g.SeedHostIdentity = nil
	g.Readonly = nil
	// Attribution stripping is trusted-scope in both directions, like the
	// identity fields it protects: a cloned repo must control neither whether
	// commits made in it keep AI attribution (false would re-enable trailers
	// the operator chose to strip) nor which patterns get removed from
	// messages (arbitrary line-deletion from every commit).
	if g.StripAttribution != nil && !*g.StripAttribution {
		warnUntrustedDowngrade(path, "git.strip_attribution")
	}
	g.StripAttribution = nil
	g.StripAttributionPatterns = nil
	// The branch guard is an enforcement control: a cloned/agent-planted repo must
	// not be able to shrink or empty it to unlock pushes to main. Nil it out —
	// falling back to the default set — so the guard stays on. A non-nil value
	// (including an explicit `[]` disabling attempt) is a downgrade; warn.
	if g.ProtectedBranches != nil {
		warnUntrustedDowngrade(path, "git.protected_branches")
		g.ProtectedBranches = nil
	}
}

// sanitizeUntrustedEnvCommands strips env_commands (and their timeout) from an
// untrusted source. Running a host command at session start is host code
// execution, so — unlike escaping mounts/sockets, which can be approved via
// `coi trust` — it is never honored from a project config or project-scoped
// profile; it must live in trusted-scope config (~/.coi/config.toml / $COI_CONFIG).
func sanitizeUntrustedEnvCommands(d *DefaultsConfig, path string) {
	if d == nil {
		return
	}
	// Strip the timeout unconditionally: even without env_commands here, a lone
	// env_command_timeout from an untrusted source would override the timeout
	// applied to trusted-scope env_commands.
	d.EnvCommandTimeout = ""
	if len(d.EnvCommands) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring 'env_commands' in project config %s; running a host "+
			"command is host code execution. Move it to ~/.coi/config.toml or set "+
			"COI_CONFIG to apply it.\n", path)
	d.EnvCommands = nil
}

// sanitizeUntrustedDefaultProfile strips `[defaults] profile` from an untrusted
// (project-scoped) source. The default profile decides the whole environment a
// no-flag `coi` launches into, so honoring it from a cloned/agent-planted repo
// would let that repo redirect the user's default to a weaker profile of their
// own — a silent downgrade. Move it to ~/.coi/config.toml (or COI_CONFIG) to apply.
func sanitizeUntrustedDefaultProfile(d *DefaultsConfig, path string) {
	if d == nil || d.Profile == "" {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring '[defaults] profile' in project config %s; the default "+
			"profile selects the whole session environment. Move it to "+
			"~/.coi/config.toml or set COI_CONFIG to apply it.\n", path)
	d.Profile = ""
}

// stripUntrustedInheritedSessionNames re-strips session_name from untrusted
// (project-scoped) profiles AFTER inheritance resolution: inheritance can copy
// a TRUSTED parent's session_name into a project-scoped child, so
// `inherits = "<trusted profile>"` would smuggle what direct declaration
// cannot (the per-profile strip runs before inheritance is resolved).
func stripUntrustedInheritedSessionNames(cfg *Config) {
	for name, p := range cfg.Profiles {
		// Synthesized profiles (default/hardened) have no Source and carry
		// only already-validated trusted config; disk profiles carry the
		// Trusted stamp from their scan root.
		if p.Container.SessionName == "" || p.Source == "" || p.Trusted {
			continue
		}
		sanitizeUntrustedSessionName(&p.Container, p.Source)
		cfg.Profiles[name] = p
	}
}

// sessionNameRe mirrors the profile schema's session_name pattern.
var sessionNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// validateSessionName rejects [container] session_name values that would
// silently hash to a different identity than their lookalike (whitespace,
// path separators, invisible characters). Empty = unset = valid.
func validateSessionName(name string) error {
	if name == "" || sessionNameRe.MatchString(name) {
		return nil
	}
	return fmt.Errorf("invalid [container] session_name %q: must match %s (letters, digits, '.', '_', '-'; start alphanumeric; max 64 chars)", name, sessionNameRe.String())
}

// sanitizeUntrustedSessionName strips [container] session_name from an
// untrusted (project-scoped) source. The session name selects which persistent
// container and saved session state (conversation history, restored
// credentials) a launch attaches to — a cloned/agent-planted repo must not be
// able to attach its own workspace to another project's session, or plant a
// name that a later trusted launch would unknowingly share state with.
func sanitizeUntrustedSessionName(c *ContainerConfig, path string) {
	if c == nil || c.SessionName == "" {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring '[container] session_name' in project config %s; the "+
			"session name selects which persistent session a launch attaches to. "+
			"Move it to ~/.coi/config.toml or a profile under ~/.coi/profiles to apply it.\n", path)
	c.SessionName = ""
}

// sanitizeUntrustedDocker strips an untrusted `[container] docker = true`: a
// cloned/agent-planted repo must not re-enable nesting and the wider kernel
// surface that a trusted profile disabled. `docker = false` is a NARROW
// tightening — it only turns off nesting/syscall-interception, with no effect
// on ordinary in-container workloads — so it is honored from any scope, the
// same as an add-only network restriction. (Contrast security.reduce_kernel_-
// surface, which is trusted-only in both directions because its syscall deny
// list has a far broader blast radius; see sanitizeUntrustedSecurity.) nil is
// a no-op.
func sanitizeUntrustedDocker(c *ContainerConfig, path string) {
	if c == nil || c.Docker == nil || !*c.Docker {
		return
	}
	warnUntrustedDowngrade(path, "container.docker")
	c.Docker = nil
}

// sanitizeUntrustedNetwork drops security-downgrading network settings from an
// untrusted source (a project config or a project-scoped profile). nil is a
// no-op so it can be called directly on a profile's optional *NetworkConfig.
func sanitizeUntrustedNetwork(n *NetworkConfig, path string) {
	if n == nil {
		return
	}
	refuse := func(what string) {
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring security-downgrading %q in project config %s; "+
				"move it to ~/.coi/config.toml or set COI_CONFIG to apply it.\n", what, path)
	}
	if n.BlockPrivateNetworks != nil && !*n.BlockPrivateNetworks {
		refuse("network.block_private_networks=false")
		n.BlockPrivateNetworks = nil
	}
	if n.BlockMetadataEndpoint != nil && !*n.BlockMetadataEndpoint {
		refuse("network.block_metadata_endpoint=false")
		n.BlockMetadataEndpoint = nil
	}
	if n.AllowLocalNetworkAccess != nil && *n.AllowLocalNetworkAccess {
		refuse("network.allow_local_network_access=true")
		n.AllowLocalNetworkAccess = nil
	}
	if n.Mode == NetworkModeOpen {
		refuse("network.mode=open")
		n.Mode = ""
	}
	if len(n.Hosts) > 0 {
		// A name→IP mapping is a spoofing primitive (redirect api.anthropic.com to
		// an attacker's box) and reachability punches a firewall hole. Honor it
		// only from trusted scope.
		refuse("network.hosts")
		n.Hosts = nil
	}
	if len(n.DNSServers) > 0 {
		// Pinning the resolver a container may reach is a DNS-redirect primitive:
		// a project config could point DNS at an attacker's box. Trusted scope only.
		refuse("network.dns_servers")
		n.DNSServers = nil
	}
	if len(n.AllowedPorts) > 0 {
		// A port allowlist only tightens egress, so it cannot downgrade security on
		// its own — but it is honored from trusted scope only for a uniform rule,
		// matching the other network policy keys (and so a project config cannot
		// silently narrow egress in ways the user did not intend either).
		refuse("network.allowed_ports")
		n.AllowedPorts = nil
	}
}

// markUntrustedMounts tags mounts from an untrusted source so escaping host
// mounts are gated behind explicit trust at apply time (internal/session/trust.go).
// SourcePath is the absolute config path; if Abs fails the raw path is used —
// the mounts are still marked untrusted so a path-resolution error cannot fail
// open and admit an ungated host mount.
func markUntrustedMounts(mounts []MountEntry, path string) {
	src := path
	if abs, err := filepath.Abs(path); err == nil {
		src = abs
	}
	for i := range mounts {
		mounts[i].Untrusted = true
		mounts[i].SourcePath = src
	}
}

// markUntrustedSockets tags forwarded sockets from an untrusted source so they
// are gated behind explicit trust at forward time (internal/session/trust.go).
// Like markUntrustedMounts, a path-resolution error falls back to the raw path
// rather than failing open and forwarding an ungated host socket.
func markUntrustedSockets(sockets []SocketEntry, path string) {
	src := path
	if abs, err := filepath.Abs(path); err == nil {
		src = abs
	}
	for i := range sockets {
		sockets[i].Untrusted = true
		sockets[i].SourcePath = src
	}
}

// markUntrustedPorts tags a [ports] section from an untrusted source so it
// is gated behind explicit trust (internal/session/trust.go): a repo
// declaring host listeners can squat well-known localhost ports (e.g. a fake
// postgres on 5432 capturing the host's own local connections). The flag is
// section-level and covers the pool and every map entry.
func markUntrustedPorts(ports *PortsConfig, path string) {
	if ports == nil || !ports.HasPorts() {
		return
	}
	src := path
	if abs, err := filepath.Abs(path); err == nil {
		src = abs
	}
	if ports.Pool > 0 {
		ports.PoolUntrusted = true
		ports.PoolSourcePath = src
	}
	for i := range ports.Map {
		ports.Map[i].Untrusted = true
		ports.Map[i].SourcePath = src
	}
}

// markUntrustedCredentials tags credential entries from an untrusted source so
// ad-hoc entries are gated behind explicit trust at apply time
// (internal/session/trust.go). Like markUntrustedMounts, a path-resolution
// error falls back to the raw path rather than failing open and copying an
// ungated host credential file. Catalog-referenced entries (Bundle != "") are
// also marked Untrusted here for consistency, but the trust-gating logic in
// internal/session/trust.go never gates on Bundle-sourced entries regardless
// of this flag — see CredentialEntry's own doc comment for why.
func markUntrustedCredentials(creds []CredentialEntry, path string) {
	src := path
	if abs, err := filepath.Abs(path); err == nil {
		src = abs
	}
	for i := range creds {
		creds[i].Untrusted = true
		creds[i].SourcePath = src
	}
}

// isTrustedProfileDir reports whether a profiles parent directory is
// user-controlled (trusted): the user's ~/.coi or the directory of an explicit
// $COI_CONFIG. The project workspace's ./.coi is untrusted — a cloned repo can
// ship profiles under it.
func isTrustedProfileDir(dir string) bool {
	clean := filepath.Clean(dir)
	if home, err := os.UserHomeDir(); err == nil {
		if clean == filepath.Clean(filepath.Join(home, ".coi")) {
			return true
		}
	}
	if env := os.Getenv("COI_CONFIG"); env != "" && clean == filepath.Clean(filepath.Dir(env)) {
		return true
	}
	return false
}

// loadProfileDirectories scans configDir/profiles/ for subdirectories containing config.toml
// and adds them to cfg.Profiles. Each subdirectory name becomes the profile name.
//
// If a profile with the same name is already loaded from a different source
// location, loadProfileDirectories returns an error. Profiles from different
// scan locations (e.g. ~/.coi/profiles/ and ./.coi/profiles/) are merged
// together, and users are expected to use unique names across locations so
// it's always clear which profile is being used.
func loadProfileDirectories(cfg *Config, configDir string, trusted bool) error {
	profilesDir := filepath.Join(configDir, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil // Directory doesn't exist or can't be read — that's fine
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profileName := entry.Name()
		profileConfigPath := filepath.Join(profilesDir, profileName, "config.toml")

		if _, err := os.Stat(profileConfigPath); err != nil {
			continue // No config.toml in this subdirectory
		}

		// Detect duplicate profile name across scan locations. The same path
		// loaded twice is fine (idempotent), but two different paths for the
		// same name is ambiguous — error out and tell the user to rename one.
		if existing, ok := cfg.Profiles[profileName]; ok && existing.Source != "" && existing.Source != profileConfigPath {
			return fmt.Errorf(
				"profile %q defined in multiple locations:\n  %s\n  %s\n"+
					"Rename one of them or delete the duplicate so it's clear which profile is being used",
				profileName, existing.Source, profileConfigPath,
			)
		}

		var profileCfg ProfileConfig
		if _, err := toml.DecodeFile(profileConfigPath, &profileCfg); err != nil {
			return fmt.Errorf("failed to parse profile %q config at %s: %w", profileName, profileConfigPath, err)
		}

		// Detect pre-0.8.0 profile layouts and refuse to load with a friendly
		// message before schema validation runs (deprecated fields would
		// otherwise surface as unhelpful "additionalProperties not allowed").
		if err := checkDeprecatedProfileFields(profileConfigPath); err != nil {
			return err
		}

		// Validate the raw TOML against the JSON Schema to catch unknown keys,
		// wrong types, and invalid enum values with precise error paths.
		var rawMap map[string]any
		if _, err := toml.DecodeFile(profileConfigPath, &rawMap); err != nil {
			return fmt.Errorf("failed to re-read profile %q for schema validation: %w", profileName, err)
		}
		if schemaErr := coischema.ValidateProfileMap(rawMap); schemaErr != nil {
			return fmt.Errorf("profile %q at %s failed schema validation: %w",
				profileName, profileConfigPath, schemaErr)
		}

		// Resolve paths relative to profile directory
		profileDir := filepath.Join(profilesDir, profileName)
		if profileCfg.Container.Build.Script != "" {
			profileCfg.Container.Build.Script = resolveRelativePath(profileDir, profileCfg.Container.Build.Script)
		}
		if profileCfg.Context != "" {
			profileCfg.Context = resolveRelativePath(profileDir, profileCfg.Context)
		}

		// Tag with source location and the scan root's trust
		profileCfg.Source = profileConfigPath
		profileCfg.Trusted = trusted

		// A project-scoped profile (under the workspace ./.coi) is untrusted — a
		// cloned repo can ship it. Apply the same hardening as an untrusted
		// top-level config: refuse network downgrades and tag its mounts so
		// escaping host mounts are gated behind `coi trust`.
		if !trusted {
			sanitizeUntrustedNetwork(profileCfg.Network, profileConfigPath)
			sanitizeUntrustedSessionName(&profileCfg.Container, profileConfigPath)
			sanitizeUntrustedDocker(&profileCfg.Container, profileConfigPath)
			sanitizeUntrustedSecurity(profileCfg.Security, profileConfigPath)
			sanitizeUntrustedGit(profileCfg.Git, profileConfigPath)
			sanitizeUntrustedPrompts(profileCfg.Prompts, profileConfigPath)
			markUntrustedMounts(profileCfg.Mounts, profileConfigPath)
			markUntrustedSockets(profileCfg.Sockets, profileConfigPath)
			markUntrustedPorts(profileCfg.Ports, profileConfigPath)
			markUntrustedCredentials(profileCfg.Credentials, profileConfigPath)
			if len(profileCfg.EnvCommands) > 0 {
				fmt.Fprintf(os.Stderr,
					"WARNING: ignoring 'env_commands' in project profile %s; running a "+
						"host command is host code execution. Move it to a profile under "+
						"~/.coi/profiles to apply it.\n", profileConfigPath)
				profileCfg.EnvCommands = nil
			}
			// Strip the timeout unconditionally, even with no env_commands here: a
			// lone env_command_timeout would otherwise survive and override the
			// timeout applied to trusted-scope env_commands when this profile is
			// selected — a project-scoped file must not influence how long a
			// trusted host command may run.
			profileCfg.EnvCommandTimeout = ""
		}

		// Resolve [prompts] file= paths AFTER the untrusted strip above, so only
		// surviving (trusted) entries are resolved — matching the top-level
		// loadConfigFileScoped order (sanitize first, then resolve).
		resolvePromptFiles(profileCfg.Prompts, profileDir)

		if cfg.Profiles == nil {
			cfg.Profiles = make(map[string]ProfileConfig)
		}
		cfg.Profiles[profileName] = profileCfg
	}
	return nil
}

// ensureDirectories creates necessary directories if they don't exist
func ensureDirectories(cfg *Config) error {
	dirs := []string{
		cfg.Paths.SessionsDir,
		cfg.Paths.StorageDir,
		cfg.Paths.LogsDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// checkDeprecatedConfig checks for the deprecated .coi.toml file in the current directory.
// Returns an error with migration instructions if found.
func checkDeprecatedConfig() error {
	workDir, err := os.Getwd()
	if err != nil {
		return nil // Can't check, skip
	}

	oldPath := filepath.Join(workDir, ".coi.toml")
	if _, err := os.Stat(oldPath); err == nil {
		return fmt.Errorf(
			"found .coi.toml in project root. As of this version, project config must be placed in .coi/config.toml. " +
				"Please move your config: mkdir -p .coi && mv .coi.toml .coi/config.toml",
		)
	}

	return nil
}

// resolveRelativePath resolves a path relative to a base directory.
// Absolute paths and ~-prefixed paths are returned as-is (with ~ expanded).
func resolveRelativePath(baseDir, path string) string {
	if filepath.IsAbs(path) || strings.HasPrefix(path, "~") {
		return ExpandPath(path)
	}
	return filepath.Join(baseDir, path)
}
