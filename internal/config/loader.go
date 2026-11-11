package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	coischema "github.com/coipond/coi/schema"
)

// Load loads configuration from all available sources
// Hierarchy (lowest to highest precedence):
// 1. Built-in defaults
// 2. User config (~/.coi/config.toml)
// 3. Project config (./.coi/config.toml)
// 4. The file $COI_CONFIG points at, if set (trusted, loaded last)
//
// There are no env-var config overrides: config-shaped settings live in
// config files and profiles only.
//
// Profile directories are scanned independently from config files.
// See GetProfileParentDirs() for the full list of scanned locations.
// Profiles from all scan locations are merged into a single namespace; if the
// same profile name is defined in more than one location Load() returns an
// error asking the user to resolve the conflict.
//
// Load reads every profile; LoadOnDemand reads only the profiles asked for;
// LoadWithoutProfiles reads none.
func Load() (*Config, error) {
	return load(loadAllProfiles)
}

// LoadOnDemand is Load without reading the profiles: it lists the profile
// directories (and checks for duplicate names) but reads and validates a
// profile, with the profiles it inherits from, only when GetProfile,
// LookupProfile or ApplyProfile first asks for it. cfg.Profiles then holds only
// the profiles read so far, plus the built-in profiles no disk profile replaces.
func LoadOnDemand() (*Config, error) {
	return load(loadProfilesOnDemand)
}

// LoadWithoutProfiles is Load for commands that never apply a profile: it reads
// no profile. A profile name in two locations is still an error
// (checkProfileNameClashes), so it reads the entry names of the profile
// directories, and those of ~/.coi/profiles only when ./.coi/profiles or the
// COI_CONFIG dir has entries. cfg.Profiles holds only the built-in profiles.
func LoadWithoutProfiles() (*Config, error) {
	return load(loadNoProfiles)
}

// profileLoadMode selects which profiles load reads.
type profileLoadMode int

const (
	loadAllProfiles profileLoadMode = iota
	loadProfilesOnDemand
	loadNoProfiles
)

// load runs Load, LoadOnDemand or LoadWithoutProfiles, as mode says.
func load(mode profileLoadMode) (_ *Config, err error) {
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
	// (by loadProfileDirectories, indexProfileDirectory or
	// checkProfileNameClashes) so it's always clear which profile is used.
	if mode == loadNoProfiles {
		if err := checkProfileNameClashes(GetProfileParentDirs()); err != nil {
			return nil, err
		}
	}
	for _, dir := range GetProfileParentDirs() {
		switch mode {
		case loadAllProfiles:
			err = loadProfileDirectories(cfg, dir, isTrustedProfileDir(dir))
		case loadProfilesOnDemand:
			_, err = indexProfileDirectory(cfg, dir, isTrustedProfileDir(dir))
		case loadNoProfiles:
		}
		if err != nil {
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

	// Inject the built-in profiles; a disk profile of the same name overrides one.
	for name, synthesize := range builtinProfiles {
		if ref, pending := cfg.pendingProfiles[name]; pending {
			builtin := synthesize(cfg)
			ref.builtin = &builtin
			cfg.pendingProfiles[name] = ref
		} else if _, exists := cfg.Profiles[name]; !exists {
			cfg.Profiles[name] = synthesize(cfg)
		}
	}

	if mode == loadAllProfiles {
		// Resolve profile inheritance after all profiles are loaded from all levels
		if err := cfg.ResolveProfileInheritance(); err != nil {
			return nil, fmt.Errorf("profile inheritance error: %w", err)
		}

		stripUntrustedInheritedSessionNames(cfg)
	}

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
	md, err := toml.DecodeFile(path, &fileCfg)
	if err != nil {
		return err
	}
	if md.IsDefined("network", "logging") {
		warnRemovedNetworkLogging(path)
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
	sanitizeUntrustedForwardEnv(&fileCfg.Defaults.ForwardEnv, path)
	sanitizeUntrustedSSH(&fileCfg.SSH, path)
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
// pre_launch is dropped too: commands that run automatically at every session
// start must not be switched on by a cloned repo. Applied to the top-level
// project config and to project-scoped profiles alike. nil is a no-op.
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
	// pre_launch runs commands automatically at every session start: a cloned
	// repo must not be able to switch that on.
	if len(tc.PreLaunch) > 0 {
		fmt.Fprintf(os.Stderr,
			"WARNING: ignoring 'tool.pre_launch' in project config %s; commands that "+
				"run automatically at session start must come from your own config. "+
				"Move it to ~/.coi/config.toml (or a profile under ~/.coi/profiles) "+
				"or set COI_CONFIG to apply it.\n", path)
		tc.PreLaunch = nil
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

// sanitizeUntrustedForwardEnv strips forward_env from an untrusted source.
// Forwarding copies the named HOST env vars (typically tokens and API keys)
// into the container, where the agent can read them, so a cloned or
// agent-planted repo must not be able to pick them. Applied to the top-level
// project config and to project-scoped profiles alike.
func sanitizeUntrustedForwardEnv(forwardEnv *[]string, path string) {
	if len(*forwardEnv) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring 'forward_env' in project config %s; it hands host "+
			"environment variables to the container. Move it to ~/.coi/config.toml "+
			"(or a profile under ~/.coi/profiles) or set COI_CONFIG to apply it.\n", path)
	*forwardEnv = nil
}

// sanitizeUntrustedSSH drops `[ssh] forward_agent = true` from an untrusted
// source: it lets the container use the host's SSH keys (push to any repo,
// log in to any host they open). forward_agent = false is a strengthening
// value and is kept. nil is a no-op.
func sanitizeUntrustedSSH(s *SSHConfig, path string) {
	if s == nil || s.ForwardAgent == nil || !*s.ForwardAgent {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: ignoring '[ssh] forward_agent = true' in project config %s; it "+
			"exposes your host SSH agent to the container. Move it to "+
			"~/.coi/config.toml (or a profile under ~/.coi/profiles) or set "+
			"COI_CONFIG to apply it.\n", path)
	s.ForwardAgent = nil
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
	for name := range cfg.Profiles {
		stripUntrustedInheritedSessionName(cfg, name)
	}
}

// stripUntrustedInheritedSessionName is stripUntrustedInheritedSessionNames
// for one loaded profile.
func stripUntrustedInheritedSessionName(cfg *Config, name string) {
	p := cfg.Profiles[name]
	// Synthesized profiles (default/hardened) have no Source and carry
	// only already-validated trusted config; disk profiles carry the
	// Trusted stamp from their scan root.
	if p.Container.SessionName == "" || p.Source == "" || p.Trusted {
		return
	}
	sanitizeUntrustedSessionName(&p.Container, p.Source)
	cfg.Profiles[name] = p
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
	if n.AllowHostAccess != nil && *n.AllowHostAccess {
		refuse("network.allow_host_access=true")
		n.AllowHostAccess = nil
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

// pendingProfile is a profile directory that LoadOnDemand listed but has not
// read yet.
type pendingProfile struct {
	dir     string // <profiles>/<name>
	trusted bool
	builtin *ProfileConfig // the built-in it replaces, used if it is gone
}

// configPath returns the profile's config.toml path.
func (p pendingProfile) configPath() string {
	return filepath.Join(p.dir, "config.toml")
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
	names, err := indexProfileDirectory(cfg, configDir, trusted)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := cfg.readPendingProfile(name); err != nil {
			return err
		}
	}
	return nil
}

// indexProfileDirectory lists configDir/profiles/ and records each
// subdirectory as a profile to read, without reading any config.toml. It
// returns the names it recorded, in directory order.
//
// A name already recorded or loaded from another location is an error when
// both locations hold a config.toml. Only such a clash costs a stat.
func indexProfileDirectory(cfg *Config, configDir string, trusted bool) ([]string, error) {
	profilesDir := filepath.Join(configDir, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil, nil // Directory doesn't exist or can't be read — that's fine
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profileName := entry.Name()
		ref := pendingProfile{dir: filepath.Join(profilesDir, profileName), trusted: trusted}

		// Detect duplicate profile name across scan locations. The same path
		// loaded twice is fine (idempotent), but two different paths for the
		// same name is ambiguous — error out and tell the user to rename one.
		// A subdirectory without config.toml is no profile, so it never clashes.
		existingSource := ""
		existingPending := false
		if existing, ok := cfg.Profiles[profileName]; ok {
			existingSource = existing.Source
		} else if existing, ok := cfg.pendingProfiles[profileName]; ok {
			existingSource = existing.configPath()
			existingPending = true
		}
		if existingSource != "" && existingSource != ref.configPath() {
			if !profileFileExists(ref.configPath()) {
				continue
			}
			if !existingPending || profileFileExists(existingSource) {
				return nil, fmt.Errorf(
					"profile %q defined in multiple locations:\n  %s\n  %s\n"+
						"Rename one of them or delete the duplicate so it's clear which profile is being used",
					profileName, existingSource, ref.configPath(),
				)
			}
		}

		if cfg.pendingProfiles == nil {
			cfg.pendingProfiles = make(map[string]pendingProfile)
		}
		cfg.pendingProfiles[profileName] = ref
		names = append(names, profileName)
	}
	return names, nil
}

// checkProfileNameClashes returns the error indexProfileDirectory returns for a
// profile name defined in more than one of dirs. It reads only entry names and
// stats only a name found in two dirs, so its cost stays small with many
// profiles. A dir that repeats an earlier one is skipped, as the same path
// never clashes.
func checkProfileNameClashes(dirs []string) error {
	var profileDirs []string
	for _, dir := range dirs {
		if dir = filepath.Join(dir, "profiles"); !slices.Contains(profileDirs, dir) {
			profileDirs = append(profileDirs, dir)
		}
	}
	names := make([][]string, len(profileDirs))
	for i := len(profileDirs) - 1; i >= 0; i-- {
		names[i] = readDirNames(profileDirs[i])
		// The first dir is read only when a later one has entries.
		if i == 1 && !slices.ContainsFunc(names[1:], func(n []string) bool { return len(n) > 0 }) {
			return nil
		}
	}

	seen := make(map[string]bool, len(names[0]))
	for _, name := range names[0] {
		seen[name] = true
	}
	for i := 1; i < len(names); i++ {
		var shared []string
		for _, name := range names[i] {
			if seen[name] {
				shared = append(shared, name)
			}
		}
		sort.Strings(shared)
		for _, name := range shared {
			existing := ""
			for j := range i {
				if path := profileConfigPath(profileDirs[j], name); path != "" {
					existing = path
					break
				}
			}
			if path := profileConfigPath(profileDirs[i], name); existing != "" && path != "" {
				return fmt.Errorf(
					"profile %q defined in multiple locations:\n  %s\n  %s\n"+
						"Rename one of them or delete the duplicate so it's clear which profile is being used",
					name, existing, path,
				)
			}
		}
		for _, name := range names[i] {
			seen[name] = true
		}
	}
	return nil
}

// readDirNames returns the entry names of dir, unsorted, or nil when it cannot
// be read.
func readDirNames(dir string) []string {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	return names
}

// profileConfigPath returns profilesDir/name/config.toml when name is a
// directory (not a symlink, as in indexProfileDirectory) holding a
// config.toml, else "".
func profileConfigPath(profilesDir, name string) string {
	dir := filepath.Join(profilesDir, name)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return ""
	}
	path := filepath.Join(dir, "config.toml")
	if !profileFileExists(path) {
		return ""
	}
	return path
}

// profileFileExists reports whether a profile config.toml exists at path.
func profileFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readPendingProfile reads, validates and stores the listed profile name in
// c.Profiles, without resolving its inheritance. A profile whose config.toml
// is gone is dropped, as if never listed.
func (c *Config) readPendingProfile(profileName string) error {
	ref, ok := c.pendingProfiles[profileName]
	if !ok {
		return nil
	}
	delete(c.pendingProfiles, profileName)
	profileDir := ref.dir
	profileConfigPath := ref.configPath()
	trusted := ref.trusted

	// Read the file once and decode that content for every check below.
	// Other processes add and remove profiles between the listing and this
	// read (an orchestrator launching many sessions creates and deletes one
	// per session), so separate reads could each see a different file, or
	// none: a profile removed between a stat and a later read used to
	// fail this whole command with "failed to parse profile".
	data, err := os.ReadFile(profileConfigPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No config.toml in this subdirectory (or it was just removed)
			if ref.builtin != nil {
				c.Profiles[profileName] = *ref.builtin
			}
			return nil
		}
		return fmt.Errorf("failed to read profile %q config at %s: %w", profileName, profileConfigPath, err)
	}

	// Parse once; the struct, the deprecated-field check and the schema
	// validation each decode that one parse.
	var doc toml.Primitive
	md, err := toml.Decode(string(data), &doc)
	if err != nil {
		return fmt.Errorf("failed to parse profile %q config at %s: %w", profileName, profileConfigPath, err)
	}
	var profileCfg ProfileConfig
	if err := md.PrimitiveDecode(doc, &profileCfg); err != nil {
		return fmt.Errorf("failed to parse profile %q config at %s: %w", profileName, profileConfigPath, err)
	}

	// Detect pre-0.8.0 profile layouts and refuse to load with a friendly
	// message before schema validation runs (deprecated fields would
	// otherwise surface as unhelpful "additionalProperties not allowed").
	var trap deprecatedProfileFields
	if md.PrimitiveDecode(doc, &trap) == nil {
		if err := checkDeprecatedProfileTrap(profileConfigPath, trap); err != nil {
			return err
		}
	}

	// Validate the raw TOML against the JSON Schema to catch unknown keys,
	// wrong types, and invalid enum values with precise error paths.
	var rawMap map[string]any
	if err := md.PrimitiveDecode(doc, &rawMap); err != nil {
		return fmt.Errorf("failed to re-read profile %q for schema validation: %w", profileName, err)
	}
	DropRemovedProfileKeys(rawMap, profileConfigPath)
	if schemaErr := coischema.ValidateProfileMap(rawMap); schemaErr != nil {
		return fmt.Errorf("profile %q at %s failed schema validation: %w",
			profileName, profileConfigPath, schemaErr)
	}

	// Resolve paths relative to profile directory
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
		sanitizeUntrustedTool(profileCfg.Tool, profileConfigPath)
		sanitizeUntrustedPrompts(profileCfg.Prompts, profileConfigPath)
		sanitizeUntrustedForwardEnv(&profileCfg.ForwardEnv, profileConfigPath)
		sanitizeUntrustedSSH(profileCfg.SSH, profileConfigPath)
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

	if c.Profiles == nil {
		c.Profiles = make(map[string]ProfileConfig)
	}
	c.Profiles[profileName] = profileCfg
	return nil
}

// loadProfile reads the listed profile name and the listed profiles it
// inherits from, resolves its inheritance and stores them in c.Profiles. It
// does nothing for a profile already loaded or never listed. On error it
// leaves the chain listed and unread, so a later call fails the same way.
func (c *Config) loadProfile(name string) (err error) {
	if _, ok := c.pendingProfiles[name]; !ok {
		return nil
	}

	var chain []string
	refs := make(map[string]pendingProfile)
	defer func() {
		if err != nil {
			for n, ref := range refs {
				delete(c.Profiles, n)
				c.pendingProfiles[n] = ref
			}
		}
	}()
	for current := name; ; {
		ref, ok := c.pendingProfiles[current]
		if !ok {
			break
		}
		refs[current] = ref
		if err := c.readPendingProfile(current); err != nil {
			return err
		}
		p, ok := c.Profiles[current]
		if !ok {
			break
		}
		chain = append(chain, current)
		if p.Inherits == "" {
			break
		}
		current = p.Inherits
	}

	resolved := make(map[string]bool, len(c.Profiles))
	for n := range c.Profiles {
		resolved[n] = true
	}
	for _, n := range chain {
		delete(resolved, n)
	}
	if err := c.resolveProfileInheritance(chain, resolved); err != nil {
		return fmt.Errorf("profile inheritance error: %w", err)
	}

	for _, n := range chain {
		stripUntrustedInheritedSessionName(c, n)
		if err := validateSessionName(c.Profiles[n].Container.SessionName); err != nil {
			return fmt.Errorf("profile %q: %w", n, err)
		}
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
