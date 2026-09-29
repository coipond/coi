package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// GetDefaultConfig returns the default configuration by parsing the embedded default config TOML.
func GetDefaultConfig() *Config {
	cfg := &Config{}
	if _, err := toml.Decode(string(EmbeddedDefaultConfig), cfg); err != nil {
		// Fatal: embedded config is broken — programming error
		panic(fmt.Sprintf("failed to parse embedded default config: %v", err))
	}

	// Expand ~ in all path fields
	expandConfigPaths(cfg)

	// Initialize runtime-only fields
	cfg.Profiles = make(map[string]ProfileConfig)

	// Ensure empty slices are initialized (TOML doesn't set them)
	if cfg.Security.AdditionalProtectedPaths == nil {
		cfg.Security.AdditionalProtectedPaths = []string{}
	}
	if cfg.Mounts.Default == nil {
		cfg.Mounts.Default = []MountEntry{}
	}

	return cfg
}

// expandConfigPaths expands ~ in all path fields of the config.
// Called once at the end of Merge and ApplyProfile so that path-merging
// helpers can work with raw (unexpanded) strings.
func expandConfigPaths(cfg *Config) {
	cfg.Paths.SessionsDir = ExpandPath(cfg.Paths.SessionsDir)
	cfg.Paths.StorageDir = ExpandPath(cfg.Paths.StorageDir)
	cfg.Paths.LogsDir = ExpandPath(cfg.Paths.LogsDir)
	cfg.Tool.ContextFile = ExpandPath(cfg.Tool.ContextFile)
	cfg.Tool.ContextJSONFile = ExpandPath(cfg.Tool.ContextJSONFile)
	cfg.Network.Logging.Path = ExpandPath(cfg.Network.Logging.Path)
	cfg.Detection.GTFOBinsDir = ExpandPath(cfg.Detection.GTFOBinsDir)
	cfg.Detection.SigmaDir = ExpandPath(cfg.Detection.SigmaDir)
}

// cloneSlice returns a shallow copy of a slice (nil-safe).
func cloneSlice[S ~[]E, E any](in S) S {
	if in == nil {
		return nil
	}
	out := make(S, len(in))
	copy(out, in)
	return out
}

// cloneMap returns a shallow copy of a map (nil-safe).
func cloneMap[M ~map[K]V, K comparable, V any](in M) M {
	if in == nil {
		return nil
	}
	out := make(M, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// synthesizeDefaultProfile creates a ProfileConfig from the loaded Config,
// representing the "default" built-in profile.
// All struct fields are copied by value (not aliased) so that applying
// or merging the default profile cannot mutate the original Config.
func synthesizeDefaultProfile(cfg *Config) ProfileConfig {
	limits := cfg.Limits
	tool := cfg.Tool
	shell := cfg.Shell
	network := cfg.Network
	network.AllowedDomains = cloneSlice(cfg.Network.AllowedDomains)
	network.DNSServers = cloneSlice(cfg.Network.DNSServers)
	network.AllowedPorts = cloneSlice(cfg.Network.AllowedPorts)
	paths := cfg.Paths
	incus := cfg.Incus
	git := cfg.Git
	git.StripAttributionPatterns = cloneSlice(cfg.Git.StripAttributionPatterns)
	// ProtectedBranches is a *[]string: copy the pointer to a freshly cloned slice
	// so the synthesized profile never shares backing storage with the original
	// (nil stays nil, preserving the "use default" tri-state).
	if cfg.Git.ProtectedBranches != nil {
		pb := cloneSlice(*cfg.Git.ProtectedBranches)
		git.ProtectedBranches = &pb
	}
	ssh := cfg.SSH
	security := cfg.Security
	security.ProtectedPaths = cloneSlice(cfg.Security.ProtectedPaths)
	security.AdditionalProtectedPaths = cloneSlice(cfg.Security.AdditionalProtectedPaths)
	security.WritablePaths = cloneSlice(cfg.Security.WritablePaths)
	security.SecretPaths = cloneSlice(cfg.Security.SecretPaths)
	monitoring := cfg.Monitoring
	timezone := cfg.Timezone

	container := cfg.Container
	container.Build.Commands = cloneSlice(cfg.Container.Build.Commands)
	container.Build.Agents = cloneSlice(cfg.Container.Build.Agents)

	p := ProfileConfig{
		Container:   container,
		Environment: cloneMap(cfg.Defaults.Environment),
		EnvCommands: cloneMap(cfg.Defaults.EnvCommands),
		ForwardEnv:  cloneSlice(cfg.Defaults.ForwardEnv),
		Limits:      &limits,
		Tool:        &tool,
		Shell:       &shell,
		Network:     &network,
		Mounts:      cloneSlice(cfg.Mounts.Default),
		Sockets:     cloneSlice(cfg.Sockets),
		Ports:       clonePortsConfig(&cfg.Ports),
		Credentials: cloneSlice(cfg.Credentials),
		Paths:       &paths,
		Incus:       &incus,
		Git:         &git,
		SSH:         &ssh,
		Security:    &security,
		Monitoring:  &monitoring,
		Timezone:    &timezone,
		Source:      "(built-in)",
	}
	return p
}

// synthesizeHardenedProfile returns the built-in "hardened" profile: a hardened
// preset for opening untrusted / freshly-cloned repositories. It bundles COI's
// strongest controls (no in-shell policing) so `coi shell --profile hardened`
// is a one-flag, maximally-safe way to inspect code you don't trust.
//
// Unlike the "default" profile this is a FIXED baseline, not a clone of the
// user's resolved config: it sets only the hardened overrides and lets every
// other field fall through. It can be overridden by a same-named disk profile.
//
// Limitation: profile merges are additive for slice fields, so it cannot
// *subtract* a globally-configured forward_env, nor force protections back on if
// the user globally set disable_protection=true. It hardens network egress,
// secrets, immutability, ephemerality, SSH-agent forwarding, and monitoring.
func synthesizeHardenedProfile() ProfileConfig {
	t, f := true, false
	return ProfileConfig{
		Source: "(built-in)",
		// Ephemeral: nothing from a risky session persists. Docker/nesting is
		// left off by reduce_kernel_surface below (the single hardening switch),
		// so no explicit docker flag is needed here — and omitting it lets an
		// explicit user `docker = true` surface the override warning rather than
		// being silently masked.
		Container: ContainerConfig{Persistent: &f},
		// No exfil path: internet-only, block LAN + cloud metadata endpoints.
		Network: &NetworkConfig{
			Mode:                    NetworkModeRestricted,
			BlockPrivateNetworks:    &t,
			BlockMetadataEndpoint:   &t,
			AllowLocalNetworkAccess: &f,
		},
		// Never forward the host SSH agent into an untrusted repo's container
		// (overrides a global forward_agent = true).
		SSH: &SSHConfig{ForwardAgent: &f},
		// Host-side immutability on; mask common secret files (union-merged with
		// any the user already configured). protected_paths defaults already cover
		// .claude/settings*.json, .git/hooks, .coi, etc.
		Security: &SecurityConfig{
			HostImmutable: &t,
			SecretPaths:   cloneSlice(HardenedProfileSecretPaths),
			// Shrink the shared-kernel attack surface: no nesting, and the
			// syscall families behind most recent kernel escape chains denied.
			ReduceKernelSurface: &t,
		},
		// Catch in-container exfil / reverse-shell attempts and auto-respond.
		Monitoring: &MonitoringConfig{
			Enabled:            &t,
			AutoPauseOnHigh:    &t,
			AutoKillOnCritical: &t,
			NFT:                NFTMonitoringConfig{Enabled: &t},
		},
		// Bound the session: the Trail of Bits agent-escape report's chains
		// took 12+ hours of autonomous persistence — a hardened session for an
		// untrusted repo should not run unattended for that long. auto_stop
		// defaults to true, so this alone arms the shutdown timer; users who
		// need longer can override max_duration in their own config/profile.
		Limits: &LimitsConfig{Runtime: RuntimeLimits{MaxDuration: "4h"}},
	}
}

// GetConfigPaths returns the list of config file paths to check (in order).
// COI looks for configuration in two places:
//  1. ~/.coi/config.toml        (user, co-located with sessions/storage/logs)
//  2. ./.coi/config.toml        (current project)
//
// If COI_CONFIG environment variable is set, it is added as highest priority.
func GetConfigPaths() []string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}

	paths := []string{
		filepath.Join(homeDir, ".coi", "config.toml"), // User config
		filepath.Join(workDir, ".coi", "config.toml"), // Project config
	}

	// COI_CONFIG environment variable has highest priority
	if envConfig := os.Getenv("COI_CONFIG"); envConfig != "" {
		paths = append(paths, envConfig)
	}

	return paths
}

// GetProfileParentDirs returns directories to scan for the "profiles/"
// subdirectory. Profiles found under any of these locations are merged into
// a single namespace; the loader rejects duplicate profile names across
// locations so it is always unambiguous which profile is in use.
//
// Scanned locations:
//  1. ~/.coi                    (user home; co-located with sessions/storage/logs)
//  2. ./.coi                    (current project)
//  3. dirname($COI_CONFIG)      (if COI_CONFIG is set)
func GetProfileParentDirs() []string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	workDir, err := os.Getwd()
	if err != nil {
		workDir = "."
	}

	dirs := []string{
		filepath.Join(homeDir, ".coi"), // 1. User home
		filepath.Join(workDir, ".coi"), // 2. Project
	}

	// COI_CONFIG environment variable: scan its parent dir for profiles too
	if envConfig := os.Getenv("COI_CONFIG"); envConfig != "" {
		dirs = append(dirs, filepath.Dir(envConfig))
	}

	return dirs
}

// ptrBool returns a pointer to a bool value
func ptrBool(b bool) *bool {
	return &b
}

// BoolVal safely dereferences a *bool, returning false if nil
func BoolVal(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// IntVal dereferences a *int config pointer, returning 0 if nil.
func IntVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// ExpandPath expands ~ in paths to home directory
func ExpandPath(path string) string {
	if len(path) == 0 {
		return path
	}
	if path[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path // Return path as-is if home dir cannot be determined
		}
		if len(path) == 1 {
			return homeDir
		}
		return filepath.Join(homeDir, path[1:])
	}
	return path
}
