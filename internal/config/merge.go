package config

import "fmt"

// Merge merges another config into this one (other takes precedence).
func (c *Config) Merge(other *Config) {
	mergeContainerInto(&c.Container, &other.Container)

	if other.Defaults.Profile != "" {
		c.Defaults.Profile = other.Defaults.Profile
	}
	if len(other.Defaults.ForwardEnv) > 0 {
		c.Defaults.ForwardEnv = MergeStringSliceUnique(c.Defaults.ForwardEnv, other.Defaults.ForwardEnv)
	}
	if len(other.Defaults.Environment) > 0 {
		if c.Defaults.Environment == nil {
			c.Defaults.Environment = make(map[string]string)
		}
		for k, v := range other.Defaults.Environment {
			c.Defaults.Environment[k] = v
		}
	}
	if len(other.Defaults.EnvCommands) > 0 {
		if c.Defaults.EnvCommands == nil {
			c.Defaults.EnvCommands = make(map[string]string)
		}
		for k, v := range other.Defaults.EnvCommands {
			c.Defaults.EnvCommands[k] = v
		}
	}
	if other.Defaults.EnvCommandTimeout != "" {
		c.Defaults.EnvCommandTimeout = other.Defaults.EnvCommandTimeout
	}
	if len(other.Prompts) > 0 {
		if c.Prompts == nil {
			c.Prompts = make(map[string]PromptEntry)
		}
		for k, v := range other.Prompts {
			c.Prompts[k] = v
		}
	}
	if len(other.Mounts.Default) > 0 {
		c.Mounts.Default = append(c.Mounts.Default, other.Mounts.Default...)
	}
	if len(other.Sockets) > 0 {
		c.Sockets = append(c.Sockets, other.Sockets...)
	}
	mergePortsInto(&c.Ports, &other.Ports)
	if len(other.Credentials) > 0 {
		c.Credentials = append(c.Credentials, other.Credentials...)
	}

	mergePathsInto(&c.Paths, &other.Paths)
	mergeIncusInto(&c.Incus, &other.Incus)
	mergeNetworkInto(&c.Network, &other.Network)
	mergeShellInto(&c.Shell, &other.Shell)
	mergeToolInto(&c.Tool, &other.Tool)
	mergeLimits(&c.Limits, &other.Limits)
	mergeGitInto(&c.Git, &other.Git)
	mergeSSHInto(&c.SSH, &other.SSH)
	mergeSecurityInto(&c.Security, &other.Security)
	mergeMonitoring(&c.Monitoring, &other.Monitoring)
	mergeTimezoneInto(&c.Timezone, &other.Timezone)
	mergeDetectionInto(&c.Detection, &other.Detection)

	expandConfigPaths(c)
}

// mergeLimits merges limit configurations (other takes precedence)
func mergeLimits(base *LimitsConfig, other *LimitsConfig) {
	// Merge CPU limits
	if other.CPU.Count != "" {
		base.CPU.Count = other.CPU.Count
	}
	if other.CPU.Allowance != "" {
		base.CPU.Allowance = other.CPU.Allowance
	}
	if other.CPU.Priority != 0 {
		base.CPU.Priority = other.CPU.Priority
	}

	// Merge memory limits
	if other.Memory.Limit != "" {
		base.Memory.Limit = other.Memory.Limit
	}
	if other.Memory.Enforce != "" {
		base.Memory.Enforce = other.Memory.Enforce
	}
	if other.Memory.Swap != "" {
		base.Memory.Swap = other.Memory.Swap
	}

	// Merge disk limits
	if other.Disk.Read != "" {
		base.Disk.Read = other.Disk.Read
	}
	if other.Disk.Write != "" {
		base.Disk.Write = other.Disk.Write
	}
	if other.Disk.Max != "" {
		base.Disk.Max = other.Disk.Max
	}
	if other.Disk.Priority != 0 {
		base.Disk.Priority = other.Disk.Priority
	}
	if other.Disk.Size != "" {
		base.Disk.Size = other.Disk.Size
	}
	if other.Disk.TmpfsSize != "" {
		base.Disk.TmpfsSize = other.Disk.TmpfsSize
	}

	// Merge runtime limits
	if other.Runtime.MaxDuration != "" {
		base.Runtime.MaxDuration = other.Runtime.MaxDuration
	}
	if other.Runtime.MaxProcesses != 0 {
		base.Runtime.MaxProcesses = other.Runtime.MaxProcesses
	}
	if other.Runtime.AutoStop != nil {
		base.Runtime.AutoStop = other.Runtime.AutoStop
	}
	if other.Runtime.StopGraceful != nil {
		base.Runtime.StopGraceful = other.Runtime.StopGraceful
	}
}

// mergeMonitoring merges monitoring configurations (other takes precedence)
func mergeMonitoring(base *MonitoringConfig, other *MonitoringConfig) {
	if other.Enabled != nil {
		base.Enabled = other.Enabled
	}
	if other.AutoPauseOnHigh != nil {
		base.AutoPauseOnHigh = other.AutoPauseOnHigh
	}
	if other.AutoKillOnCritical != nil {
		base.AutoKillOnCritical = other.AutoKillOnCritical
	}
	if other.ForensicsOnKill != nil {
		base.ForensicsOnKill = other.ForensicsOnKill
	}
	if other.ReverseShellOneLiners != nil {
		base.ReverseShellOneLiners = other.ReverseShellOneLiners
	}

	// Merge thresholds
	if other.PollIntervalSec != 0 {
		base.PollIntervalSec = other.PollIntervalSec
	}
	if other.FileReadThresholdMB != 0 {
		base.FileReadThresholdMB = other.FileReadThresholdMB
	}
	if other.FileReadRateMBPerSec != 0 {
		base.FileReadRateMBPerSec = other.FileReadRateMBPerSec
	}
	if other.ProcessCountThreshold != 0 {
		base.ProcessCountThreshold = other.ProcessCountThreshold
	}
	if other.ProcessSpawnRateThreshold != nil {
		base.ProcessSpawnRateThreshold = other.ProcessSpawnRateThreshold
	}
	if other.AuditLogRetentionDays != 0 {
		base.AuditLogRetentionDays = other.AuditLogRetentionDays
	}

	// Merge NFT monitoring
	if other.NFT.Enabled != nil {
		base.NFT.Enabled = other.NFT.Enabled
	}
	if other.NFT.RateLimitPerSecond != 0 {
		base.NFT.RateLimitPerSecond = other.NFT.RateLimitPerSecond
	}
	if other.NFT.DNSQueryThreshold != 0 {
		base.NFT.DNSQueryThreshold = other.NFT.DNSQueryThreshold
	}
	if other.NFT.LogDNSQueries != nil {
		base.NFT.LogDNSQueries = other.NFT.LogDNSQueries
	}
	if other.NFT.LimaHost != "" {
		base.NFT.LimaHost = other.NFT.LimaHost
	}
}

// MergeStringSliceUnique appends items from other to base, skipping duplicates
func MergeStringSliceUnique(base, other []string) []string {
	seen := make(map[string]bool, len(base))
	for _, s := range base {
		seen[s] = true
	}
	for _, s := range other {
		if !seen[s] {
			base = append(base, s)
			seen[s] = true
		}
	}
	return base
}

// GetProfile returns a profile by name, or nil if not found
func (c *Config) GetProfile(name string) *ProfileConfig {
	if profile, ok := c.Profiles[name]; ok {
		return &profile
	}
	return nil
}

// ApplyProfile applies a profile's settings to the defaults.
// Returns an error if the profile is not found or fails validation.
func (c *Config) ApplyProfile(name string) error {
	profile := c.GetProfile(name)
	if profile == nil {
		return fmt.Errorf("profile '%s' not found", name)
	}

	if err := profile.Validate(name); err != nil {
		return err
	}

	// Save the project-level alias before merging — profiles must not
	// override it because aliases are workspace-specific and a profile
	// used across multiple projects must not stamp them with a single name.
	projectAlias := c.Container.Alias
	mergeContainerInto(&c.Container, &profile.Container)
	if projectAlias != "" {
		c.Container.Alias = projectAlias
	}
	if profile.Context != "" {
		c.ProfileContextFile = profile.Context
	}

	// Apply profile environment if present
	if len(profile.Environment) > 0 {
		if c.Defaults.Environment == nil {
			c.Defaults.Environment = make(map[string]string)
		}
		for k, v := range profile.Environment {
			c.Defaults.Environment[k] = v
		}
	}
	if len(profile.EnvCommands) > 0 {
		if c.Defaults.EnvCommands == nil {
			c.Defaults.EnvCommands = make(map[string]string)
		}
		for k, v := range profile.EnvCommands {
			c.Defaults.EnvCommands[k] = v
		}
	}
	if profile.EnvCommandTimeout != "" {
		c.Defaults.EnvCommandTimeout = profile.EnvCommandTimeout
	}
	if len(profile.ForwardEnv) > 0 {
		c.Defaults.ForwardEnv = MergeStringSliceUnique(c.Defaults.ForwardEnv, profile.ForwardEnv)
	}
	if len(profile.Prompts) > 0 {
		// Untrusted (project-scoped) profiles have their [prompts] stripped at
		// load (sanitizeUntrustedPrompts), so anything here came from trusted
		// scope and may layer onto the base config.
		if c.Prompts == nil {
			c.Prompts = make(map[string]PromptEntry)
		}
		for k, v := range profile.Prompts {
			c.Prompts[k] = v
		}
	}
	if len(profile.Mounts) > 0 {
		c.Mounts.Default = append(c.Mounts.Default, profile.Mounts...)
	}
	if len(profile.Sockets) > 0 {
		c.Sockets = append(c.Sockets, profile.Sockets...)
	}
	if profile.Ports != nil {
		mergePortsInto(&c.Ports, profile.Ports)
	}
	if len(profile.Credentials) > 0 {
		c.Credentials = append(c.Credentials, profile.Credentials...)
	}

	// Apply struct sections
	if profile.Limits != nil {
		mergeLimits(&c.Limits, profile.Limits)
	}
	if profile.Monitoring != nil {
		mergeMonitoring(&c.Monitoring, profile.Monitoring)
	}
	if profile.Tool != nil {
		mergeToolInto(&c.Tool, profile.Tool)
	}
	if profile.Shell != nil {
		mergeShellInto(&c.Shell, profile.Shell)
	}
	if profile.Network != nil {
		mergeNetworkInto(&c.Network, profile.Network)
	}
	if profile.Paths != nil {
		mergePathsInto(&c.Paths, profile.Paths)
	}
	if profile.Incus != nil {
		mergeIncusInto(&c.Incus, profile.Incus)
	}
	if profile.Git != nil {
		mergeGitInto(&c.Git, profile.Git)
	}
	if profile.SSH != nil {
		mergeSSHInto(&c.SSH, profile.SSH)
	}
	if profile.Security != nil {
		mergeSecurityInto(&c.Security, profile.Security)
	}
	if profile.Timezone != nil {
		mergeTimezoneInto(&c.Timezone, profile.Timezone)
	}

	expandConfigPaths(c)
	return nil
}

// ReapplyProfileContainer re-merges ONLY the container section of the named
// profile into the config. Used after a workspace-config overlay so an
// explicitly requested profile keeps winning over the project's
// [container] settings (image, persistent, storage pool, build) — the
// overlay merges the project config on top of the profile applied earlier
// in PersistentPreRunE. Unlike a full ApplyProfile, this is idempotent:
// mergeContainerInto/mergeBuildInto are field-level overrides with no
// appends, so it is safe to call after a profile was already applied
// (a full re-apply would duplicate profile mounts and sockets).
// The project alias is preserved, mirroring ApplyProfile.
func (c *Config) ReapplyProfileContainer(name string) error {
	profile := c.GetProfile(name)
	if profile == nil {
		return fmt.Errorf("profile '%s' not found", name)
	}
	projectAlias := c.Container.Alias
	mergeContainerInto(&c.Container, &profile.Container)
	if projectAlias != "" {
		c.Container.Alias = projectAlias
	}
	return nil
}

// mergeContainerInto merges src into dst for the container-shape section.
func mergeContainerInto(dst *ContainerConfig, src *ContainerConfig) {
	if src == nil {
		return
	}
	mergeScalar(&dst.Image, src.Image)
	mergePtr(&dst.Persistent, src.Persistent)
	mergeScalar(&dst.ShutdownTimeout, src.ShutdownTimeout)
	mergeScalar(&dst.ReadyTimeout, src.ReadyTimeout)
	mergeScalar(&dst.StoragePool, src.StoragePool)
	mergeScalar(&dst.Alias, src.Alias)
	mergeScalar(&dst.StaleBaseCheck, src.StaleBaseCheck)
	mergeScalar(&dst.SessionName, src.SessionName)
	mergePtr(&dst.Docker, src.Docker)
	mergeBuildInto(&dst.Build, &src.Build)
}

// mergePortsInto overlays src's ports section onto dst: a non-zero pool wins
// (pool provenance follows the winning source), and map entries with a name
// dst already has REPLACE the earlier entry while new names append — so
// re-applying a profile synthesized from the merged config (the "default"
// profile) is a no-op instead of doubling every entry, and a later scope can
// override an earlier entry's ports without duplicating its device name.
// When an UNTRUSTED pool overwrites a trusted one, the trusted value is
// remembered in PoolTrustedFallback so the trust gate can fall back to it
// instead of silently disabling the user's own pool.
func mergePortsInto(dst, src *PortsConfig) {
	if src == nil || !src.HasPorts() {
		return
	}
	if src.Pool > 0 {
		switch {
		case src.PoolUntrusted && dst.Pool > 0 && !dst.PoolUntrusted:
			dst.PoolTrustedFallback = dst.Pool
		case !src.PoolUntrusted:
			dst.PoolTrustedFallback = 0 // a trusted winner needs no fallback
		}
		dst.Pool = src.Pool
		dst.PoolUntrusted = src.PoolUntrusted
		dst.PoolSourcePath = src.PoolSourcePath
	}
	for _, e := range src.Map {
		replaced := false
		for i := range dst.Map {
			if dst.Map[i].Name == e.Name {
				dst.Map[i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			dst.Map = append(dst.Map, e)
		}
	}
}

func clonePortsConfig(src *PortsConfig) *PortsConfig {
	if src == nil {
		return nil
	}
	out := *src
	out.Map = cloneSlice(src.Map)
	return &out
}

// mergeProfiles merges a parent profile into a child profile.
// Maps merge (child wins), arrays replace if child defines them, scalars child wins if set.
// Struct pointers deep-merge field by field if child defines the section.
func mergeProfiles(parent, child ProfileConfig) ProfileConfig {
	result := child

	// Container section: deep field-by-field merge starting from parent
	mergedContainer := parent.Container
	mergeContainerInto(&mergedContainer, &child.Container)
	result.Container = mergedContainer

	// Scalars: child overrides parent if set
	if result.Context == "" {
		result.Context = parent.Context
	}

	// Maps: deep merge — parent keys preserved, child keys override
	if len(parent.Environment) > 0 {
		merged := make(map[string]string, len(parent.Environment)+len(result.Environment))
		for k, v := range parent.Environment {
			merged[k] = v
		}
		for k, v := range result.Environment {
			if v == "" {
				// Empty string clears inherited key
				delete(merged, k)
			} else {
				merged[k] = v
			}
		}
		result.Environment = merged
	}

	// EnvCommands: deep merge with the same semantics as Environment — parent
	// keys preserved, child keys override, an empty child value clears the
	// inherited key. Without this a child profile silently loses the parent's
	// env_commands (they are trusted-scope, so this only affects trusted profiles).
	if len(parent.EnvCommands) > 0 {
		merged := make(map[string]string, len(parent.EnvCommands)+len(result.EnvCommands))
		for k, v := range parent.EnvCommands {
			merged[k] = v
		}
		for k, v := range result.EnvCommands {
			if v == "" {
				delete(merged, k)
			} else {
				merged[k] = v
			}
		}
		result.EnvCommands = merged
	}

	// EnvCommandTimeout: scalar inherit — child value wins, else take parent's.
	if result.EnvCommandTimeout == "" {
		result.EnvCommandTimeout = parent.EnvCommandTimeout
	}

	// Prompts: deep merge — parent keys preserved, child keys override (#701).
	// A child entry with empty text AND empty file clears the inherited key,
	// mirroring the Environment/EnvCommands clear-on-empty semantics.
	if len(parent.Prompts) > 0 {
		merged := make(map[string]PromptEntry, len(parent.Prompts)+len(result.Prompts))
		for k, v := range parent.Prompts {
			merged[k] = v
		}
		for k, v := range result.Prompts {
			if v.Text == "" && v.File == "" {
				delete(merged, k)
			} else {
				merged[k] = v
			}
		}
		result.Prompts = merged
	}

	// Arrays: if child defines them, they fully replace parent's. If not, inherit.
	if result.Mounts == nil {
		result.Mounts = parent.Mounts
	}
	if result.Sockets == nil {
		result.Sockets = parent.Sockets
	}
	if result.Ports == nil {
		result.Ports = parent.Ports
	}
	if result.Credentials == nil {
		result.Credentials = parent.Credentials
	}
	if result.ForwardEnv == nil {
		result.ForwardEnv = parent.ForwardEnv
	}

	// Struct pointers: deep field-by-field merge if child defines section
	result.Limits = mergeStructPtr(parent.Limits, result.Limits, mergeLimitsInto)
	result.Tool = mergeStructPtr(parent.Tool, result.Tool, mergeToolInto)
	result.Network = mergeStructPtr(parent.Network, result.Network, mergeNetworkInto)
	result.Monitoring = mergeStructPtr(parent.Monitoring, result.Monitoring, mergeMonitoringInto)

	// New extended fields: scalar and struct pointer merges
	result.Paths = mergeStructPtr(parent.Paths, result.Paths, mergePathsInto)
	result.Incus = mergeStructPtr(parent.Incus, result.Incus, mergeIncusInto)
	result.Git = mergeStructPtr(parent.Git, result.Git, mergeGitInto)
	result.SSH = mergeStructPtr(parent.SSH, result.SSH, mergeSSHInto)
	result.Security = mergeStructPtr(parent.Security, result.Security, mergeSecurityInto)
	result.Timezone = mergeStructPtr(parent.Timezone, result.Timezone, mergeTimezoneInto)
	result.Shell = mergeStructPtr(parent.Shell, result.Shell, mergeShellInto)

	return result
}

// mergeStructPtr merges two struct pointers: if child is nil, inherit parent;
// if both set, deep-merge child fields into a copy of parent.
func mergeStructPtr[T any](parent, child *T, mergeFn func(dst *T, src *T)) *T {
	if child == nil {
		return parent
	}
	if parent == nil {
		return child
	}
	merged := *parent
	mergeFn(&merged, child)
	return &merged
}

// mergeScalar copies src into *dst when src is non-zero — the config "unset"
// sentinel for strings, ints, and named-string types. Equivalent to the
// historical `if src.X != "" { dst.X = src.X }` / `!= 0` field merges.
func mergeScalar[T comparable](dst *T, src T) {
	var zero T
	if src != zero {
		*dst = src
	}
}

// mergePtr copies a non-nil src pointer into *dst — for optional/tristate
// (*bool) fields. Equivalent to `if src.X != nil { dst.X = src.X }`.
func mergePtr[T any](dst **T, src *T) {
	if src != nil {
		*dst = src
	}
}

// mergeSlice copies a non-nil src slice into *dst (replace semantics), for the
// slice fields merged with `if src.X != nil { dst.X = src.X }`.
func mergeSlice[T any](dst *[]T, src []T) {
	if src != nil {
		*dst = src
	}
}

// mergeFlag ORs a bool: a true src wins; a false src never clears an existing
// true. Equivalent to `if src.X { dst.X = true }`.
func mergeFlag(dst *bool, src bool) {
	if src {
		*dst = true
	}
}

func mergeLimitsInto(dst *LimitsConfig, src *LimitsConfig) {
	mergeLimits(dst, src)
}

func mergeToolInto(dst *ToolConfig, src *ToolConfig) {
	mergeScalar(&dst.Name, src.Name)
	mergeScalar(&dst.Binary, src.Binary)
	mergeScalar(&dst.PermissionMode, src.PermissionMode)
	mergeScalar(&dst.ContextFile, src.ContextFile)
	mergePtr(&dst.AutoContext, src.AutoContext)
	mergePtr(&dst.ContextJSON, src.ContextJSON)
	mergeScalar(&dst.ContextJSONFile, src.ContextJSONFile)
	mergeSlice(&dst.PreLaunch, src.PreLaunch)
	mergeScalar(&dst.Claude.EffortLevel, src.Claude.EffortLevel)
	mergeScalar(&dst.Claude.Model, src.Claude.Model)
	mergeScalar(&dst.Codex.Model, src.Codex.Model)
	mergeScalar(&dst.Codex.ReasoningEffort, src.Codex.ReasoningEffort)
}

func mergeBuildInto(dst *BuildConfig, src *BuildConfig) {
	mergeScalar(&dst.Base, src.Base)
	mergeScalar(&dst.Script, src.Script)
	mergeSlice(&dst.Commands, src.Commands)
	mergeScalar(&dst.Compression, src.Compression)
	if len(src.Agents) > 0 {
		dst.Agents = src.Agents
	}
}

func mergeNetworkInto(dst *NetworkConfig, src *NetworkConfig) {
	mergeScalar(&dst.Mode, src.Mode)
	mergePtr(&dst.BlockPrivateNetworks, src.BlockPrivateNetworks)
	mergePtr(&dst.BlockMetadataEndpoint, src.BlockMetadataEndpoint)
	mergePtr(&dst.AllowLocalNetworkAccess, src.AllowLocalNetworkAccess)
	mergePtr(&dst.UseSudo, src.UseSudo)
	mergeSlice(&dst.AllowedDomains, src.AllowedDomains)
	mergeScalar(&dst.RefreshIntervalMinutes, src.RefreshIntervalMinutes)
	mergeSlice(&dst.Hosts, src.Hosts)
	mergeSlice(&dst.DNSServers, src.DNSServers)
	mergeSlice(&dst.AllowedPorts, src.AllowedPorts)
	mergeScalar(&dst.Logging.Path, src.Logging.Path)
	mergePtr(&dst.Logging.Enabled, src.Logging.Enabled)
}

func mergeMonitoringInto(dst *MonitoringConfig, src *MonitoringConfig) {
	mergeMonitoring(dst, src)
}

func mergePathsInto(dst *PathsConfig, src *PathsConfig) {
	mergeScalar(&dst.SessionsDir, src.SessionsDir)
	mergeScalar(&dst.StorageDir, src.StorageDir)
	mergeScalar(&dst.LogsDir, src.LogsDir)
	mergeFlag(&dst.PreserveWorkspacePath, src.PreserveWorkspacePath)
}

func mergeIncusInto(dst *IncusConfig, src *IncusConfig) {
	mergeScalar(&dst.Project, src.Project)
	mergeScalar(&dst.Group, src.Group)
	mergeScalar(&dst.CodeUID, src.CodeUID)
	mergeScalar(&dst.CodeUser, src.CodeUser)
	mergeFlag(&dst.DisableShift, src.DisableShift)
}

func mergeGitInto(dst *GitConfig, src *GitConfig) {
	mergePtr(&dst.WritableHooks, src.WritableHooks)
	mergeScalar(&dst.Name, src.Name)
	mergeScalar(&dst.Email, src.Email)
	mergePtr(&dst.SeedHostIdentity, src.SeedHostIdentity)
	mergePtr(&dst.Readonly, src.Readonly)
	mergePtr(&dst.StripAttribution, src.StripAttribution)
	// Replacement, not union: a later scope's pattern list fully defines what is
	// stripped (the built-in defaults apply only when no scope sets any).
	if len(src.StripAttributionPatterns) > 0 {
		dst.StripAttributionPatterns = src.StripAttributionPatterns
	}
	// Pointer merge (not len-based) so a later scope can set `protected_branches
	// = []` to DISABLE the guard — an empty slice is a real value here, distinct
	// from an absent (nil) field that inherits the default.
	if src.ProtectedBranches != nil {
		dst.ProtectedBranches = src.ProtectedBranches
	}
}

func mergeSSHInto(dst *SSHConfig, src *SSHConfig) {
	mergePtr(&dst.ForwardAgent, src.ForwardAgent)
}

func mergeSecurityInto(dst *SecurityConfig, src *SecurityConfig) {
	if len(src.ProtectedPaths) > 0 {
		dst.ProtectedPaths = src.ProtectedPaths
	}
	if len(src.AdditionalProtectedPaths) > 0 {
		dst.AdditionalProtectedPaths = MergeStringSliceUnique(dst.AdditionalProtectedPaths, src.AdditionalProtectedPaths)
	}
	mergeFlag(&dst.DisableProtection, src.DisableProtection)
	mergePtr(&dst.HostImmutable, src.HostImmutable)
	if len(src.WritablePaths) > 0 {
		dst.WritablePaths = MergeStringSliceUnique(dst.WritablePaths, src.WritablePaths)
	}
	if len(src.SecretPaths) > 0 {
		dst.SecretPaths = MergeStringSliceUnique(dst.SecretPaths, src.SecretPaths)
	}
	mergePtr(&dst.ReduceKernelSurface, src.ReduceKernelSurface)
	mergePtr(&dst.ReduceKernelSurfaceStrict, src.ReduceKernelSurfaceStrict)
}

func mergeTimezoneInto(dst *TimezoneConfig, src *TimezoneConfig) {
	mergeScalar(&dst.Mode, src.Mode)
	mergeScalar(&dst.Name, src.Name)
}

func mergeShellInto(dst *ShellConfig, src *ShellConfig) {
	mergePtr(&dst.UseTmux, src.UseTmux)
}

func mergeDetectionInto(dst *DetectionConfig, src *DetectionConfig) {
	mergeScalar(&dst.GTFOBinsSource, src.GTFOBinsSource)
	mergeScalar(&dst.GTFOBinsDir, src.GTFOBinsDir)
	mergeScalar(&dst.SigmaSource, src.SigmaSource)
	mergeScalar(&dst.SigmaDir, src.SigmaDir)
}

// ResolveProfileInheritance resolves all inheritance chains in loaded profiles.
// It flattens each profile so that after resolution, profiles are self-contained.
// Detects cycles and enforces a maximum inheritance depth.
func (c *Config) ResolveProfileInheritance() error {
	// First pass: validate chain lengths and detect cycles before any resolution.
	// This ensures max depth is checked against the full chain, not just recursion depth.
	for name := range c.Profiles {
		if c.Profiles[name].Inherits == "" {
			continue
		}
		visited := map[string]bool{name: true}
		current := name
		for {
			parent := c.Profiles[current].Inherits
			if parent == "" {
				break
			}
			if visited[parent] {
				return fmt.Errorf("profile inheritance cycle detected involving %q", parent)
			}
			if _, exists := c.Profiles[parent]; !exists {
				return fmt.Errorf("profile %q inherits from %q, but parent profile not found", current, parent)
			}
			if len(visited) > maxInheritanceDepth {
				return fmt.Errorf("profile inheritance chain exceeds maximum depth of %d", maxInheritanceDepth)
			}
			visited[parent] = true
			current = parent
		}
	}

	// Second pass: resolve inheritance by merging parent into child.
	resolved := make(map[string]bool, len(c.Profiles))

	var resolve func(name string) error
	resolve = func(name string) error {
		if resolved[name] {
			return nil
		}

		profile := c.Profiles[name]
		if profile.Inherits == "" {
			resolved[name] = true
			return nil
		}

		parentName := profile.Inherits

		// Resolve parent first
		if err := resolve(parentName); err != nil {
			return err
		}

		// Parent is now resolved — merge
		parent := c.Profiles[parentName]
		merged := mergeProfiles(parent, profile)

		// Preserve the original direct parent name for display/inspection
		// while still flattening the effective configuration values.
		merged.Inherits = parentName

		c.Profiles[name] = merged
		resolved[name] = true
		return nil
	}

	for name := range c.Profiles {
		if err := resolve(name); err != nil {
			return err
		}
	}

	return nil
}
