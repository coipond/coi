package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/code-on-incus/internal/config"
	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/vmhost"
)

// ConfigureUIDMapping decides how the workspace mount maps host UIDs into the
// container and applies raw.idmap when needed. It is the single source of truth
// for both the shell (session.Setup) and run pipelines so they cannot diverge
// (issue #530). Returns the effective shift flag (for MountDisk) and whether
// raw.idmap was applied.
//
// Host-VM detection (whether the VM already handles UID mapping, as Colima/Lima
// do — but NOT OrbStack) is delegated to the shared internal/vmhost package.
//
// See decideUIDMapping for the case matrix; the key rule is that a host-UID /
// code-UID mismatch (macOS user 501, CI runner 1001, mapped to code=1000)
// ALWAYS sets raw.idmap and turns shift off — the previous code gated this on
// !disableShift, so the Colima/Lima path silently skipped it and writes to a
// non-1000-owned workspace failed.
//
// raw.idmap only takes effect at container START, so a caller that has ALREADY
// started the container (the run pipeline uses `incus launch` = create+start)
// must restart it when idmapApplied is true; the shell pipeline sets it before
// its own start, so it ignores idmapApplied.
//
// sources are the HOST paths this container's disk devices are sourced from
// (workspace first, then any configured mounts). Their filesystems decide
// whether an idmapped (shift=true) mount is possible at all, which is a
// property of the paths rather than of the VM around them (#683).
func ConfigureUIDMapping(containerName string, sources []string, disableShift bool, logger func(string)) (useShift, idmapApplied bool, err error) {
	if logger == nil {
		logger = func(string) {}
	}
	// Detect() reads /proc/mounts etc.; call it once and reuse.
	hostHandlesUIDMapping := vmhost.Detect().HandlesUIDMapping()
	blocking := vmhost.FirstBlockingSource(sources...)
	var idmap string
	useShift, idmap = decideUIDMapping(os.Getuid(), container.CodeUID, disableShift, hostHandlesUIDMapping, blocking != "")
	// Only worth saying when the filesystem actually decided the outcome —
	// asked of the decision matrix itself (by re-deciding without the blocking
	// source), so this can't drift from decideUIDMapping's precedence the way
	// a hand-copied condition would.
	if blocking != "" {
		if s, i := decideUIDMapping(os.Getuid(), container.CodeUID, disableShift, hostHandlesUIDMapping, false); s != useShift || i != idmap {
			logger(fmt.Sprintf("Mount source %s is on a filesystem that can't be relied on for idmapped (shift) mounts; using raw.idmap for this container instead", blocking))
		}
	}

	if idmap != "" {
		if os.Getuid() != container.CodeUID {
			logger(fmt.Sprintf("Host UID %d differs from container code UID %d, using raw.idmap: %s",
				os.Getuid(), container.CodeUID, idmap))
		} else {
			logger(fmt.Sprintf("Host UID %d matches container code UID but shift is off and the guest doesn't map it, using raw.idmap: %s",
				os.Getuid(), idmap))
		}
		if setErr := container.IncusExec("config", "set", containerName, "raw.idmap", idmap); setErr != nil {
			// Fail fast (#838): without this map the workspace mounts with no UID
			// mapping and is unwritable — silently continuing hands an agent a
			// broken /workspace. Abort with a cause the caller surfaces; when the
			// host UID is subordinate, also print the copy-paste fix.
			line, inRange := HostUIDSubordinateRange()
			if inRange {
				logger(rawIdmapGuidance())
			}
			return useShift, false, rawIdmapFailure(setErr, os.Getuid(), line)
		}
		return useShift, true, nil
	}

	if !useShift {
		logger("UID shifting disabled (Colima/Lima or configured); host UID matches container code UID")
	} else if disableShift || hostHandlesUIDMapping {
		// Colima/Lima was detected but host UID happens to equal code UID.
		logger("Auto-detected Colima/Lima environment - disabling UID shifting")
	}
	return useShift, false, nil
}

// rawIdmapFailure builds the fatal error for a rejected `raw.idmap` set — terse
// and staticcheck-clean (ST1005: no capital, no trailing punctuation/newline).
// The actionable multi-line fix is emitted separately via rawIdmapGuidance (a
// log line, not an error string). `line` is the offending /etc/subuid range, ""
// when the host UID isn't subordinate. Extracted (pure) so it is unit-testable.
func rawIdmapFailure(setErr error, hostUID int, line string) error {
	if line != "" {
		return fmt.Errorf("host UID %d is inside a subordinate ID range in /etc/subuid (%s), so Incus "+
			"cannot map it and the workspace would be unwritable (raw.idmap: %w)", hostUID, line, setErr)
	}
	return fmt.Errorf("cannot UID-map the workspace; it would be unwritable (raw.idmap: %w)", setErr)
}

// rawIdmapGuidance is the actionable, copy-paste fix printed (via the logger, so
// ST1005 doesn't apply) when the host UID is subordinate and can't be mapped
// (#838). Returned as a string so it's unit-testable.
func rawIdmapGuidance() string {
	return "To fix the UID mapping, pick one:\n" +
		"  1. Give Incus a dedicated delegation for your UID and restart it, then relaunch:\n" +
		"       echo \"root:$(id -u):1\" | sudo tee -a /etc/subuid /etc/subgid\n" +
		"       sudo systemctl restart incus\n" +
		fmt.Sprintf("  2. Or run coi as a user whose UID is below the subuid range (e.g. the image's uid-%d user).\n", container.CodeUID) +
		"Run `coi health` for a diagnosis."
}

// MountSources lists the HOST paths a session's disk devices are sourced from:
// the workspace, any configured extra mounts, and any extra device sources the
// caller knows about (the git-worktree common dir, whose device carries the
// same shift flag — see WorktreeSources). Protected paths and secret masks are
// not included — they live inside the workspace, so its filesystem already
// speaks for them. Empty extras are skipped.
func MountSources(workspacePath string, mountConfig *MountConfig, extra ...string) []string {
	sources := []string{workspacePath}
	if mountConfig != nil {
		for _, m := range mountConfig.Mounts {
			sources = append(sources, m.HostPath)
		}
	}
	for _, e := range extra {
		if e != "" {
			sources = append(sources, e)
		}
	}
	return sources
}

// WorktreeSources returns the host paths of a worktree layout's external git
// dirs for inclusion in MountSources (nil-safe). MountGitWorktreeDirs attaches
// the common dir as a shift-carrying disk device sourced OUTSIDE the
// workspace, so its filesystem must vote on the shift decision too (#683): a
// worktree on local disk whose main repo lives on a FUSE share would otherwise
// mount its entire git internals with junk ownership.
func WorktreeSources(layout *GitWorktreeLayout) []string {
	if layout == nil {
		return nil
	}
	return []string{layout.CommonDir}
}

// ResolveReuseUIDMapping is the reuse-path counterpart of ConfigureUIDMapping:
// it applies the fresh-launch mapping decision to a REUSED container, folds in
// the container's existing raw.idmap (which always wins — shift and raw.idmap
// are mutually exclusive, #685), and, when the decision is raw.idmap while the
// container still carries creation-time shift=true disk devices (created
// before the decision changed — e.g. by a pre-#683 coi on OrbStack ≥2.2.2,
// where the start failure the #678 reactive fallback keys on never happens),
// proactively converts those devices to shift=false so the raw.idmap actually
// takes effect. Returns the shift flag for devices re-added this session.
func ResolveReuseUIDMapping(containerName string, sources []string, disableShift bool, logger func(string)) bool {
	if logger == nil {
		logger = func(string) {}
	}
	hadRawIdmap := container.ContainerUsesRawIdmap(containerName)
	configuredShift, idmapApplied, err := ConfigureUIDMapping(containerName, sources, disableShift, logger)
	if err != nil {
		// Reuse heals an EXISTING container (fresh creation already fails fast on
		// this); log and carry on rather than block a reused session.
		logger(fmt.Sprintf("Warning: %v", err))
	}
	useShift := reuseShiftDecision(configuredShift, hadRawIdmap || idmapApplied)
	convertCreationTimeShiftDevices(containerName, idmapApplied, hadRawIdmap, logger)
	return useShift
}

// convertCreationTimeShiftDevices strips a container's creation-time shift=true
// disk devices (setting shift=false) when the mapping decision has just
// transitioned to raw.idmap (idmapApplied && !hadRawIdmap), so the newly-set
// raw.idmap actually takes effect (#683). It is a no-op on the steady state: a
// container that already carried raw.idmap had its devices converted when that
// first happened (creation, the #678 fallback, or an earlier reuse), so the
// per-device incus scan is skipped every later session. Shared by the reuse
// (ResolveReuseUIDMapping) and start (ResolveStartUIDMapping) paths.
func convertCreationTimeShiftDevices(containerName string, idmapApplied, hadRawIdmap bool, logger func(string)) {
	if !idmapApplied || hadRawIdmap {
		return
	}
	converted, failed := container.ConvertShiftedDiskDevices(containerName)
	if converted > 0 {
		logger(fmt.Sprintf("Converted %d creation-time shift=true disk device(s) to shift=false to match raw.idmap (#683)", converted))
	}
	if failed > 0 {
		logger(fmt.Sprintf("Warning: %d shift=true disk device(s) could not be converted to shift=false; the container may fail to start with raw.idmap set — retry, or recreate the container", failed))
	}
}

// ResolveStartUIDMapping is the `coi container start` counterpart of
// ResolveReuseUIDMapping. That command has no session context (workspace path,
// mount config), so it derives the statfs-sweep sources from the container's
// OWN disk devices and proactively applies the #683 shift→raw.idmap decision
// before start. On OrbStack ≥2.2.2 the shift mount succeeds-but-unwritable, so
// the reactive #678 fallback in StartWithIdmapFallback never fires; this heals
// a pre-#689 container up front (#691).
//
// It is deliberately a no-op when the container carries no shift=true disk
// device: `coi container start` runs against an arbitrary container, and — like
// the reactive fallbackShiftToRawIdmap, which only acts when shift devices
// exist — it must not mutate a container that has nothing to heal.
func ResolveStartUIDMapping(containerName string, disableShift bool, logger func(string)) {
	if logger == nil {
		logger = func(string) {}
	}
	// `coi container start` can target an arbitrary container in any state, so
	// scope the heal tightly (#691 review):
	//   - Skip a RUNNING container: raw.idmap/shift can't be changed to effect
	//     without a restart, and mutating a live instance only emits misleading
	//     "unwritable"/"could not convert" warnings. Skip on error too (don't
	//     act on uncertain state).
	if running, err := container.ContainerRunning(containerName); err != nil || running {
		return
	}
	sources, hasShiftDevice := container.DiskDeviceSources(containerName)
	if !hasShiftDevice {
		return
	}
	//   - Skip a container that isn't coi-managed: coi always mounts a disk
	//     device named "workspace", so an empty workspace source means this is
	//     someone else's container we must not rewrite.
	if container.NewManager(containerName).GetWorkspaceSource() == "" {
		return
	}
	hadRawIdmap := container.ContainerUsesRawIdmap(containerName)
	_, idmapApplied, err := ConfigureUIDMapping(containerName, sources, disableShift, logger)
	if err != nil {
		// Best-effort heal of an arbitrary container on `coi container start`; log
		// and continue rather than abort the start.
		logger(fmt.Sprintf("Warning: %v", err))
	}
	convertCreationTimeShiftDevices(containerName, idmapApplied, hadRawIdmap, logger)
}

// decideUIDMapping is the pure decision behind ConfigureUIDMapping (no I/O), so
// the case matrix — especially the issue #530 regression where a UID mismatch
// was skipped under Colima/Lima — is unit-testable. Returns the effective shift
// flag and the raw.idmap value to set (empty = none).
//
// A host-UID/code-UID mismatch ALWAYS wins: raw.idmap is set and shift is off,
// regardless of disableShift or Colima/Lima. shift=true only translates root,
// not arbitrary UIDs, and cannot be combined with raw.idmap.
func decideUIDMapping(hostUID, codeUID int, disableShift, hostHandlesUIDMapping, sourceBlocksShift bool) (useShift bool, idmap string) {
	// A source filesystem that can't be relied on for idmapped mounts is the
	// exact situation disable_shift exists for (#683), so fold it in first and
	// let the rest of the matrix apply unchanged. In particular this reaches the
	// #667 branch below, so a host/code UID match still gets raw.idmap rather
	// than nothing — the container's default subuid range doesn't cover hostUID
	// just because the nominal code UID matches it.
	if sourceBlocksShift {
		disableShift = true
	}
	if !disableShift && hostHandlesUIDMapping {
		disableShift = true
	}
	if hostUID != codeUID {
		return false, fmt.Sprintf("both %d %d", hostUID, codeUID)
	}
	if disableShift && !hostHandlesUIDMapping {
		// Shift is off but the guest doesn't already handle UID mapping itself
		// (manual disable_shift, e.g. #553's OrbStack case) — the container's
		// default unprivileged subuid range won't cover hostUID just because
		// the nominal code UID matches it, so raw.idmap is still required
		// (issue #667, a gap in #530's fix).
		return false, fmt.Sprintf("both %d %d", hostUID, codeUID)
	}
	return !disableShift, ""
}

// reuseShiftDecision folds a container's existing state into the fresh-launch
// shift decision when a persistent container is reused (issue #685).
//
// configuredShift is what ConfigureUIDMapping says the current config wants.
// hasRawIdmap is whether the container already carries raw.idmap. The two are
// mutually exclusive — shift=true only translates root, and Incus rejects the
// combination — so an existing raw.idmap always wins. That covers the container
// healed by the #678 fallback: its config still asks for shift, but the start
// failure that forced the conversion would repeat on every single session.
func reuseShiftDecision(configuredShift, hasRawIdmap bool) bool {
	return configuredShift && !hasRawIdmap
}

// SameWorkspaceSource reports whether two host paths refer to the same
// workspace directory. Symlinks are resolved when possible so a workspace
// reached via an aliased path (~/proj -> /data/proj) does not count as moved —
// a spurious remount would churn devices on every launch and, under
// preserve-path, flip the container-side path between spellings.
func SameWorkspaceSource(a, b string) bool {
	na, errA := filepath.EvalSymlinks(a)
	nb, errB := filepath.EvalSymlinks(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return na == nb
}

// WorkspaceRemounter is the slice of ContainerManager that
// RemountMovedWorkspace needs — narrowed so tests can fake it without
// implementing the whole manager surface.
type WorkspaceRemounter interface {
	container.ContainerDevices
	GetWorkspaceSource() string
}

// RemountMovedWorkspace reconciles a reused container whose persisted
// workspace device points at a different host source than the current
// workspace — the normal situation for a NAMED session ([container]
// session_name) launched from a new location, and for a workspace directory
// that moved on disk. The workspace and git-worktree-common devices are
// replaced, with the container-side path re-derived from the current
// workspace under the same preserve-path/worktree rules a fresh launch uses.
// Configured [[mount]] devices are location-independent and keep their
// persisted sources. Returns the container-side workspace path and whether a
// remount happened (cwp is "" when it didn't).
//
// Must run BEFORE the security mounts are re-applied (they derive protect
// overlays from the container-side workspace path) and AFTER the reuse shift
// decision (the new devices carry the current shift flag).
func RemountMovedWorkspace(mgr WorkspaceRemounter, workspacePath string, preservePath bool, layout *GitWorktreeLayout, useShift bool, logger func(string)) (string, bool, error) {
	if logger == nil {
		logger = func(string) {}
	}
	src := mgr.GetWorkspaceSource()
	if src == "" {
		// Can't tell (device missing or incus error) — fail open, but say so:
		// a silently skipped remount is indistinguishable from the same-source
		// no-op, and for a named session that means running against the wrong
		// checkout with no trace.
		logger("Warning: could not determine the reused container's workspace source; skipping the moved-workspace check")
		return "", false, nil
	}
	if SameWorkspaceSource(src, workspacePath) {
		return "", false, nil
	}
	logger(fmt.Sprintf("Workspace location changed since this session's container was created (%s -> %s); remounting", src, workspacePath))

	cwp := "/workspace"
	if preservePath || layout != nil {
		if WorkspaceUnderSystemDir(workspacePath) {
			if layout != nil {
				// Can't preserve the path, so the worktree's git pointers can't
				// resolve — fail closed, matching the fresh-launch rule.
				return "", false, fmt.Errorf("git worktree workspace %q is under a system directory; cannot preserve its host path to mount git internals safely", workspacePath)
			}
			logger(fmt.Sprintf("Warning: preserve_workspace_path requested for %q conflicts with system directories; using /workspace instead", workspacePath))
		} else {
			cwp = filepath.Clean(workspacePath)
		}
	}

	if err := mgr.RemoveDevice("workspace"); err != nil {
		return "", false, fmt.Errorf("failed to remove stale workspace device: %w", err)
	}
	// May not exist (non-worktree creation); a leftover from the old location
	// must not survive pointing at the old repo.
	_ = mgr.RemoveDevice("git-worktree-common")

	if err := mgr.MountDisk("workspace", workspacePath, cwp, useShift, false); err != nil {
		return "", false, fmt.Errorf("failed to remount workspace from %s: %w", workspacePath, err)
	}
	if layout != nil {
		if err := MountGitWorktreeDirs(mgr, layout, useShift); err != nil {
			return "", false, fmt.Errorf("failed to mount git worktree dirs: %w", err)
		}
		logger(fmt.Sprintf("Mounted git worktree common dir (read-write): %s", layout.CommonDir))
	}
	return cwp, true, nil
}

// mergeJSONSettings merges settings into existing JSON content with one-level deep merge.
// If both existing and new values for a key are maps, their entries are merged;
// otherwise the new value overwrites. Returns indented JSON with trailing newline.
// If existingContent is empty or invalid JSON, settings are used as the base and
// parseErr is set to the JSON parse error (callers should log a warning).
func mergeJSONSettings(existingContent []byte, settings map[string]interface{}) (result []byte, parseErr error, err error) {
	existing := make(map[string]interface{})

	// Parse existing content if non-empty
	trimmed := strings.TrimSpace(string(existingContent))
	if len(trimmed) > 0 {
		if unmarshalErr := json.Unmarshal([]byte(trimmed), &existing); unmarshalErr != nil {
			// Invalid JSON — start fresh with settings only, report to caller
			existing = make(map[string]interface{})
			parseErr = unmarshalErr
		}
	}

	// Normalize settings through JSON round-trip to convert typed maps
	// (e.g., map[string]string) to map[string]interface{} for consistent
	// type assertions during merge
	normalizedSettings := make(map[string]interface{})
	settingsBytes, marshalErr := json.Marshal(settings)
	if marshalErr != nil {
		return nil, parseErr, fmt.Errorf("failed to normalize settings: %w", marshalErr)
	}
	if unmarshalErr := json.Unmarshal(settingsBytes, &normalizedSettings); unmarshalErr != nil {
		return nil, parseErr, fmt.Errorf("failed to normalize settings: %w", unmarshalErr)
	}

	// One-level deep merge
	for k, v := range normalizedSettings {
		newMap, newIsMap := v.(map[string]interface{})
		existMap, existIsMap := existing[k].(map[string]interface{})

		if newIsMap && existIsMap {
			for mk, mv := range newMap {
				existMap[mk] = mv
			}
		} else {
			existing[k] = v
		}
	}

	out, marshalErr := json.MarshalIndent(existing, "", "  ")
	if marshalErr != nil {
		return nil, parseErr, fmt.Errorf("failed to marshal merged settings: %w", marshalErr)
	}

	return append(out, '\n'), parseErr, nil
}

// SetupMiseTrust configures MISE_TRUSTED_CONFIG_PATHS so mise automatically
// trusts config files (mise.toml, .tool-versions, etc.) in the workspace.
// The env var is written to both /etc/profile.d/ (login shells) and prepended
// to /etc/bash.bashrc (non-login interactive shells, sourced before ~/.bashrc
// where mise activates). Non-fatal: logs a warning on failure.
func SetupMiseTrust(mgr container.ContainerExecution, containerWorkspacePath string, logger func(string)) {
	exportLine := fmt.Sprintf(`export MISE_TRUSTED_CONFIG_PATHS="%s"`, containerWorkspacePath)
	trustCmd := fmt.Sprintf(
		`printf '%%s\n' '%s' > /etc/profile.d/coi-mise-trust.sh && `+
			`sed -i '/MISE_TRUSTED_CONFIG_PATHS/d' /etc/bash.bashrc && `+
			`sed -i '1i %s' /etc/bash.bashrc`,
		exportLine, exportLine,
	)
	if _, err := mgr.ExecCommand(trustCmd, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: Failed to configure mise workspace trust: %v", err))
	}
}

// GitIdentity is a concrete git author identity resolved outside the container.
type GitIdentity struct {
	Name  string
	Email string
}

// Complete reports whether both identity fields are present.
func (i GitIdentity) Complete() bool {
	return strings.TrimSpace(i.Name) != "" && strings.TrimSpace(i.Email) != ""
}

// SetupGitIdentityGuard configures git to require explicit user.name and
// user.email before allowing commits. This prevents AI tools from committing
// as the container's default "code" user. The setting is applied globally
// (--global) so it covers all repos inside the container.
// Non-fatal: logs a warning on failure.
func SetupGitIdentityGuard(mgr container.ContainerExecution, homeDir string, logger func(string)) {
	cmd := fmt.Sprintf(
		`HOME=%s git config --global user.useConfigOnly true`,
		shellEscape(homeDir),
	)
	if _, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: Failed to set git user.useConfigOnly: %v", err))
	}
}

// SetupGitIdentity writes a complete, pre-resolved identity into container git
// config. It intentionally does not guess inside the container; when the host
// side cannot provide both fields, user.useConfigOnly remains the fail-closed
// boundary and git will refuse commits rather than allowing model fabrication.
func SetupGitIdentity(mgr container.ContainerExecution, homeDir string, identity GitIdentity, logger func(string)) {
	if !identity.Complete() {
		return
	}
	cmd := fmt.Sprintf(
		`HOME=%s git config --global user.name %s && HOME=%s git config --global user.email %s`,
		shellEscape(homeDir),
		shellEscape(strings.TrimSpace(identity.Name)),
		shellEscape(homeDir),
		shellEscape(strings.TrimSpace(identity.Email)),
	)
	if _, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: Failed to configure git identity: %v", err))
		return
	}
	logger("Configured container git identity from host global git config")
}

// tmpfsSizer is the subset of container operations ApplyTmpfsSizing needs.
type tmpfsSizer interface {
	SetTmpfsSize(size string) error
}

// ApplyTmpfsSizing sizes /tmp for a freshly launched, RUNNING container when
// [limits.disk] tmpfs_size is set. It is the single source of truth for both
// the shell (session.Setup) and run (coi run) launch paths, so an explicit
// tmpfs_size from a profile applies uniformly regardless of how the container
// was started (#728/#769). No default is applied: coi does NOT convert /tmp to
// a RAM-backed tmpfs on its own — that would silently move /tmp off disk and
// onto RAM for every container. To bound /tmp without RAM cost, cap the whole
// rootfs with [limits.disk] size instead. Non-fatal: logs warnings.
func ApplyTmpfsSizing(mgr tmpfsSizer, limitsCfg *config.LimitsConfig, logger func(string)) {
	if limitsCfg == nil || limitsCfg.Disk.TmpfsSize == "" {
		return
	}
	size := limitsCfg.Disk.TmpfsSize
	if err := mgr.SetTmpfsSize(size); err != nil {
		logger(fmt.Sprintf("Warning: Failed to set /tmp size: %v", err))
	} else {
		logger(fmt.Sprintf("Set /tmp size to %s", size))
	}
}

// shouldSuppressClaudeAutoMode reports whether coi should write the Claude
// managed-settings policy that disables auto mode. It is Claude-specific and,
// per #764, deliberately skipped under interactive permission mode: managed
// settings are Claude Code's highest-precedence tier and cannot be overridden
// by any user/project setting, so writing the policy also strips auto mode from
// the in-session Shift+Tab cycle. Under interactive the user is present and
// owns that per-session choice; the sandbox boundary is enforced by the
// container, not by Claude's permission gate. Default (bypass) is unchanged.
func shouldSuppressClaudeAutoMode(toolName, permissionMode string) bool {
	return toolName == "claude" && permissionMode != "interactive"
}

// renderClaudeManagedSettings composes the managed-settings policy from the
// enabled parts: disableAutoMode (auto-mode prompt suppression, #764) and
// includeCoAuthoredBy=false (AI-attribution stripping at the source for
// Claude, [git] strip_attribution — this also covers the two cases the
// commit-msg hook cannot: repos with a local core.hooksPath and
// `git commit --no-verify`). Returns "" when neither applies.
func renderClaudeManagedSettings(suppressAutoMode, stripAttribution bool) string {
	parts := []string{}
	if suppressAutoMode {
		parts = append(parts, `"disableAutoMode": "disable"`)
	}
	if stripAttribution {
		parts = append(parts, `"includeCoAuthoredBy": false`)
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ", ") + "}\n"
}

// SetupClaudeManagedSettings writes /etc/claude-code/managed-settings.json
// inside the container — Claude Code's highest-precedence settings tier, which
// no user/project setting can override. Used for disableAutoMode (the only
// place it can be set) and includeCoAuthoredBy. A no-op when no policy part is
// enabled. Non-fatal: logs a warning on failure.
// Accepts ContainerManager (not a sub-interface) because it uses both
// ExecCommand (ContainerExecution) and CreateFileWithOwner (ContainerFiles).
func SetupClaudeManagedSettings(mgr container.ContainerManager, suppressAutoMode, stripAttribution bool, logger func(string)) {
	content := renderClaudeManagedSettings(suppressAutoMode, stripAttribution)
	if content == "" {
		return
	}
	mkdirCmd := "mkdir -p /etc/claude-code"
	if _, err := mgr.ExecCommand(mkdirCmd, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: Failed to create Claude managed settings directory: %v", err))
		return
	}
	// Root-owned and world-readable, applied atomically by the push: a plain
	// CreateFile inherits the host temp file's 0600 mode and UID, which the
	// container code user cannot read when the host UID differs (macOS 501,
	// CI 1001) — Claude Code then refuses OAuth on the unreadable policy file.
	// Root ownership also keeps the sandboxed agent from rewriting its own
	// managed policy.
	if err := mgr.CreateFileWithOwner("/etc/claude-code/managed-settings.json", content, 0, 0, "0644"); err != nil {
		logger(fmt.Sprintf("Warning: Failed to write Claude managed settings: %v", err))
	}
}
