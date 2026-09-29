package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
)

var errGitDirIndirection = errors.New("workspace .git uses gitdir indirection")

// SetupSecurityMounts mounts protected paths as read-only for security.
// This prevents containers from modifying files that could execute automatically
// on the host (git hooks, IDE configs, etc.).
// containerWorkspacePath is the path where the workspace is mounted inside the container
// (either /workspace or the preserved host path).
//
// The dynamic per-worktree git configs (.git/worktrees/<name>/config.worktree)
// are expanded HERE — the single chokepoint every caller passes through — rather
// than at each call site. That is deliberate (issue #545): #542 was caused by one
// of two callers forgetting to expand, and centralizing it makes that class of gap
// structurally impossible for any future caller. sec carries the trusted-scope
// opt-outs (disable_protection / writable_paths) honored during expansion; it may
// be nil (expand unconditionally).
//
// Returns the effective (expanded) protected-path list, so the caller can drive
// its logging and host-immutable passes over the same set that was mounted, and an
// error if a mount failed. The list is returned even on error so a partial failure
// still applies the immutable attribute to the full set.
func SetupSecurityMounts(mgr container.ContainerDevices, workspacePath, containerWorkspacePath string, protectedPaths []string, useShift bool, sec *config.SecurityConfig) ([]string, error) {
	protectedPaths = ExpandGitWorktreeProtectedPaths(workspacePath, protectedPaths, sec)
	if len(protectedPaths) == 0 {
		return protectedPaths, nil
	}

	var warnings []string
	for _, relPath := range protectedPaths {
		if err := setupProtectedPath(mgr, workspacePath, containerWorkspacePath, relPath, useShift); err != nil {
			if errors.Is(err, errGitDirIndirection) {
				warnings = append(warnings, fmt.Sprintf("%s: %v", relPath, err))
				continue
			}
			// Paths that legitimately cannot be protected (non-git workspace,
			// a file-type default whose parent directory is missing, or a
			// user-added path that does not exist in the workspace) surface
			// as os.ErrNotExist and are skipped silently. Any other failure
			// (validation / stat / mount errors) is propagated and surfaces
			// as a warning at the caller in setup.go.
			if !errors.Is(err, os.ErrNotExist) {
				return protectedPaths, fmt.Errorf("failed to protect %s: %w", relPath, err)
			}
		}
	}

	if len(warnings) > 0 {
		return protectedPaths, errors.New(strings.Join(warnings, "; "))
	}

	return protectedPaths, nil
}

// securityDeviceStripper is the container API slice StripSecurityDevices needs.
type securityDeviceStripper interface {
	ListDevices() ([]string, error)
	RemoveDevice(name string) error
}

// Device-name prefixes for the security disk-device families whose host sources
// are (re)established by the fresh-launch security setup: workspace-relative
// protected paths (protect-), secret masks (mask-, sourced under ~/.coi/masks),
// and the read-only git worktree common-dir overlays (gitc-). Each generator
// (pathToDeviceName, maskDeviceName, commonDirDeviceName) builds its name from
// the matching constant here, and stripSecurityDevicePrefixes below lists the
// same constants — so the create side and the reuse-strip side share one source
// of truth and cannot diverge (a new family added without stripping it would
// leak across reuse, the #610 class; TestSecurityDeviceNamesAreStripped verifies
// the coupling for every generator). The read-WRITE base mounts these overlay
// (workspace, git-worktree-common) are deliberately NOT here.
const (
	protectDevicePrefix = "protect-"
	maskDevicePrefix    = "mask-"
	gitcDevicePrefix    = "gitc-"
)

// stripSecurityDevicePrefixes is the reuse-strip list; it MUST list exactly the
// prefixes above (each family created is a family stripped on reuse).
var stripSecurityDevicePrefixes = []string{protectDevicePrefix, maskDevicePrefix, gitcDevicePrefix}

// StripSecurityDevices removes the creation-time security device families (see
// stripSecurityDevicePrefixes) from a REUSED persistent container, so the caller
// can re-run the fresh-launch security setup as a clean re-add before restarting.
//
// This is the reuse-path analogue of RemoveStalePortDevices and the heart of the
// issue #610 fix: on a fresh launch SetupSecurityMounts / SetupSecretMasks /
// SetupCommonDirProtection materialize each source and attach the device, but on
// reuse those functions never ran, so a device attached at first launch keeps its
// original host source forever. If that source was removed from the workspace
// while the container was stopped, Incus rejects the container at start with
// `Missing source path`, and nothing self-heals it. Stripping here + re-running
// the SAME validated setup means all the materialization, symlink-rejection,
// type, and missing-path handling come from one place (the fresh-launch code)
// rather than being re-derived, and protection is re-established to match the
// CURRENT workspace (paths added, removed, or replaced since first launch).
//
// Best-effort: listing / per-device errors are logged, not fatal — a strip
// failure must not be worse than the stale-device wedge it prevents. Must run
// while the container is stopped, before start.
func StripSecurityDevices(mgr securityDeviceStripper, logger func(string)) {
	devices, err := mgr.ListDevices()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not list devices to reconcile protected paths: %v", err))
		return
	}
	for _, d := range devices {
		for _, prefix := range stripSecurityDevicePrefixes {
			if strings.HasPrefix(d, prefix) {
				if err := mgr.RemoveDevice(d); err != nil {
					logger(fmt.Sprintf("Warning: could not remove stale security device %s: %v", d, err))
				}
				break
			}
		}
	}
}

// applySessionSecurity establishes the full read-only security layer for a coi
// shell session: workspace-relative protected-path mounts (with the dynamic
// worktree-config expansion), the external git common-dir protection for a
// worktree checkout, the host-immutable belt, and secret-path masks. It is the
// single implementation shared by BOTH the fresh-launch path and the
// reuse/restart reconcile (issue #610), so both establish identical protection
// against the CURRENT workspace from one place.
//
// Returns the effective (expanded) protected-path list — which the caller adopts
// as canonical for downstream logging/context — and whether the host-immutable
// attribute was applied. The error is non-nil only for a FAIL-CLOSED secret-mask
// failure (a configured secret could not be masked); the caller must abort start
// rather than launch with the secret exposed. Read-only protected-mount failures
// are logged and non-fatal, matching prior behavior.
func applySessionSecurity(mgr container.ContainerManager, opts SetupOptions, containerWorkspacePath string, useShift bool, worktreeLayout *GitWorktreeLayout, worktreeWritableHooks bool, containerName string) (effectivePaths []string, hasImmutable bool, err error) {
	securityPaths := opts.Security.ProtectedPaths
	if worktreeLayout != nil {
		// Workspace .git is a file; its .git/* defaults can't be protected here
		// (they'd warn "gitdir indirection"). SetupCommonDirProtection covers the
		// real internals; keep the non-.git protections.
		securityPaths = StripGitProtectedPaths(securityPaths)
	}
	effectivePaths, mErr := SetupSecurityMounts(mgr, opts.WorkspacePath, containerWorkspacePath, securityPaths, useShift, opts.Security.Config)
	if mErr != nil {
		opts.Logger(fmt.Sprintf("Warning: Failed to setup security mounts: %v", mErr))
		// Non-fatal: continue even if a read-only protection mount fails.
	} else if len(effectivePaths) > 0 {
		if actual := GetProtectedPathsForLogging(opts.WorkspacePath, effectivePaths); len(actual) > 0 {
			opts.Logger(fmt.Sprintf("Protected paths (mounted read-only): %s", strings.Join(actual, ", ")))
		}
	}

	// Extend the read-only protection to the external git common dir (issue #533):
	// the same #474 hook/config lockdown applied to the worktree's real internals,
	// which the workspace-relative pass above cannot reach.
	if worktreeLayout != nil {
		cProtected, cErr := SetupCommonDirProtection(mgr, worktreeLayout.CommonDir, useShift, worktreeWritableHooks, opts.Security.Config)
		if cErr != nil {
			opts.Logger(fmt.Sprintf("Warning: some git common-dir protections not applied: %v", cErr))
		}
		if len(cProtected) > 0 {
			opts.Logger(fmt.Sprintf("Protected git common-dir paths (read-only): %s", strings.Join(cProtected, ", ")))
		}
	}

	// Host-side immutable attribute for defense-in-depth. Runs even on a partial
	// mount error, so it is gated on the effective list, not mErr.
	if len(effectivePaths) > 0 && opts.Security.HostImmutable {
		if immutablePaths := ApplyImmutable(opts.WorkspacePath, effectivePaths, containerName, opts.Logger); len(immutablePaths) > 0 {
			hasImmutable = true
			opts.Logger(fmt.Sprintf("Host-side immutable protection applied: %s", strings.Join(immutablePaths, ", ")))
		}
	}

	// Mask secret paths (issue #494) — independent of protected_paths. FAIL CLOSED:
	// if a configured secret cannot be masked we must not launch with it exposed.
	if len(opts.Security.SecretPaths) > 0 {
		masked, skipped, sErr := SetupSecretMasks(mgr, opts.WorkspacePath, containerWorkspacePath, opts.Security.SecretPaths, useShift)
		for _, s := range skipped {
			opts.Logger(fmt.Sprintf("Warning: secret_paths entry %q is NOT masked (missing, or a symlink resolving outside the workspace) — it is not hidden from the agent", s))
		}
		if sErr != nil {
			return effectivePaths, hasImmutable, fmt.Errorf("failed to mask secret paths: %w", sErr)
		}
		if len(masked) > 0 {
			opts.Logger(fmt.Sprintf("Masked secret paths (hidden read-only): %s", strings.Join(masked, ", ")))
		}
	}
	return effectivePaths, hasImmutable, nil
}

// setupProtectedPath mounts a single path as read-only
func setupProtectedPath(mgr container.ContainerDevices, workspacePath, containerWorkspacePath, relPath string, useShift bool) error {
	if err := validateRelPath(relPath); err != nil {
		return err
	}
	cleaned := filepath.Clean(relPath)

	hostPath := filepath.Join(workspacePath, cleaned)
	containerPath := filepath.Join(containerWorkspacePath, cleaned)

	// For .git paths, check if .git itself is valid FIRST (not a symlink or file)
	// This must happen before we try to create .git/hooks. When .git is a file
	// (worktree/submodule) the real internals live outside the workspace and are
	// mounted + protected separately via the git-worktree layout (issue #533);
	// surface the indirection here so a non-worktree caller does not silently lose
	// protection.
	if strings.HasPrefix(cleaned, ".git"+string(filepath.Separator)) || cleaned == ".git" {
		gitDir := filepath.Join(workspacePath, ".git")
		gitInfo, err := os.Lstat(gitDir)
		if err != nil {
			if os.IsNotExist(err) {
				return os.ErrNotExist // Not a git repo
			}
			return fmt.Errorf("failed to stat .git: %w", err)
		}
		if gitInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: .git is a symlink, so git commands may fail and git protected paths cannot be mounted from the workspace", errGitDirIndirection)
		}
		if !gitInfo.IsDir() {
			return fmt.Errorf("%w: .git is a file, so git commands may fail and git protected paths are not applied because git internals may live outside the mounted workspace", errGitDirIndirection)
		}
	}

	if err := ensureProtectedExists(workspacePath, hostPath, cleaned); err != nil {
		return err // os.ErrNotExist surfaces for unknown / user-added missing paths
	}

	// Use Lstat to avoid following symlinks (security measure)
	info, err := os.Lstat(hostPath)
	if err != nil {
		return fmt.Errorf("failed to stat %s after materialization: %w", cleaned, err)
	}

	// Security check: reject symlinks to prevent mounting arbitrary host paths
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to mount for security reasons", cleaned)
	}

	// Generate unique device name from path
	deviceName := pathToDeviceName(cleaned)

	// Mount as read-only
	return mgr.MountDisk(deviceName, hostPath, containerPath, useShift, true)
}

// validateRelPath rejects protected_paths entries that are empty,
// absolute, or attempt to traverse outside the workspace. Returning
// a non-os.ErrNotExist error causes the caller to surface a warning
// rather than silently skipping the entry.
func validateRelPath(relPath string) error {
	if relPath == "" {
		return fmt.Errorf("protected path is empty")
	}
	if filepath.IsAbs(relPath) {
		return fmt.Errorf("protected path %q must be relative to workspace", relPath)
	}
	cleaned := filepath.Clean(relPath)
	if cleaned == "." || cleaned == ".." {
		return fmt.Errorf("protected path %q resolves outside workspace", relPath)
	}
	// Reject any ".." segment anywhere in either the original or cleaned
	// form. filepath.Clean collapses inner traversals (e.g. "foo/../bar"
	// becomes "bar"), hiding the attacker's intent — check both.
	for _, seg := range strings.Split(relPath, "/") {
		if seg == ".." {
			return fmt.Errorf("protected path %q must not contain .. segments", relPath)
		}
	}
	for _, seg := range strings.Split(cleaned, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("protected path %q must not contain .. segments", relPath)
		}
	}
	return nil
}

// fileTypeProtectedPaths lists entries that are materialized as empty
// placeholder files (rather than directories) when missing. The parent
// directory must already exist — we never synthesize a parent tree.
// Extend this set in lockstep with internal/config/embedded/default_config.toml
// when adding new file-type defaults.
var fileTypeProtectedPaths = map[string]bool{
	".git/config": true,
	// .git/config.worktree and .git/info/attributes are additional git
	// config/attribute sinks that can drive host code execution via
	// filter/diff/textconv drivers or core.hooksPath when
	// extensions.worktreeConfig is enabled. They are protected read-only so a
	// container cannot plant a driver command (config.worktree) or name one
	// (info/attributes) that runs on the host at the next git operation.
	".git/config.worktree": true,
	".git/info/attributes": true,
	// Claude Code project settings carry a "hooks" key that the host auto-executes
	// when it opens the repo. They are materialized as empty read-only placeholders
	// so a contained agent cannot PLANT them when absent (the parent .claude dir is
	// auto-created — see fileTypeParentAutoCreate). Issue #504 / settings planting.
	".claude/settings.json":       true,
	".claude/settings.local.json": true,
	// Codex project-scoped config can name commands the host would run (e.g.
	// notify, MCP server launchers) when a host codex session trusts the repo.
	// Protected read-only for the same planting reason as the Claude settings.
	".codex/config.toml": true,
}

// fileTypeParentAutoCreate lists file-type protected entries whose parent
// directory should be created (writable, symlink-safe) when absent, so the
// read-only placeholder can be materialized even in a workspace that does not
// already contain that directory. The parent directory itself is NOT mounted
// read-only — only the listed file is. (.git/config is deliberately excluded: we
// must not synthesize a .git directory in a non-git workspace.) This closes the
// planting attack where a contained agent creates an absent .claude/settings.json
// carrying a hooks payload that a later host `claude` session auto-executes.
var fileTypeParentAutoCreate = map[string]bool{
	".claude/settings.json":       true,
	".claude/settings.local.json": true,
	".codex/config.toml":          true,
}

// directoryTypeProtectedPaths lists entries that are materialized as
// empty directories when missing. Only the built-in default paths that
// closed FLAWS Finding 2 are auto-created; user-added entries in
// additional_protected_paths must already exist on disk and are
// silently skipped otherwise (see ensureProtectedExists). This avoids
// guessing whether a user-added path like "Makefile" was intended as a
// file or a directory.
var directoryTypeProtectedPaths = map[string]bool{
	".git/hooks": true,
	".husky":     true,
	".vscode":    true,
}

func isFileTypeProtected(relPath string) bool {
	return fileTypeProtectedPaths[relPath]
}

func isDirTypeProtected(relPath string) bool {
	return directoryTypeProtectedPaths[relPath]
}

// ExpandGitWorktreeProtectedPaths returns paths plus a protected entry for each
// existing per-worktree git config file (.git/worktrees/<name>/config.worktree).
//
// When a repo has extensions.worktreeConfig=true, git reads those per-worktree
// config files, so they are config sinks that can carry filter/diff/textconv
// driver commands or core.hooksPath — i.e. host code execution at the next git
// operation. The static protected_paths list cannot glob, so this discovers the
// concrete files at setup time. Only files that already exist on disk are added
// (worktree config files are created by `git worktree`, never synthesized here);
// symlinks and directories are skipped.
//
// The same trusted-scope opt-outs that GetEffectiveProtectedPaths applies to the
// static list are honored for these dynamically discovered files: when sec is
// non-nil, nothing is expanded if disable_protection is set, and a file the user
// explicitly listed in writable_paths is not re-added (without this, the
// expansion would silently override an opt-out that the static-list subtraction
// had already applied). sec may be nil (expand unconditionally).
//
// Idempotent: a discovered path already present in paths is not re-added, so
// calling this more than once on the same list (or on an already-expanded list)
// never produces a duplicate — a duplicate would collide on the derived Incus
// device name and fail the second mount.
func ExpandGitWorktreeProtectedPaths(workspacePath string, paths []string, sec *config.SecurityConfig) []string {
	if sec != nil && sec.DisableProtection {
		return paths // protection disabled — do not resurrect worktree configs
	}
	wtRoot := filepath.Join(workspacePath, ".git", "worktrees")
	entries, err := os.ReadDir(wtRoot)
	if err != nil {
		return paths // no worktrees, or .git is a file/symlink — nothing to add
	}

	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[filepath.ToSlash(p)] = true
	}
	out := append([]string(nil), paths...)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rel := filepath.Join(".git", "worktrees", e.Name(), "config.worktree")
		if seen[filepath.ToSlash(rel)] {
			continue // already protected — keep expansion idempotent
		}
		if err := validateRelPath(rel); err != nil {
			continue
		}
		if sec != nil && sec.IsWritablePath(rel) {
			continue // user explicitly opted this path out of protection
		}
		info, err := os.Lstat(filepath.Join(workspacePath, rel))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
			continue
		}
		seen[filepath.ToSlash(rel)] = true
		out = append(out, rel)
	}
	return out
}

// ensureProtectedExists materializes hostPath so it has a real inode
// to read-only-mount over. Known default directory-type entries are
// created via a symlink-safe walk. The known file-type entry
// (.git/config) gets an empty placeholder, but only when its parent
// directory already exists. User-added paths that do not exist on
// disk return os.ErrNotExist and are silently skipped by the caller
// — the user is responsible for creating them beforehand.
func ensureProtectedExists(workspacePath, hostPath, relPath string) error {
	if _, err := os.Lstat(hostPath); err == nil {
		return nil // already exists, don't clobber
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat %s: %w", relPath, err)
	}

	switch {
	case isFileTypeProtected(relPath):
		if fileTypeParentAutoCreate[relPath] {
			// Create the parent directory (writable, symlink-safe) when absent so
			// the read-only placeholder can be materialized even in a workspace
			// that doesn't already have it — closing the planting attack on an
			// absent file. The parent dir itself is not mounted read-only.
			if err := safeMkdirAll(workspacePath, filepath.Dir(hostPath), filepath.Dir(relPath)); err != nil {
				return err
			}
		}
		return createProtectedFilePlaceholder(hostPath, relPath)
	case isDirTypeProtected(relPath):
		return safeMkdirAll(workspacePath, hostPath, relPath)
	default:
		// User-added path that does not exist. Do not guess whether
		// the user wanted a directory or a file — skip silently so
		// the caller's os.ErrNotExist filter swallows it.
		return os.ErrNotExist
	}
}

// createProtectedFilePlaceholder creates an empty file at hostPath,
// but only if its parent directory already exists and is not a
// symlink. It never synthesizes a parent tree.
func createProtectedFilePlaceholder(hostPath, relPath string) error {
	parent := filepath.Dir(hostPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return os.ErrNotExist
		}
		return fmt.Errorf("failed to stat parent of %s: %w", relPath, err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("parent of %s is a symlink; refusing to create placeholder", relPath)
	}
	if !parentInfo.IsDir() {
		return os.ErrNotExist
	}

	f, err := os.OpenFile(hostPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return nil // lost a harmless race
		}
		return fmt.Errorf("failed to create protected file placeholder %s: %w", relPath, err)
	}
	return f.Close()
}

// safeMkdirAll walks the components of relPath under workspacePath,
// creating each missing component with a plain os.Mkdir. Any existing
// parent component that is a symlink (or not a directory) is refused
// — this prevents a repo-controlled protected_paths entry from causing
// host directory creation outside the workspace via symlinked parents.
func safeMkdirAll(workspacePath, hostPath, relPath string) error {
	rel, err := filepath.Rel(workspacePath, hostPath)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for %s: %w", relPath, err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	current := workspacePath
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to create %s: parent component %s is a symlink", relPath, current)
			}
			if !info.IsDir() {
				return fmt.Errorf("refusing to create %s: parent component %s is not a directory", relPath, current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat %s: %w", current, err)
		}
		if err := os.Mkdir(current, 0o755); err != nil {
			return fmt.Errorf("failed to create protected directory %s: %w", relPath, err)
		}
	}
	return nil
}

// pathToDeviceName converts a path to a valid Incus device name
func pathToDeviceName(path string) string {
	// Replace path separators and dots with dashes
	name := strings.ReplaceAll(path, "/", "-")
	name = strings.ReplaceAll(name, ".", "")
	// Remove leading dash if present
	name = strings.TrimPrefix(name, "-")
	// Prefix for clarity + so the reuse-strip path (stripSecurityDevicePrefixes)
	// removes it.
	return protectDevicePrefix + name
}

// GetProtectedPathsForLogging returns a human-readable list of protected paths
// that actually exist in the workspace
func GetProtectedPathsForLogging(workspacePath string, protectedPaths []string) []string {
	var existing []string
	for _, relPath := range protectedPaths {
		hostPath := filepath.Join(workspacePath, relPath)
		if info, err := os.Lstat(hostPath); err == nil {
			// Skip symlinks in the list
			if info.Mode()&os.ModeSymlink == 0 {
				existing = append(existing, relPath)
			}
		} else if relPath == ".git/hooks" {
			// .git/hooks will be created, so include it if .git exists
			gitDir := filepath.Join(workspacePath, ".git")
			if gitInfo, err := os.Lstat(gitDir); err == nil && gitInfo.IsDir() {
				existing = append(existing, relPath)
			}
		}
	}
	return existing
}
