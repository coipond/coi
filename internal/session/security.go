package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

var errGitDirIndirection = errors.New("workspace .git uses gitdir indirection")

// errSymlinkedPath refuses a protected path that is, or lies below, a symlink.
var errSymlinkedPath = errors.New("refusing to mount through a symlink")

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
// The git dirs below the root (submodules, nested repositories) are expanded
// here too (expandNestedGit), from scan: a scan started early with
// StartNestedGitScan so the walk overlaps the caller's Incus calls, or the zero
// value to scan now. Their entries, whose number grows with the submodules,
// are mounted in one batch, with .git/commondir and the linked worktree
// entries (one per worktree). writableHooks ([git] writable_hooks) leaves their
// hooks dirs writable, as it does the root one.
//
// The dirs between the workspace root and each protected path are pinned
// (parentPinMounts), except at or below a sec.SecretPaths mask.
//
// Returns the effective (expanded) protected-path list, so the caller can drive
// its logging and host-immutable passes over the same set that was mounted, and an
// error if a mount failed. The list is returned even on error so a partial failure
// still applies the immutable attribute to the full set.
func SetupSecurityMounts(mgr container.ContainerDevices, workspacePath, containerWorkspacePath string, protectedPaths []string, useShift bool, sec *config.SecurityConfig, scan NestedGitScan, writableHooks bool) ([]string, error) {
	dirs := realDirs{}
	protectedPaths = expandGitWorktreeProtectedPaths(workspacePath, protectedPaths, sec, dirs)
	protectedPaths = expandNestedGit(workspacePath, protectedPaths, sec, scan, writableHooks, dirs)
	if len(protectedPaths) == 0 {
		return protectedPaths, nil
	}

	var warnings, prepared []string
	var batch []container.DiskMount
	for _, relPath := range protectedPaths {
		d, err := prepareProtectedPath(workspacePath, containerWorkspacePath, relPath, useShift, dirs)
		if err == nil {
			prepared = append(prepared, filepath.Clean(relPath))
			if isBatchedGitPath(relPath) {
				batch = append(batch, d)
				continue
			}
			err = mgr.MountDisk(d.Name, d.Source, d.Path, d.Shift, d.Readonly)
		}
		if err != nil {
			if errors.Is(err, errGitDirIndirection) || errors.Is(err, errSymlinkedPath) {
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
	var masked []string
	if sec != nil && len(sec.SecretPaths) > 0 {
		masks, _ := expandSecretPaths(workspacePath, sec.SecretPaths)
		for _, m := range masks {
			masked = append(masked, filepath.Clean(m.relPath))
		}
	}
	pins := parentPinMounts(workspacePath, containerWorkspacePath, prepared, masked, useShift)
	pinWarnings, err := mountNestedAndPins(mgr, batch, pins)
	if err != nil {
		return protectedPaths, fmt.Errorf("failed to protect nested git paths: %w", err)
	}
	warnings = append(warnings, pinWarnings...)

	if len(warnings) > 0 {
		return protectedPaths, errors.New(strings.Join(warnings, "; "))
	}

	return protectedPaths, nil
}

// diskBatchMounter is the optional Manager method that adds many disk devices
// in one Incus call.
type diskBatchMounter interface {
	MountDisks(mounts []container.DiskMount) error
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
	pinDevicePrefix     = "pin-"
)

// stripSecurityDevicePrefixes is the reuse-strip list; it MUST list exactly the
// prefixes above (each family created is a family stripped on reuse).
var stripSecurityDevicePrefixes = []string{protectDevicePrefix, maskDevicePrefix, gitcDevicePrefix, pinDevicePrefix}

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
func applySessionSecurity(mgr container.ContainerManager, opts SetupOptions, containerWorkspacePath string, useShift bool, worktreeLayout *GitWorktreeLayout, worktreeWritableHooks bool, containerName string, nestedScan NestedGitScan) (effectivePaths []string, hasImmutable bool, err error) {
	securityPaths := opts.Security.ProtectedPaths
	if worktreeLayout != nil {
		// Workspace .git is a file; its .git/* defaults can't be protected here
		// (they'd warn "gitdir indirection"). SetupCommonDirProtection covers the
		// real internals; keep the non-.git protections.
		securityPaths = StripGitProtectedPaths(securityPaths)
	}
	effectivePaths, mErr := SetupSecurityMounts(mgr, opts.WorkspacePath, containerWorkspacePath, securityPaths, useShift, opts.Security.Config, nestedScan, worktreeWritableHooks)
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
	var commonDir string
	var cProtected []string
	if worktreeLayout != nil {
		commonDir = worktreeLayout.CommonDir
		var cErr error
		cProtected, cErr = SetupCommonDirProtection(mgr, commonDir, useShift, worktreeWritableHooks, opts.Security.Config)
		if cErr != nil {
			opts.Logger(fmt.Sprintf("Warning: some git common-dir protections not applied: %v", cErr))
		}
		if len(cProtected) > 0 {
			opts.Logger(fmt.Sprintf("Protected git common-dir paths (read-only): %s", strings.Join(cProtected, ", ")))
		}
	}
	if found := UnexpectedCommonDirs(opts.WorkspacePath, effectivePaths, nestedScan, commonDir, cProtected); len(found) > 0 {
		opts.Logger(fmt.Sprintf("Warning: unexpected git commondir, kept as it is; check it: %s", strings.Join(found, ", ")))
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

// parentPinMounts returns read-write disk devices that mount each directory
// between root and a protected path over itself (pin-). A mount point cannot
// be renamed or removed in the container, so a parent of a read-only mount
// cannot be moved aside and recreated without it (mv .git .git.old; mkdir
// .git). rels are relative to root, which is mounted at containerRoot. A
// parent that is a protected path itself is already a mount point. The walk
// stops at a symlink, a non-directory and at or below a masked path (rel to
// root), which is a mount point over an empty read-only dir.
func parentPinMounts(root, containerRoot string, rels, masked []string, useShift bool) []container.DiskMount {
	protected := make(map[string]bool, len(rels))
	for _, rel := range rels {
		protected[rel] = true
	}
	realDir := map[string]bool{}
	var pins []container.DiskMount
	for _, rel := range rels {
		parts := strings.Split(rel, string(filepath.Separator))
		for i := 1; i < len(parts); i++ {
			parent := filepath.Join(parts[:i]...)
			ok, checked := realDir[parent]
			if !checked {
				ok = isRealDir(filepath.Join(root, parent)) && !underAny(parent, masked)
				realDir[parent] = ok
				if ok && !protected[parent] {
					containerPath := filepath.Join(containerRoot, parent)
					pins = append(pins, container.DiskMount{Name: pinDeviceName(containerPath), Source: filepath.Join(root, parent), Path: containerPath, Shift: useShift})
				}
			}
			if !ok {
				break
			}
		}
	}
	return pins
}

// underAny reports whether rel is one of paths or below one.
func underAny(rel string, paths []string) bool {
	for _, p := range paths {
		if rel == p || strings.HasPrefix(rel, p+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// pinDeviceName derives the device name of a parent pin from its container
// path, so pins of the workspace and of a git common dir cannot collide.
func pinDeviceName(containerPath string) string {
	sum := sha256.Sum256([]byte(containerPath))
	return pinDevicePrefix + hex.EncodeToString(sum[:])[:16]
}

// mountNestedAndPins mounts the nested git entries and then the parent pins.
// A pin can share its path with a device added elsewhere (a user mount), so
// a failed pin is a warning and never costs the nested git entries or the
// other pins. A batch is retried as separate PATCHes, which merge the devices
// map, so re-sending a device that an earlier chunk added is a no-op.
func mountNestedAndPins(mgr container.ContainerDevices, nested, pins []container.DiskMount) (pinWarnings []string, err error) {
	bm, ok := mgr.(diskBatchMounter)
	if !ok {
		for _, d := range nested {
			if err := mgr.MountDisk(d.Name, d.Source, d.Path, d.Shift, d.Readonly); err != nil {
				return nil, err
			}
		}
		for _, d := range pins {
			if err := mgr.MountDisk(d.Name, d.Source, d.Path, d.Shift, d.Readonly); err != nil {
				pinWarnings = append(pinWarnings, fmt.Sprintf("parent dir %s not pinned: %v", d.Path, err))
			}
		}
		return pinWarnings, nil
	}
	if len(nested)+len(pins) == 0 || bm.MountDisks(append(nested, pins...)) == nil {
		return nil, nil
	}
	if len(nested) > 0 {
		if err := bm.MountDisks(nested); err != nil {
			return nil, err
		}
	}
	for _, d := range pins {
		if err := bm.MountDisks([]container.DiskMount{d}); err != nil {
			pinWarnings = append(pinWarnings, fmt.Sprintf("parent dir %s not pinned: %v", d.Path, err))
		}
	}
	return pinWarnings, nil
}

// prepareProtectedPath validates and materializes one protected path and
// returns its read-only disk device, without mounting it. dirs caches the
// parent dirs checked in this setup; it may be nil.
func prepareProtectedPath(workspacePath, containerWorkspacePath, relPath string, useShift bool, dirs realDirs) (container.DiskMount, error) {
	var none container.DiskMount
	if err := validateRelPath(relPath); err != nil {
		return none, err
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
				return none, os.ErrNotExist // Not a git repo
			}
			return none, fmt.Errorf("failed to stat .git: %w", err)
		}
		if gitInfo.Mode()&os.ModeSymlink != 0 {
			return none, fmt.Errorf("%w: .git is a symlink, so git commands may fail and git protected paths cannot be mounted from the workspace", errGitDirIndirection)
		}
		if !gitInfo.IsDir() {
			return none, fmt.Errorf("%w: .git is a file, so git commands may fail and git protected paths are not applied because git internals may live outside the mounted workspace", errGitDirIndirection)
		}
	}

	if parent := dirs.symlinkedParent(workspacePath, cleaned); parent != "" {
		return none, fmt.Errorf("%w: parent dir %s of %s is a symlink", errSymlinkedPath, parent, cleaned)
	}

	if err := ensureProtectedExists(workspacePath, hostPath, cleaned); err != nil {
		return none, err // os.ErrNotExist surfaces for unknown / user-added missing paths
	}

	// Use Lstat to avoid following symlinks (security measure)
	info, err := os.Lstat(hostPath)
	if err != nil {
		return none, fmt.Errorf("failed to stat %s after materialization: %w", cleaned, err)
	}

	// Security check: reject symlinks to prevent mounting arbitrary host paths
	if info.Mode()&os.ModeSymlink != 0 {
		return none, fmt.Errorf("%w: %s is a symlink", errSymlinkedPath, cleaned)
	}

	return container.DiskMount{Name: pathToDeviceName(cleaned), Source: hostPath, Path: containerPath, Shift: useShift, Readonly: true}, nil
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
	// git reads $GIT_DIR/commondir in every git dir, not only in linked
	// worktrees, and then reads config and hooks from the dir it names. An
	// absent one is materialized as commonDirPlaceholder, not empty: git
	// refuses an empty commondir.
	".git/commondir": true,
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

// commonDirPlaceholder is the content of a materialized commondir: the git
// dir itself, as when the file is absent. libgit2 refuses "." without the
// trailing slash.
const commonDirPlaceholder = "./\n"

// ExpandGitWorktreeProtectedPaths returns paths plus a protected entry for each
// per-worktree git config file (.git/worktrees/<name>/config.worktree) and
// existing commondir (.git/worktrees/<name>/commondir).
//
// When a repo has extensions.worktreeConfig=true, git reads those per-worktree
// config files, so they are config sinks that can carry filter/diff/textconv
// driver commands or core.hooksPath — i.e. host code execution at the next git
// operation. The static protected_paths list cannot glob, so this discovers the
// concrete files at setup time. An absent config.worktree is created empty so
// it is protected too; a commondir is added only when it exists. Symlinks and
// directories are skipped. A worktree's commondir names the dir git reads its
// config and hooks from when run in that worktree.
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
	return expandGitWorktreeProtectedPaths(workspacePath, paths, sec, nil)
}

// expandGitWorktreeProtectedPaths is ExpandGitWorktreeProtectedPaths with dirs,
// the cache of the parent dirs checked in this setup; dirs may be nil.
func expandGitWorktreeProtectedPaths(workspacePath string, paths []string, sec *config.SecurityConfig, dirs realDirs) []string {
	if sec != nil && sec.DisableProtection {
		return paths // protection disabled — do not resurrect worktree configs
	}
	found := linkedWorktreeEntries(workspacePath, ".git", dirs)
	if len(found) == 0 {
		return paths // no worktrees, or .git is a file/symlink — nothing to add
	}

	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[filepath.ToSlash(p)] = true
	}
	out := append([]string(nil), paths...)
	for _, rel := range found {
		if seen[filepath.ToSlash(rel)] {
			continue // already protected — keep expansion idempotent
		}
		if sec != nil && sec.IsWritablePath(rel) {
			continue // user explicitly opted this path out of protection
		}
		seen[filepath.ToSlash(rel)] = true
		out = append(out, rel)
	}
	return out
}

// linkedWorktreeEntries returns the config.worktree and commondir files of the
// linked worktrees of the git dir at gitDirRel
// (<gitDirRel>/worktrees/<name>/...) that exist as regular files; symlinks,
// directories and a symlinked worktrees dir are skipped. An absent
// config.worktree is created as a placeholder so it cannot be planted;
// commondir never is, since a placeholder would point the worktree at its own
// admin dir.
func linkedWorktreeEntries(workspacePath, gitDirRel string, dirs realDirs) []string {
	wtRoot := filepath.Join(workspacePath, gitDirRel, "worktrees")
	if !isRealDir(wtRoot) {
		return nil
	}
	entries, err := os.ReadDir(wtRoot)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, name := range []string{"config.worktree", "commondir"} {
			rel := filepath.Join(gitDirRel, "worktrees", e.Name(), name)
			if validateRelPath(rel) != nil {
				continue
			}
			if name == "config.worktree" {
				if materializeNestedGitEntry(workspacePath, rel, false, dirs) {
					out = append(out, rel)
				}
				continue
			}
			if isRegularFile(filepath.Join(workspacePath, rel)) {
				out = append(out, rel)
			}
		}
	}
	return out
}

// nestedGitSearchDepth bounds how deep below the workspace root the walk for
// nested .git entries goes (a/b/c/.git is the deepest found).
const nestedGitSearchDepth = 3

// gitModulesSearchDepth bounds the walk below a modules/ dir. Submodule names
// may contain slashes, so one git dir can sit several levels down.
const gitModulesSearchDepth = 8

// nestedGitDirEntries are the per-git-dir entries protected for every git dir
// below the workspace root, mirroring the root .git defaults.
var nestedGitDirEntries = []string{"hooks", "config", "config.worktree", filepath.Join("info", "attributes"), "commondir"}

// nestedGitFound is what scanNestedGit found below the workspace root.
type nestedGitFound struct {
	gitDirs  []string // submodule git dirs and nested .git dirs
	gitFiles []string // .git files of submodule or worktree checkouts
}

// NestedGitScan is a nested git scan of one workspace, started early by
// StartNestedGitScan. The zero value, or a scan of another workspace, scans
// when the result is needed.
type NestedGitScan struct {
	workspacePath string
	result        func() nestedGitFound
}

// StartNestedGitScan starts the nested git scan of workspacePath in the
// background. A caller starts it before the container launch and passes it to
// SetupSecurityMounts, so a walk of a large tree overlaps the Incus calls
// instead of adding to the launch time.
func StartNestedGitScan(workspacePath string) NestedGitScan {
	ch := make(chan nestedGitFound, 1)
	go func() { ch <- scanNestedGit(workspacePath) }()
	return NestedGitScan{workspacePath: workspacePath, result: sync.OnceValue(func() nestedGitFound { return <-ch })}
}

// resultFor waits for the scan when it is of workspacePath, else scans now.
func (s NestedGitScan) resultFor(workspacePath string) nestedGitFound {
	if s.result == nil || s.workspacePath != workspacePath {
		return scanNestedGit(workspacePath)
	}
	return s.result()
}

// expandNestedGit returns paths plus protected entries for the git
// dirs below the workspace root: submodule git dirs (.git/modules/**, nested
// modules included) and nested repositories (<dir>/.git, up to
// nestedGitSearchDepth). For each such git dir its hooks, config,
// config.worktree, info/attributes and commondir are added, materialized like
// the root .git defaults so they cannot be planted, and so are its linked
// worktree entries (worktrees/<name>/config.worktree, materialized, and an
// existing commondir). A .git file
// (submodule or worktree checkout) is protected itself, so its gitdir pointer
// cannot be redirected.
//
// Host git reads these on a plain `git status` in the superproject (it recurses
// into submodules), so a writable submodule config is host code execution
// (core.fsmonitor), the same class the root .git defaults close. Discovery
// runs at setup: a git dir created during the session stays unprotected until
// the next launch.
//
// disable_protection, writable_paths, symlinks and idempotency are handled as
// in ExpandGitWorktreeProtectedPaths; writableHooks leaves the hooks entries out.
func expandNestedGit(workspacePath string, paths []string, sec *config.SecurityConfig, scan NestedGitScan, writableHooks bool, dirs realDirs) []string {
	if sec != nil && sec.DisableProtection {
		return paths
	}
	found := scan.resultFor(workspacePath)

	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[filepath.ToSlash(p)] = true
	}
	out := append([]string(nil), paths...)
	add := func(rel string) {
		if seen[filepath.ToSlash(rel)] || validateRelPath(rel) != nil {
			return
		}
		if sec != nil && sec.IsWritablePath(rel) {
			return
		}
		seen[filepath.ToSlash(rel)] = true
		out = append(out, rel)
	}
	for _, gitDir := range found.gitDirs {
		addGitDirEntries(workspacePath, gitDir, writableHooks, dirs, func(rel string, _ bool) { add(rel) })
	}
	for _, f := range found.gitFiles {
		add(f)
	}
	return out
}

// addGitDirEntries calls add for each protected entry of the git dir at
// gitDirRel below root: its nestedGitDirEntries (hooks unless writableHooks),
// materialized, and its linked worktree entries.
func addGitDirEntries(root, gitDirRel string, writableHooks bool, dirs realDirs, add func(rel string, isDir bool)) {
	for _, entry := range nestedGitDirEntries {
		if entry == "hooks" && writableHooks {
			continue
		}
		rel := filepath.Join(gitDirRel, entry)
		if materializeNestedGitEntry(root, rel, entry == "hooks", dirs) {
			add(rel, entry == "hooks")
		}
	}
	for _, rel := range linkedWorktreeEntries(root, gitDirRel, dirs) {
		add(rel, false)
	}
}

// scanNestedGit finds the git dirs and .git files below the workspace root.
// It only reads: materializing happens in expandNestedGit, after the
// disable_protection check. A submodule checkout's .git file is also found
// from its git dir's core.worktree, so a checkout below nestedGitSearchDepth
// is covered too.
func scanNestedGit(workspacePath string) nestedGitFound {
	var found nestedGitFound
	addGitDir := func(gitDirRel string) {
		found.gitDirs = append(found.gitDirs, gitDirRel)
		if f, ok := submoduleGitFile(workspacePath, gitDirRel); ok {
			found.gitFiles = append(found.gitFiles, f)
		}
	}
	addRepo := func(gitDirRel string) {
		addGitDir(gitDirRel)
		walkModuleGitDirs(workspacePath, gitDirRel, addGitDir)
	}
	addGitFile := func(rel string) { found.gitFiles = append(found.gitFiles, rel) }

	if isRealDir(filepath.Join(workspacePath, ".git")) {
		walkModuleGitDirs(workspacePath, ".git", addGitDir)
	}
	walkNestedGit(workspacePath, "", 0, addGitFile, addRepo)
	return found
}

// walkModuleGitDirs calls addGitDir for each submodule git dir below the git
// dir at gitDirRel: <gitDirRel>/modules/** and each linked worktree's
// <gitDirRel>/worktrees/<name>/modules/**, nested modules included.
func walkModuleGitDirs(root, gitDirRel string, addGitDir func(string)) {
	visit := func(rel string) {
		addGitDir(rel)
		walkModuleGitDirs(root, rel, addGitDir)
	}
	walkGitModules(root, filepath.Join(gitDirRel, "modules"), 1, visit)
	wtRoot := filepath.Join(root, gitDirRel, "worktrees")
	if !isRealDir(wtRoot) {
		return
	}
	entries, err := os.ReadDir(wtRoot)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			walkGitModules(root, filepath.Join(gitDirRel, "worktrees", e.Name(), "modules"), 1, visit)
		}
	}
}

// submoduleGitFile returns the .git file of the checkout named by the
// core.worktree of the git dir at gitDirRel, when that file is inside the
// workspace and reached without symlinks.
func submoduleGitFile(workspacePath, gitDirRel string) (string, bool) {
	gitDir := filepath.Join(workspacePath, gitDirRel)
	worktree := gitConfigCoreWorktree(filepath.Join(gitDir, "config"))
	if worktree == "" {
		return "", false
	}
	if !filepath.IsAbs(worktree) {
		worktree = filepath.Join(gitDir, worktree)
	}
	rel, err := filepath.Rel(workspacePath, filepath.Join(worktree, ".git"))
	if err != nil || validateRelPath(rel) != nil || !strings.HasSuffix(rel, string(filepath.Separator)+".git") {
		return "", false
	}
	current := workspacePath
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return "", false
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", false // missing, a file or a symlink on the way
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() {
			return "", false
		}
	}
	return rel, true
}

// gitConfigCoreWorktree reads core.worktree from a git config file; "" when
// absent or unreadable.
func gitConfigCoreWorktree(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	inCore := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inCore = strings.EqualFold(strings.Trim(line, "[] \t"), "core")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if inCore && ok && strings.EqualFold(strings.TrimSpace(key), "worktree") {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

// walkGitModules calls addGitDir for each git dir (a dir with a HEAD file)
// below modulesRel. A dir without HEAD is a segment of a slashed submodule
// name and is descended into.
func walkGitModules(workspacePath, modulesRel string, depth int, addGitDir func(string)) {
	dir := filepath.Join(workspacePath, modulesRel)
	if depth > gitModulesSearchDepth || !isRealDir(dir) {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rel := filepath.Join(modulesRel, e.Name())
		if info, err := os.Lstat(filepath.Join(workspacePath, rel, "HEAD")); err == nil && info.Mode().IsRegular() {
			addGitDir(rel)
			continue
		}
		walkGitModules(workspacePath, rel, depth+1, addGitDir)
	}
}

// walkNestedGit finds <dir>/.git below the workspace root (the root .git is
// covered by the static defaults). A .git dir is a nested repository; a .git
// file is a submodule or worktree checkout whose gitdir lives elsewhere.
func walkNestedGit(workspacePath, dirRel string, depth int, addGitFile, addGitDir func(string)) {
	entries, err := os.ReadDir(filepath.Join(workspacePath, dirRel))
	if err != nil {
		return
	}
	for _, e := range entries {
		rel := filepath.Join(dirRel, e.Name())
		if e.Name() == ".git" {
			if depth == 0 {
				continue
			}
			switch {
			case e.Type().IsRegular():
				addGitFile(rel)
			case e.IsDir():
				addGitDir(rel)
			}
			continue
		}
		if e.IsDir() && depth < nestedGitSearchDepth {
			walkNestedGit(workspacePath, rel, depth+1, addGitFile, addGitDir)
		}
	}
}

// materializeNestedGitEntry makes sure rel exists as a real (non-symlink)
// directory or file, creating a missing one inside an existing parent, and
// reports whether it can be protected. Nothing is created or reported below a
// symlinked parent dir.
func materializeNestedGitEntry(workspacePath, rel string, isDir bool, dirs realDirs) bool {
	if dirs.symlinkedParent(workspacePath, rel) != "" {
		return false
	}
	hostPath := filepath.Join(workspacePath, rel)
	if _, err := os.Lstat(hostPath); os.IsNotExist(err) {
		if isDir {
			if !isRealDir(filepath.Dir(hostPath)) || os.Mkdir(hostPath, 0o755) != nil {
				return false
			}
		} else if createProtectedFilePlaceholder(hostPath, rel) != nil {
			return false
		}
	}
	info, err := os.Lstat(hostPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return info.IsDir() == isDir
}

// UnexpectedCommonDirs returns "<file> -> <dir>" for each protected commondir
// of a git dir that names another dir: the root .git and the git dirs below it
// (effective, relative to workspacePath, as SetupSecurityMounts returns it),
// and the common dir of a worktree checkout and its submodule git dirs
// (commonProtected, as SetupCommonDirProtection returns it). git writes a
// commondir only in a linked worktree's admin dir, and coi keeps an existing
// file as it is.
func UnexpectedCommonDirs(workspacePath string, effective []string, scan NestedGitScan, commonDir string, commonProtected []string) []string {
	out := foreignCommonDirs(workspacePath, "", ".git", effective, func() []string {
		return scan.resultFor(workspacePath).gitDirs
	})
	if commonDir != "" {
		out = append(out, foreignCommonDirs(commonDir, commonDir, ".", commonProtected, func() []string {
			var gitDirs []string
			walkModuleGitDirs(commonDir, ".", func(d string) { gitDirs = append(gitDirs, d) })
			return gitDirs
		})...)
	}
	return out
}

// foreignCommonDirs returns "<file> -> <dir>" for each commondir in protected
// (relative to root) of rootGitDir or of a git dir listed by gitDirs, named
// relative to label. A commondir in a linked worktree's admin dir is skipped.
func foreignCommonDirs(root, label, rootGitDir string, protected []string, gitDirs func() []string) []string {
	var out []string
	var known map[string]bool
	for _, rel := range protected {
		if filepath.Base(rel) != "commondir" {
			continue
		}
		gitDir := filepath.Dir(rel)
		if gitDir != rootGitDir {
			if known == nil {
				known = map[string]bool{}
				for _, d := range gitDirs() {
					known[filepath.Clean(d)] = true
				}
			}
			if !known[gitDir] {
				continue // a linked worktree's admin dir
			}
		}
		if target, ok := foreignCommonDir(filepath.Join(root, gitDir)); ok {
			out = append(out, fmt.Sprintf("%s -> %s", filepath.Join(label, rel), target))
		}
	}
	return out
}

// foreignCommonDir returns the dir named by gitDir's commondir when the file
// exists and names a dir other than gitDir. A target that does not resolve is
// returned as written.
func foreignCommonDir(gitDir string) (string, bool) {
	target, ok, err := commonDirTarget(gitDir)
	if err != nil || !ok {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return target, true
	}
	if SameDir(resolved, gitDir) {
		return "", false
	}
	return resolved, true
}

// realDirs holds the dirs below the workspace root, relative to it, that one
// protected-path setup found to be real dirs, so each is checked once per
// launch. A nil realDirs checks every time.
type realDirs map[string]bool

// symlinkedParent returns the first parent dir of rel below workspacePath that
// is a symlink, relative to workspacePath; "" when there is none. The check
// ends at the first missing part.
func (d realDirs) symlinkedParent(workspacePath, rel string) string {
	var unchecked []string
	for dir := filepath.Dir(filepath.Clean(rel)); dir != "." && !d[dir]; dir = filepath.Dir(dir) {
		unchecked = append(unchecked, dir)
	}
	for i := len(unchecked) - 1; i >= 0; i-- {
		info, err := os.Lstat(filepath.Join(workspacePath, unchecked[i]))
		if err != nil || !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return ""
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return unchecked[i]
		}
		if d != nil {
			d[unchecked[i]] = true
		}
	}
	return ""
}

func isRealDir(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}

func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// isBatchedGitPath reports whether rel is mounted in the batch: a nested git
// path, a linked worktree entry (one per worktree) or .git/commondir.
func isBatchedGitPath(rel string) bool {
	return isNestedGitPath(rel) || isWorktreeGitPath(rel) || filepath.ToSlash(rel) == ".git/commondir"
}

// isWorktreeGitPath reports whether rel lies in a linked worktree's admin dir
// (.git/worktrees/<name>/...), whose name is repo-controlled.
func isWorktreeGitPath(rel string) bool {
	return strings.HasPrefix(filepath.ToSlash(rel), ".git/worktrees/")
}

// isNestedGitPath reports whether rel lies in or is a git dir below the
// workspace root: .git/modules/... or any later .git segment.
func isNestedGitPath(rel string) bool {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, part := range parts {
		if part == ".git" && i > 0 {
			return true
		}
	}
	return len(parts) > 1 && parts[0] == ".git" && parts[1] == "modules"
}

// ensureProtectedExists materializes hostPath so it has a real inode
// to read-only-mount over. Known default directory-type entries are
// created via a symlink-safe walk. Known file-type entries get a
// placeholder (createProtectedFilePlaceholder), but only when their
// parent directory already exists or is in fileTypeParentAutoCreate.
// User-added paths that do not exist on disk return os.ErrNotExist
// and are silently skipped by the caller — the user is responsible
// for creating them beforehand.
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

// createProtectedFilePlaceholder creates an empty file at hostPath (a
// commondir gets commonDirPlaceholder), but only if its parent directory
// already exists and is not a symlink. It never synthesizes a parent tree.
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
	if filepath.Base(relPath) == "commondir" {
		if _, err := f.WriteString(commonDirPlaceholder); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to write protected file placeholder %s: %w", relPath, err)
		}
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

// deviceNameRe matches the device names every supported Incus version
// accepts: at most 63 characters (6.x), starting and ending with a letter or
// digit (7.0+), only [A-Za-z0-9._-] (7.6+).
var deviceNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)

// pathToDeviceName converts a path to a valid Incus device name
func pathToDeviceName(path string) string {
	// Replace path separators and dots with dashes
	name := strings.ReplaceAll(path, "/", "-")
	name = strings.ReplaceAll(name, ".", "")
	// Remove leading dash if present
	name = strings.TrimPrefix(name, "-")
	// Prefix for clarity + so the reuse-strip path (stripSecurityDevicePrefixes)
	// removes it.
	name = protectDevicePrefix + name
	// Nested git and linked worktree paths come from repo-controlled names:
	// hash them so they cannot collide with each other or exceed the device
	// name limit. Hash names Incus rejects too; valid names stay unchanged for
	// existing containers.
	if isNestedGitPath(path) || isWorktreeGitPath(path) || !deviceNameRe.MatchString(name) {
		sum := sha256.Sum256([]byte(path))
		return protectDevicePrefix + hex.EncodeToString(sum[:])[:16]
	}
	return name
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
