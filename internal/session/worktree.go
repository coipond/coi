package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// systemDirPrefixes are the critical directories a workspace may not be mounted
// at its host path (preserve-path). Shared by the shell and run entrypoints and
// the worktree fail-closed check so they cannot drift.
var systemDirPrefixes = []string{
	"/etc", "/bin", "/sbin", "/usr", "/root", "/boot", "/sys", "/proc", "/dev", "/lib", "/lib64",
}

// WorkspaceUnderSystemDir reports whether the workspace path is at or under a
// critical system directory, where mounting it at its host path is disallowed.
func WorkspaceUnderSystemDir(absWorkspace string) bool {
	clean := filepath.Clean(absWorkspace)
	for _, prefix := range systemDirPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return true
		}
	}
	return false
}

// GitWorktreeLayout describes the external git directories referenced by a
// worktree checkout whose `.git` is a file (not a directory).
//
//   - GitDir is the worktree's own admin dir, e.g. <main>/.git/worktrees/<name>
//     (holds HEAD, index, and the per-worktree links). Mounted read-write.
//   - CommonDir is the shared/common git dir, e.g. <main>/.git (holds objects,
//     refs, config, hooks, ...). Mounted read-write; its RCE-sink subpaths
//     (hooks/config/info-attributes/worktrees-config) are re-covered read-only
//     by SetupCommonDirProtection so this does not reopen issue #474.
//
// Both are absolute, symlink-resolved host paths that live OUTSIDE the workspace.
type GitWorktreeLayout struct {
	GitDir    string
	CommonDir string
}

// ResolveGitWorktree inspects <workspacePath>/.git and, when it is a worktree
// pointer file referencing git internals outside the workspace, returns the
// external layout to mount (issue #533).
//
// Returns:
//   - (nil, nil)   — not applicable: `.git` is a real directory, is absent, or
//     resolves to a location inside the workspace. The caller proceeds normally.
//   - (layout, nil) — a valid linked worktree; mount + protect the layout.
//   - (nil, error)  — `.git` is a pointer file that FAILS the safety guard
//     (malformed, symlink, or not bound to this workspace). The caller must NOT
//     mount anything and should warn (git will fail loudly, as before #533's fix)
//     — it must never fall through to mounting an attacker-chosen path.
//
// Security: an untrusted repo's `.git` file could set `gitdir:` to an arbitrary
// host path (e.g. ~/.ssh) to trick coi into mounting it. That is closed here by
// binding the external dir to THIS workspace: the worktree's bidirectional back
// pointer (<gitdir>/gitdir) must resolve to <workspace>/.git, and the common dir
// must contain a real object store (objects/ + HEAD). An attacker cannot forge a
// back pointer inside a directory they do not control, so they cannot redirect
// the mount. This makes the resolution self-securing, so it is deliberately NOT
// additionally gated behind `coi trust` (which governs user-configured mounts, a
// separate concern).
func ResolveGitWorktree(workspacePath string) (*GitWorktreeLayout, error) {
	gitPath := filepath.Join(workspacePath, ".git")
	fi, err := os.Lstat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // not a repo — normal handling
		}
		return nil, fmt.Errorf("stat %s: %w", gitPath, err)
	}
	if fi.IsDir() {
		return nil, nil // ordinary repo — the workspace mount already covers .git
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// A symlinked .git can point anywhere; refuse rather than resolve it.
		return nil, fmt.Errorf("%s is a symlink; refusing to resolve worktree gitdir", gitPath)
	}

	// `.git` is a file: parse the "gitdir: <path>" pointer.
	gitDir, err := parseGitdirPointer(gitPath, workspacePath)
	if err != nil {
		return nil, err
	}
	gitDir, err = filepath.EvalSymlinks(gitDir)
	if err != nil {
		return nil, fmt.Errorf("resolve gitdir %q: %w", gitDir, err)
	}

	// The common dir is <gitdir>/commondir (a path RELATIVE to the gitdir), or
	// the gitdir itself when no commondir file exists.
	commonDir, err := resolveCommonDir(gitDir)
	if err != nil {
		return nil, err
	}

	// Safety guard — bind the external dirs to THIS workspace and prove they are
	// a real git dir before we agree to mount anything.
	if err := verifyWorktreeBinding(gitDir, commonDir, workspacePath); err != nil {
		return nil, err
	}

	// If the resolved dirs already live inside the workspace, the workspace mount
	// covers them — no external mount is needed (v1 handles the external case only).
	inside, err := pathInsideWorkspace(workspacePath, gitDir, commonDir)
	if err != nil {
		return nil, err
	}
	if inside {
		return nil, nil
	}

	return &GitWorktreeLayout{GitDir: gitDir, CommonDir: commonDir}, nil
}

// parseGitdirPointer reads a `.git` pointer file and returns the referenced
// gitdir as an absolute path (relative pointers are resolved against the
// workspace, matching git's own behavior).
func parseGitdirPointer(gitFilePath, workspacePath string) (string, error) {
	data, err := os.ReadFile(gitFilePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", gitFilePath, err)
	}
	var target string
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "gitdir:"); ok {
			target = strings.TrimSpace(rest)
			break
		}
	}
	if target == "" {
		return "", fmt.Errorf("%s is not a valid gitdir pointer (no 'gitdir:' line)", gitFilePath)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(workspacePath, target)
	}
	return filepath.Clean(target), nil
}

// resolveCommonDir reads <gitDir>/commondir (a path relative to gitDir) and
// returns the symlink-resolved common git dir. When no commondir file exists the
// gitdir is its own common dir.
func resolveCommonDir(gitDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		if os.IsNotExist(err) {
			return gitDir, nil
		}
		return "", fmt.Errorf("read commondir: %w", err)
	}
	rel := strings.TrimSpace(string(data))
	common := rel
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitDir, rel)
	}
	common, err = filepath.EvalSymlinks(filepath.Clean(common))
	if err != nil {
		return "", fmt.Errorf("resolve commondir %q: %w", common, err)
	}
	return common, nil
}

// verifyWorktreeBinding is the security guard: it proves the external dirs are a
// real git repository bound to THIS workspace before coi will mount them.
func verifyWorktreeBinding(gitDir, commonDir, workspacePath string) error {
	// Bidirectional link: <gitdir>/gitdir must point back at <workspace>/.git.
	// An attacker who plants a `.git` file pointing at ~/.ssh cannot also plant a
	// matching back pointer inside a directory they do not control.
	backData, err := os.ReadFile(filepath.Join(gitDir, "gitdir"))
	if err != nil {
		return fmt.Errorf("worktree gitdir %q has no back pointer (not a linked worktree): %w", gitDir, err)
	}
	back, err := filepath.EvalSymlinks(strings.TrimSpace(string(backData)))
	if err != nil {
		return fmt.Errorf("resolve worktree back pointer: %w", err)
	}
	wantGit, err := filepath.EvalSymlinks(filepath.Join(workspacePath, ".git"))
	if err != nil {
		return fmt.Errorf("resolve workspace .git: %w", err)
	}
	if back != wantGit {
		return fmt.Errorf("worktree back pointer %q does not bind to this workspace (%q); refusing to mount", back, wantGit)
	}

	// Structural: the common dir must be a real object store.
	if info, err := os.Stat(filepath.Join(commonDir, "objects")); err != nil || !info.IsDir() {
		return fmt.Errorf("common dir %q has no objects/ store; refusing to mount", commonDir)
	}
	if _, err := os.Stat(filepath.Join(commonDir, "HEAD")); err != nil {
		return fmt.Errorf("common dir %q has no HEAD; refusing to mount", commonDir)
	}
	return nil
}

// MountGitWorktreeDirs mounts the worktree's common git dir read-write at its
// identical host path (source==path) so every git pointer — the workspace `.git`
// file, the forward gitdir pointer, `commondir`, and the back pointer — resolves
// the same inside and outside the container. The worktree's own gitdir
// (<common>/worktrees/<name>) is a subdirectory of the common dir, so the single
// common-dir mount already covers it.
//
// Must run in the pre-start / workspace-mount phase, using the SAME useShift as the
// workspace mount, and BEFORE SetupCommonDirProtection layers the read-only overlays
// on top. Its RCE-sink subpaths are re-covered read-only there, so mounting the
// common dir read-write does not reopen issue #474 (objects/refs are data, not code).
func MountGitWorktreeDirs(mgr container.ContainerDevices, layout *GitWorktreeLayout, useShift bool) error {
	if err := mgr.MountDisk("git-worktree-common", layout.CommonDir, layout.CommonDir, useShift, false); err != nil {
		return fmt.Errorf("mount git common dir %q: %w", layout.CommonDir, err)
	}
	return nil
}

// commonDirSink is an RCE-sink path relative to the git common dir.
type commonDirSink struct {
	rel   string
	isDir bool
}

// SetupCommonDirProtection layers read-only mounts over the RCE-sink paths inside
// the external git common dir (issue #533) — the same protection #474 applies to a
// normal repo's `.git`, extended to the second root. Paths are relative to the common
// dir (no ".git/" prefix, because the common dir IS the git dir). Because the layout
// is mounted preserve-path, the container path equals the host path.
//
// The common dir is mounted read-write (so commits work), so an ABSENT sink would
// otherwise be plantable by a contained agent (a #474 regression). To match the
// workspace side — which synthesizes empty read-only placeholders for absent sinks —
// each sink is covered by mounting the real path read-only, first synthesizing an
// EMPTY, host-user-owned placeholder on the host when it is absent (like the workspace's
// ensureProtectedExists). The placeholder is created as the host user (correct ownership,
// readable/deletable) before the read-only mount blocks writes. config.worktree is
// covered for EVERY worktree admin dir, since the host may have
// extensions.worktreeConfig=true and the dir is read-write.
//
// writableHooks mirrors the workspace `git.writable_hooks` opt-out. Returns the list of
// protected relative paths (for logging) and an aggregated warning error.
func SetupCommonDirProtection(mgr container.ContainerDevices, commonDir string, useShift, writableHooks bool, sec *config.SecurityConfig) ([]string, error) {
	if sec != nil && sec.DisableProtection {
		return nil, nil
	}

	sinks := []commonDirSink{{"config", false}, {filepath.Join("info", "attributes"), false}}
	if !writableHooks {
		sinks = append([]commonDirSink{{"hooks", true}}, sinks...)
	}
	if entries, e := os.ReadDir(filepath.Join(commonDir, "worktrees")); e == nil {
		for _, en := range entries {
			if en.IsDir() {
				sinks = append(sinks, commonDirSink{filepath.Join("worktrees", en.Name(), "config.worktree"), false})
			}
		}
	}

	var protected, warnings []string
	for _, s := range sinks {
		if sec != nil && sec.IsWritablePath(s.rel) {
			continue
		}
		if err := protectCommonDirSink(mgr, commonDir, s, useShift); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", s.rel, err))
			continue
		}
		protected = append(protected, s.rel)
	}
	if len(warnings) > 0 {
		return protected, errors.New(strings.Join(warnings, "; "))
	}
	return protected, nil
}

// protectCommonDirSink read-only-mounts one common-dir sink at its (preserve-path)
// host==container path. When the sink is absent it is first synthesized as an empty,
// host-user-owned placeholder (symlink-safe, via the same primitives the workspace path
// uses) so the read-write common-dir mount cannot be used to create it. A symlinked or
// wrong-type sink is refused rather than mounted.
func protectCommonDirSink(mgr container.ContainerDevices, commonDir string, s commonDirSink, useShift bool) error {
	path := filepath.Join(commonDir, s.rel)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to mount for security reasons", s.rel)
		}
		if info.IsDir() != s.isDir {
			return fmt.Errorf("%s exists but is not the expected type", s.rel)
		}
	case os.IsNotExist(err):
		if s.isDir {
			if e := safeMkdirAll(commonDir, path, s.rel); e != nil {
				return e
			}
		} else {
			if e := safeMkdirAll(commonDir, filepath.Dir(path), filepath.Dir(s.rel)); e != nil {
				return e
			}
			if e := createProtectedFilePlaceholder(path, s.rel); e != nil {
				return e
			}
		}
	default:
		return fmt.Errorf("stat %s: %w", s.rel, err)
	}
	return mgr.MountDisk(commonDirDeviceName(s.rel), path, path, useShift, true)
}

// commonDirDeviceName derives a unique, valid Incus device name for a common-dir sink.
// Hashing (like maskDeviceName) is collision-free across arbitrary worktree names, which
// pathToDeviceName is not (it strips '.' and maps '/'→'-').
func commonDirDeviceName(rel string) string {
	sum := sha256.Sum256([]byte("gitcommon/" + rel))
	return gitcDevicePrefix + hex.EncodeToString(sum[:])[:16]
}

// StripGitProtectedPaths removes workspace-relative `.git` / `.git/*` entries from a
// protected-paths list. For a worktree checkout the workspace `.git` is a FILE, so
// those entries can't be protected there (they'd each trip the gitdir-indirection
// warning); the real internals are protected via SetupCommonDirProtection instead.
// Non-.git entries (.husky, .vscode, .coi, .claude/settings*) are kept.
func StripGitProtectedPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		cleaned := filepath.Clean(p)
		if cleaned == ".git" || strings.HasPrefix(cleaned, ".git"+string(filepath.Separator)) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// containsGitHooksPath reports whether the workspace protected set still includes
// `.git/hooks`. Its absence means git.writable_hooks (or an explicit writable_paths
// opt-out) removed it — the user chose writable hooks — which we mirror for the
// external common dir so a worktree honors the same choice.
func containsGitHooksPath(paths []string) bool {
	target := filepath.Join(".git", "hooks")
	for _, p := range paths {
		if filepath.Clean(p) == target {
			return true
		}
	}
	return false
}

// pathInsideWorkspace reports whether any of the given paths resolves to a
// location at or under the (symlink-resolved) workspace root.
func pathInsideWorkspace(workspacePath string, paths ...string) (bool, error) {
	root, err := filepath.EvalSymlinks(workspacePath)
	if err != nil {
		return false, fmt.Errorf("resolve workspace %q: %w", workspacePath, err)
	}
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true, nil
		}
	}
	return false, nil
}
