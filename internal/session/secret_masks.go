package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// secretMask is an expanded secret path to mask, with whether it is a directory.
// relPath is the RESOLVED (symlink-free) workspace-relative path of the real
// file/dir to mask — never a symlink, so the bind-mount target cannot resolve
// through a link.
type secretMask struct {
	relPath string
	isDir   bool
}

// ExpandSecretPaths resolves the workspace-relative secret_paths globs to the
// concrete entries to mask. Supported patterns: exact paths (".env"),
// filepath.Glob patterns ("*.pem"), and a trailing "/**" ("secrets/**") which
// masks the base directory.
//
// Symlinks are RESOLVED (not skipped): a secret that is — or is reached through —
// a symlink is masked at its real, symlink-free target, so a repo cannot evade
// masking by making the secret a symlink to an in-workspace file. This also keeps
// the bind-mount target free of symlink components (a mount over a symlink would
// resolve through it). A path that does not exist, or whose target resolves
// OUTSIDE the workspace, is returned in `skipped` instead of being masked — its
// target is not reachable in the container's /workspace, so there is nothing to
// leak, but the caller MUST surface it so the protection never fails silently.
// Pure; safe to unit-test without a container.
func ExpandSecretPaths(workspacePath string, secretPaths []string) (masks []secretMask, skipped []string) {
	wsResolved, err := filepath.EvalSymlinks(workspacePath)
	if err != nil {
		wsResolved = filepath.Clean(workspacePath)
	}

	seen := make(map[string]bool)
	skippedSeen := make(map[string]bool)
	addSkip := func(s string) {
		if !skippedSeen[s] {
			skippedSeen[s] = true
			skipped = append(skipped, s)
		}
	}
	add := func(rel string) {
		rel = filepath.Clean(rel)
		if validateRelPath(rel) != nil {
			return
		}
		// Resolve all symlink components to the real target.
		resolved, err := filepath.EvalSymlinks(filepath.Join(workspacePath, rel))
		if err != nil {
			addSkip(rel) // broken or missing — cannot mask
			return
		}
		realRel, err := filepath.Rel(wsResolved, resolved)
		if err != nil || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) || validateRelPath(realRel) != nil {
			// Resolves outside the workspace — not reachable in the container's
			// /workspace (so no leak), but flag it so the caller can warn.
			addSkip(rel)
			return
		}
		realRel = filepath.Clean(realRel)
		if seen[realRel] {
			return
		}
		info, err := os.Stat(resolved)
		if err != nil {
			addSkip(rel)
			return
		}
		seen[realRel] = true
		masks = append(masks, secretMask{relPath: realRel, isDir: info.IsDir()})
	}

	for _, pat := range secretPaths {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if base, ok := strings.CutSuffix(pat, "/**"); ok {
			add(base) // mask the whole directory
			continue
		}
		matches, err := filepath.Glob(filepath.Join(workspacePath, filepath.FromSlash(pat)))
		if err != nil {
			continue // malformed pattern
		}
		for _, m := range matches {
			if rel, err := filepath.Rel(workspacePath, m); err == nil {
				add(rel)
			}
		}
	}
	return masks, skipped
}

// maskDeviceName derives a UNIQUE, valid Incus device name for a masked path.
// It hashes the (resolved) relPath rather than reusing pathToDeviceName, which is
// lossy (it strips '.' and maps '/'->'-', so e.g. ".env" and "env", or
// "secrets/db.conf" and "secrets/dbconf", would collapse to the same name and the
// second MountDisk would fail). The hash is collision-free and stable per path.
func maskDeviceName(relPath string) string {
	sum := sha256.Sum256([]byte(relPath))
	return maskDevicePrefix + hex.EncodeToString(sum[:])[:16]
}

// ensureMaskSources creates the empty file and empty directory used as read-only
// mask sources under ~/.coi/masks, returning their host paths. It is robust to a
// stale/corrupted masks dir: a leftover non-directory where the empty-dir is
// expected (or a directory where the empty-file is expected) is removed, and the
// empty-file is truncated so a stale non-empty file can never become the mask.
func ensureMaskSources() (emptyFile, emptyDir string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	maskRoot := filepath.Join(home, ".coi", "masks")

	emptyDir = filepath.Join(maskRoot, "empty-dir")
	if info, statErr := os.Lstat(emptyDir); statErr == nil && !info.IsDir() {
		_ = os.Remove(emptyDir)
	}
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		return "", "", err
	}

	emptyFile = filepath.Join(maskRoot, "empty-file")
	if info, statErr := os.Lstat(emptyFile); statErr == nil && info.IsDir() {
		_ = os.RemoveAll(emptyFile)
	}
	// O_TRUNC guarantees the file is empty even if a stale non-empty file exists.
	f, ferr := os.OpenFile(emptyFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if ferr != nil {
		return "", "", ferr
	}
	_ = f.Close()
	return emptyFile, emptyDir, nil
}

// SetupSecretMasks masks each resolved secret path by mounting an empty,
// read-only file/dir over it inside the container, so the contained agent can
// neither read its contents nor modify it. The host file is left untouched.
//
// Returns the relPaths actually masked, the secret_paths entries that could NOT
// be masked (missing, or a symlink resolving outside the workspace), and an error
// if ANY mask failed. It does NOT abort on the first failure — it keeps masking
// the rest so a single failure (e.g. a transient Incus error) cannot leave later
// secrets exposed — and the returned error lets the caller FAIL CLOSED rather
// than launch with an exposed secret. Issue #494.
//
// Limitation: masking is a read-only bind-mount overlay; like all such overlays,
// an in-container process with CAP_SYS_ADMIN (e.g. via sudo) could unmount it and
// read the real file underneath. It protects the agent's normal reads/writes, not
// a deliberate root-level unmount.
func SetupSecretMasks(mgr container.ContainerDevices, workspacePath, containerWorkspacePath string, secretPaths []string, useShift bool) (masked, skipped []string, err error) {
	masks, skipped := ExpandSecretPaths(workspacePath, secretPaths)
	if len(masks) == 0 {
		return nil, skipped, nil
	}
	emptyFile, emptyDir, err := ensureMaskSources()
	if err != nil {
		return nil, skipped, fmt.Errorf("failed to create secret mask sources: %w", err)
	}

	var errs []error
	for _, m := range masks {
		source := emptyFile
		if m.isDir {
			source = emptyDir
		}
		containerPath := filepath.Join(containerWorkspacePath, m.relPath)
		if e := mgr.MountDisk(maskDeviceName(m.relPath), source, containerPath, useShift, true); e != nil {
			errs = append(errs, fmt.Errorf("mask %s: %w", m.relPath, e))
			continue // keep masking the rest — never leave a later secret exposed
		}
		masked = append(masked, m.relPath)
	}
	if len(errs) > 0 {
		return masked, skipped, fmt.Errorf("failed to mask %d secret path(s): %w", len(errs), errors.Join(errs...))
	}
	return masked, skipped, nil
}
