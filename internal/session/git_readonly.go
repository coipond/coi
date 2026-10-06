package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// git.readonly locks the container commit identity so the agent cannot overwrite
// it. `git config --global` writes ~/.gitconfig via lock-file + rename, and the
// container home is writable, so file permissions alone don't stop it. Instead Coi
// generates a host-side gitconfig holding the identity and mounts it READ-ONLY at
// the container's ~/.gitconfig — a rename over a mount point fails, so the write is
// blocked at the filesystem layer.
//
// The read-only mount is only ONE of three layers (a config file loses to `-c`,
// `--author`, and env): the caller also pins GIT_AUTHOR_*/GIT_COMMITTER_* as
// container-level env (ApplyGitIdentityContainerEnv — beats `git -c user.*`) and
// installs a root-owned post-commit re-stamp hook (SetupGitHooks — catches
// `--author=` and agent-exported GIT_*). This file provides layer 1 and the
// core.hooksPath bake for layer 3.
//
// NB: this locks the WHOLE global gitconfig, not only user.name/email — any
// `git config --global …` in the container fails read-only. The agent uses
// per-repo (`--local`) config or env for anything else.
//
// This runs at the git-identity step of Setup, AFTER the container's real home is
// resolved (result.HomeDir — /home/<code> or /root when the image has no code
// user), so the mount always lands where git actually reads it.

const gitReadonlyDeviceName = "git-identity"

// gitReadonlyMounter is the slice of *container.Manager this needs: remove any
// stale device from a previous session (persistent reuse) then add the read-only
// disk. Narrow so the path is unit-testable with a stub.
type gitReadonlyMounter interface {
	RemoveDevice(name string) error
	MountDisk(name, source, path string, shift, readonly bool) error
}

// gitConfigQuote renders a git-config value as a quoted string, escaping the
// characters that are special inside git's double-quoted values (and newlines, so
// a stray control character can't produce a broken multi-line entry). Keeps names
// like "coipond-coder[bot]" intact ([ and ] are ordinary in a value).
func gitConfigQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// renderReadonlyGitConfig produces the full ~/.gitconfig content for a locked
// identity: the author fields plus user.useConfigOnly=true (the same fail-closed
// guard Coi would otherwise set live), so nothing else needs writing in-container.
// A non-empty hooksPath additionally bakes in core.hooksPath — the readonly mount
// blocks `git config --global`, so the attribution strip hook's config has to
// ride in the mounted file itself.
func renderReadonlyGitConfig(id GitIdentity, hooksPath string) string {
	cfg := fmt.Sprintf(
		"# Managed by coi (git.readonly): mounted read-only, do not edit.\n"+
			"[user]\n\tname = %s\n\temail = %s\n\tuseConfigOnly = true\n",
		gitConfigQuote(strings.TrimSpace(id.Name)),
		gitConfigQuote(strings.TrimSpace(id.Email)),
	)
	if hooksPath != "" {
		cfg += fmt.Sprintf("[core]\n\thooksPath = %s\n", gitConfigQuote(hooksPath))
	}
	return cfg
}

// readonlyGitConfigHostPath returns the host path Coi writes the generated config
// to. The name is a hash of the rendered CONTENT, so a given path only ever holds
// one content: distinct identities / hooksPaths (two parallel slots differing
// only in strip_attribution) get distinct files, and a file never needs
// rewriting once it exists. Lives under ~/.coi so it persists for the
// container's life (an Incus disk device references it) and is not swept from
// /tmp.
func readonlyGitConfigHostPath(hostHome string, id GitIdentity, hooksPath string) string {
	sum := sha256.Sum256([]byte(renderReadonlyGitConfig(id, hooksPath)))
	name := hex.EncodeToString(sum[:])[:16] + ".gitconfig"
	return filepath.Join(hostHome, ".coi", "git-identity", name)
}

// writeReadonlyGitConfigHostFile makes sure the generated config exists on the
// host and returns its path.
//
// The file is the source of an Incus disk device on EVERY container that uses
// this identity, running or stopped, so it must never be replaced: Incus binds
// the source when a container starts, and a rename landing in that window
// unlinks the inode being mounted, which aborts the start ("Failed to mount
// .../disk.git--identity...: No such file or directory"). With hundreds of
// containers on one identity, one launch's rewrite regularly overlapped another
// container's start. So an existing file with the right content is left alone
// (the content-addressed name makes that the steady state), and a missing one is
// installed with link(2), which never replaces an existing path.
func writeReadonlyGitConfigHostFile(id GitIdentity, hooksPath string) (string, error) {
	hostHome, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve host home: %w", err)
	}
	content := renderReadonlyGitConfig(id, hooksPath)
	hostPath := readonlyGitConfigHostPath(hostHome, id, hooksPath)
	if ok, err := readonlyGitConfigInstalled(hostPath, content); err != nil || ok {
		return hostPath, err
	}
	dir := filepath.Dir(hostPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create git.readonly dir: %w", err)
	}
	// Write to a temp file in the same dir first, so the installed file is never
	// torn: a crash mid-write leaves only the temp file behind.
	tmp, err := os.CreateTemp(dir, ".gitconfig-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create git.readonly temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // the installed file is a separate link (or a rename)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return "", fmt.Errorf("failed to write git.readonly config: %w", err)
	}
	// os.CreateTemp makes the file 0600; set 0644 explicitly so the container's code
	// user can read it regardless of uid shift.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return "", fmt.Errorf("failed to chmod git.readonly config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("failed to close git.readonly temp file: %w", err)
	}
	if err := installReadonlyGitConfig(tmpName, hostPath, content); err != nil {
		return "", err
	}
	return hostPath, nil
}

// readonlyGitConfigInstalled reports whether hostPath already holds content. A
// readable mode is restored in place (chmod keeps the inode, so containers
// mounting it are unaffected).
func readonlyGitConfigInstalled(hostPath, content string) (bool, error) {
	existing, err := os.ReadFile(hostPath)
	if err != nil || string(existing) != content {
		return false, nil
	}
	fi, err := os.Stat(hostPath)
	if err != nil {
		return false, nil
	}
	if fi.Mode().Perm() != 0o644 {
		if err := os.Chmod(hostPath, 0o644); err != nil {
			return false, fmt.Errorf("failed to chmod git.readonly config: %w", err)
		}
	}
	return true, nil
}

// installReadonlyGitConfig puts the finished temp file at hostPath without ever
// replacing a file a container may be mounting. link(2) fails when hostPath
// exists; that is a concurrent launch that installed the same content first
// (the name is content-addressed), which is success. Only a file with the WRONG
// content (left by a crash of an older Coi, so no container can be using it as
// intended) is replaced. Filesystems without hard links fall back to rename.
func installReadonlyGitConfig(tmpName, hostPath, content string) error {
	err := os.Link(tmpName, hostPath)
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrExist) {
		if ok, _ := readonlyGitConfigInstalled(hostPath, content); ok {
			return nil
		}
	}
	if err := os.Rename(tmpName, hostPath); err != nil {
		return fmt.Errorf("failed to install git.readonly config: %w", err)
	}
	return nil
}

// SetupGitIdentityReadonly locks the identity by mounting a generated gitconfig
// read-only at homeDir/.gitconfig. homeDir MUST be the container's resolved home
// (/home/<code> or /root). hooksPath, when non-empty, bakes core.hooksPath into
// the mounted config (the attribution strip hook — a live `git config --global`
// would fail against the read-only mount). The caller treats a returned error as
// fatal (fail closed): if the user asked to lock the identity and we cannot, the
// session must not proceed with a writable one.
func SetupGitIdentityReadonly(mgr gitReadonlyMounter, homeDir string, id GitIdentity, hooksPath string) error {
	hostPath, err := writeReadonlyGitConfigHostFile(id, hooksPath)
	if err != nil {
		return err
	}
	containerPath := filepath.Clean(homeDir + "/.gitconfig")
	// Remove any device left by a previous session (persistent reuse) before
	// re-adding; RemoveDevice is a no-op when absent.
	_ = mgr.RemoveDevice(gitReadonlyDeviceName)
	if err := mgr.MountDisk(gitReadonlyDeviceName, hostPath, containerPath, false, true); err != nil {
		return fmt.Errorf("failed to mount read-only git identity at %s: %w", containerPath, err)
	}
	return nil
}
