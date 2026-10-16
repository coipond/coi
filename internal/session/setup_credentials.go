package session

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/container"
)

// seedHostFile copies a single host file into the container: a missing host
// file logs and skips (the user may not have signed into that provider yet),
// the destination directory is created, and the pushed file is chowned to
// the container's code user (unless running as root) with an optional chmod.
// This is the ONE file-seeding primitive shared by the generic
// [[credentials]] entries and the builtin tools' setupCLIConfig essential-
// file loop, so the two copy paths cannot drift. Directory-creation failure
// is returned (nothing can be pushed there); push/chown/chmod failures
// degrade to warnings so one bad file doesn't kill the session. copied is
// true when the file was pushed into the container.
func seedHostFile(mgr container.ContainerManager, hostPath, destPath, homeDir, mode string, logger func(string)) (copied bool, err error) {
	if _, err := os.Stat(hostPath); err != nil {
		logger(fmt.Sprintf("  - Skipping %s (not found on host)", hostPath))
		return false, nil
	}

	destDir := filepath.Dir(destPath)
	if err := mgr.ExecArgs([]string{"mkdir", "-p", destDir}, container.ExecCommandOptions{}); err != nil {
		return false, fmt.Errorf("failed to create %s: %w", destDir, err)
	}

	logger(fmt.Sprintf("  - Copying %s -> %s", hostPath, destPath))
	if err := mgr.PushFile(hostPath, destPath); err != nil {
		logger(fmt.Sprintf("  - Warning: Failed to copy %s: %v", hostPath, err))
		return false, nil
	}

	if homeDir != "/root" {
		if err := mgr.Chown(destPath, container.CodeUID, container.CodeUID); err != nil {
			logger(fmt.Sprintf("  - Warning: Failed to chown %s: %v", destPath, err))
		}
	}

	if mode != "" {
		if err := mgr.ExecArgs([]string{"chmod", mode, destPath}, container.ExecCommandOptions{}); err != nil {
			logger(fmt.Sprintf("  - Warning: Failed to chmod %s to %s: %v", destPath, mode, err))
		}
	}
	return true, nil
}

// SetupCredentials copies each configured credential entry (catalog bundle or
// ad-hoc) from host to container via seedHostFile. Tolerant of a missing host
// file (e.g. the user hasn't signed into the referenced provider yet), logs
// and skips rather than failing the whole session. Safe to call again on
// session resume: each entry is independently idempotent (re-push, re-chown,
// re-chmod).
// SetupCredentials applies a (possibly nil) CredentialConfig to a running
// container, seeding each [[credentials]] entry from host to container. Exported
// so the run pipeline can apply credentials the same way session.Setup does for
// the shell path (#726 follow-up). A nil/empty config is a no-op.
func SetupCredentials(mgr container.ContainerManager, homeDir string, cc *CredentialConfig, logger func(string)) error {
	if cc == nil || len(cc.Entries) == 0 {
		return nil
	}
	copied, err := setupCredentials(mgr, homeDir, cc.Entries, logger)
	// Record the copies (best-effort, like the shell path), so a later
	// `coi shell` reusing this container can vouch for them.
	if op, ok := recordCopiesOp(copyRecords(copyKindCredential, copied)); ok {
		_ = runGuestOps(mgr, []guestOp{op}, container.ExecCommandOptions{})
	}
	return err
}

// setupCredentials seeds each entry and returns the ones actually copied in
// (ContainerPath resolved to the absolute destination), even on error, so the
// grants report lists exactly what landed.
func setupCredentials(mgr container.ContainerManager, homeDir string, entries []CredentialEntry, logger func(string)) ([]CredentialEntry, error) {
	var copied []CredentialEntry
	for _, entry := range entries {
		dest := credentialDestPath(entry, homeDir)
		ok, err := seedHostFile(mgr, entry.HostPath, dest, homeDir, entry.Mode, logger)
		if err != nil {
			return copied, err
		}
		if ok {
			entry.ContainerPath = dest
			copied = append(copied, entry)
		}
	}
	return copied, nil
}

// credentialDestPath resolves an entry's destination: absolute as-is, else
// relative to the container home.
func credentialDestPath(entry CredentialEntry, homeDir string) string {
	if filepath.IsAbs(entry.ContainerPath) {
		return entry.ContainerPath
	}
	return filepath.Join(homeDir, entry.ContainerPath)
}
