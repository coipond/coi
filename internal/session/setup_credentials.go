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
// degrade to warnings so one bad file doesn't kill the session.
func seedHostFile(mgr container.ContainerManager, hostPath, destPath, homeDir, mode string, logger func(string)) error {
	if _, err := os.Stat(hostPath); err != nil {
		logger(fmt.Sprintf("  - Skipping %s (not found on host)", hostPath))
		return nil
	}

	destDir := filepath.Dir(destPath)
	if err := mgr.ExecArgs([]string{"mkdir", "-p", destDir}, container.ExecCommandOptions{}); err != nil {
		return fmt.Errorf("failed to create %s: %w", destDir, err)
	}

	logger(fmt.Sprintf("  - Copying %s -> %s", hostPath, destPath))
	if err := mgr.PushFile(hostPath, destPath); err != nil {
		logger(fmt.Sprintf("  - Warning: Failed to copy %s: %v", hostPath, err))
		return nil
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
	return nil
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
	return setupCredentials(mgr, homeDir, cc.Entries, logger)
}

func setupCredentials(mgr container.ContainerManager, homeDir string, entries []CredentialEntry, logger func(string)) error {
	for _, entry := range entries {
		dest := entry.ContainerPath
		if !filepath.IsAbs(dest) {
			dest = filepath.Join(homeDir, dest)
		}
		if err := seedHostFile(mgr, entry.HostPath, dest, homeDir, entry.Mode, logger); err != nil {
			return err
		}
	}
	return nil
}
