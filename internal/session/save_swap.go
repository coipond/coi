package session

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/tool"
)

// A save pulls into <dir>.coi-pull, renames it to <dir>.coi-new once it is
// complete, moves the previous copy aside to <dir>.coi-old, renames
// <dir>.coi-new to <dir> and only then removes <dir>.coi-old. A coi process
// killed at any step leaves a complete copy under one of these names, which
// finishSavedConfigSwap puts back in place.
const (
	pullingSuffix  = ".coi-pull"
	completeSuffix = ".coi-new"
	previousSuffix = ".coi-old"
)

// finishSavedConfigSwap completes an interrupted swap of the saved config dir
// liveDir: a complete new copy replaces liveDir, and a previous copy comes
// back when liveDir is missing and no new copy exists.
func finishSavedConfigSwap(liveDir string) error {
	newDir := liveDir + completeSuffix
	oldDir := liveDir + previousSuffix

	if pathExists(liveDir) && pathExists(oldDir) {
		if err := os.RemoveAll(oldDir); err != nil {
			return fmt.Errorf("failed to remove previous saved copy: %w", err)
		}
	}

	if pathExists(newDir) {
		if pathExists(liveDir) {
			if err := os.Rename(liveDir, oldDir); err != nil {
				return fmt.Errorf("failed to move previous saved copy aside: %w", err)
			}
		}
		if err := os.Rename(newDir, liveDir); err != nil {
			_ = os.Rename(oldDir, liveDir)
			return fmt.Errorf("failed to store new saved copy: %w", err)
		}
		// The new copy is in place; a leftover previous copy goes next time.
		_ = os.RemoveAll(oldDir)
		return nil
	}

	if !pathExists(liveDir) && pathExists(oldDir) {
		if err := os.Rename(oldDir, liveDir); err != nil {
			return fmt.Errorf("failed to restore previous saved copy: %w", err)
		}
	}
	return nil
}

// RecoverSavedSession puts back the tool's saved config dir of a session whose
// save was interrupted mid-swap, so a resume finds it.
func RecoverSavedSession(sessionsDir, sessionID string, t tool.Tool) error {
	if t == nil || t.ConfigDirName() == "" {
		return nil
	}
	return finishSavedConfigSwap(filepath.Join(sessionsDir, sessionID, t.ConfigDirName()))
}

// pathExists reports whether path exists, without following a final symlink
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
