package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// ToolDataBaseDir returns the host directory holding per-workspace tool data
// for t: <coiDir>/tool-data/<tool>/<workspace-hash>. Keyed by workspace (not
// session name) so every session on a workspace sees the same tool history,
// as it did when the data lived in the workspace itself.
func ToolDataBaseDir(coiDir string, t tool.Tool, workspacePath string) string {
	return filepath.Join(coiDir, "tool-data", t.Name(), WorkspaceHash(workspacePath))
}

// ToolDataMounts returns the mounts backing t's data dirs (tool.ToolWithDataDirs)
// with per-workspace host dirs under coiDir, or nil when t has none. They are
// coi-generated, so always trusted, and writable.
//
// MigrateFrom points at where coi versions before #929 kept the same dir: in
// the workspace, via XDG_DATA_HOME/XDG_STATE_HOME=<workspace>/.local/... —
// PrepareMountSource moves that data over the first time the mount is added.
func ToolDataMounts(coiDir string, t tool.Tool, workspacePath string) []MountEntry {
	tdd, ok := t.(tool.ToolWithDataDirs)
	if !ok {
		return nil
	}
	base := ToolDataBaseDir(coiDir, t, workspacePath)
	home := "/home/" + container.CodeUser
	var mounts []MountEntry
	for _, d := range tdd.DataDirs() {
		mounts = append(mounts, MountEntry{
			HostPath:      filepath.Join(base, d.Name),
			ContainerPath: filepath.Join(home, d.HomeRelPath),
			DeviceName:    fmt.Sprintf("tool-data-%s-%s", t.Name(), d.Name),
			MigrateFrom:   filepath.Join(workspacePath, d.HomeRelPath),
		})
	}
	return mounts
}

// WithToolDataMounts returns mc with t's data mounts appended (mc itself is
// not modified). mc may be nil.
func WithToolDataMounts(mc *MountConfig, coiDir string, t tool.Tool, workspacePath string) *MountConfig {
	extra := ToolDataMounts(coiDir, t, workspacePath)
	if len(extra) == 0 {
		return mc
	}
	out := &MountConfig{}
	if mc != nil {
		out.Mounts = append(out.Mounts, mc.Mounts...)
	}
	out.Mounts = append(out.Mounts, extra...)
	return out
}

// PrepareMountSource creates a writable mount's host directory. When the mount
// has a MigrateFrom source and the host directory doesn't exist yet, the old
// directory is moved there first (one rename, so even a multi-GB opencode
// snapshot repo moves instantly), and the now-empty parents it leaves in the
// workspace are pruned. A failed move only warns: the session starts with an
// empty data dir and the old data stays where it was.
func PrepareMountSource(m MountEntry, logger func(string)) error {
	if m.MigrateFrom != "" {
		migrateMountSource(m.MigrateFrom, m.HostPath, logger)
	}
	if err := os.MkdirAll(m.HostPath, 0o755); err != nil {
		return fmt.Errorf("failed to create mount directory '%s': %w", m.HostPath, err)
	}
	return nil
}

func migrateMountSource(from, to string, logger func(string)) {
	if _, err := os.Lstat(to); err == nil || !errors.Is(err, os.ErrNotExist) {
		return // already set up (or unreadable — leave it alone)
	}
	info, err := os.Lstat(from)
	if err != nil || !info.IsDir() {
		return // nothing to migrate (a symlink is not followed)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		logger(fmt.Sprintf("Warning: could not move %s to %s: %v", from, to, err))
		return
	}
	if err := os.Rename(from, to); err != nil {
		logger(fmt.Sprintf("Warning: could not move %s to %s (%v); move it manually to keep its history", from, to, err))
		return
	}
	logger(fmt.Sprintf("Moved tool data out of the workspace: %s -> %s", from, to))
	// Prune the empty .local/share, .local/state, .local dirs the move left
	// behind; os.Remove refuses non-empty dirs, so anything else stays.
	for dir := filepath.Dir(from); ; dir = filepath.Dir(dir) {
		if filepath.Base(dir) == ".local" {
			_ = os.Remove(dir)
			return
		}
		if os.Remove(dir) != nil || dir == filepath.Dir(dir) {
			return
		}
	}
}

// AttachMissingToolDataMounts adds the tool data mounts in mc that a reused,
// STOPPED container doesn't have yet — one created before #929, or before its
// profile switched to the tool — and recreates the host dir of any that are
// attached but whose source has gone (Incus refuses to start a container with
// a missing disk source). [[mounts]] devices are otherwise never re-added on
// reuse; these are coi's own, so converging them is safe. mgr must be able to
// list its disk devices; when it can't, nothing is done.
func AttachMissingToolDataMounts(mgr container.ContainerDevices, mc *MountConfig, useShift bool, logger func(string)) error {
	if mc == nil {
		return nil
	}
	var wanted []MountEntry
	for _, m := range mc.Mounts {
		if m.MigrateFrom != "" {
			wanted = append(wanted, m)
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	lister, ok := mgr.(diskDeviceLister)
	if !ok {
		return nil
	}
	disks, err := lister.DiskDevices()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not read devices (%v); tool data mounts not reconciled", err))
		return nil
	}
	for _, m := range wanted {
		if err := PrepareMountSource(m, logger); err != nil {
			return err
		}
		if _, attached := disks[m.DeviceName]; attached {
			continue
		}
		logger(fmt.Sprintf("Adding mount: %s -> %s", m.HostPath, m.ContainerPath))
		if err := mgr.MountDisk(m.DeviceName, m.HostPath, m.ContainerPath, useShift, false); err != nil {
			return fmt.Errorf("failed to add mount '%s': %w", m.DeviceName, err)
		}
	}
	return nil
}
