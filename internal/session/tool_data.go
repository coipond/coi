package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// toolDataDevicePrefix starts the Incus device name of every tool data mount.
const toolDataDevicePrefix = "tool-data-"

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
// For a dir marked FromWorkspace, MigrateFrom points at where coi versions
// before #929 kept it: in the workspace, via
// XDG_DATA_HOME/XDG_STATE_HOME=<workspace>/.local/... — PrepareMountSource
// moves that data over the first time the mount is added.
func ToolDataMounts(coiDir string, t tool.Tool, workspacePath string) []MountEntry {
	tdd, ok := t.(tool.ToolWithDataDirs)
	if !ok {
		return nil
	}
	base := ToolDataBaseDir(coiDir, t, workspacePath)
	home := "/home/" + container.CodeUser
	var mounts []MountEntry
	for _, d := range tdd.DataDirs() {
		m := MountEntry{
			HostPath:      filepath.Join(base, d.Name),
			ContainerPath: filepath.Join(home, d.HomeRelPath),
			DeviceName:    fmt.Sprintf("%s%s-%s", toolDataDevicePrefix, t.Name(), d.Name),
		}
		if d.FromWorkspace {
			m.MigrateFrom = filepath.Join(workspacePath, d.HomeRelPath)
		}
		mounts = append(mounts, m)
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
// a missing disk source). Another tool's data mount on the same container path
// (opencode and opencode2 both use ~/.local/share/opencode) is removed first:
// two disk devices can't share a path, so a tool switch would otherwise leave
// the container unable to start. Its data stays in that tool's host dir.
// A new mount without MigrateFrom covers a dir that older coi left in the
// container (opencode2's plan dir in coi 0.16), so what the container holds
// there is copied to the host dir first; the mount would hide it otherwise.
// [[mounts]] devices are otherwise never re-added on reuse; these are coi's
// own, so converging them is safe. mgr must be able to list its disk devices;
// when it can't, nothing is done.
func AttachMissingToolDataMounts(mgr container.ContainerDevices, mc *MountConfig, useShift bool, logger func(string)) error {
	if mc == nil {
		return nil
	}
	var wanted []MountEntry
	for _, m := range mc.Mounts {
		if strings.HasPrefix(m.DeviceName, toolDataDevicePrefix) {
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
	wantedNames := map[string]bool{}
	wantedPaths := map[string]bool{}
	for _, m := range wanted {
		wantedNames[m.DeviceName] = true
		wantedPaths[m.ContainerPath] = true
	}
	for name, d := range disks {
		if !strings.HasPrefix(name, toolDataDevicePrefix) || wantedNames[name] || !wantedPaths[d.Path] {
			continue
		}
		logger(fmt.Sprintf("Removing mount %s (%s): another tool's data dir on the same path", name, d.Path))
		if err := mgr.RemoveDevice(name); err != nil {
			return fmt.Errorf("failed to remove mount '%s': %w", name, err)
		}
	}
	for _, m := range wanted {
		_, attached := disks[m.DeviceName]
		if !attached && m.MigrateFrom == "" {
			copyContainerDataDir(mgr, m, logger)
		}
		if err := PrepareMountSource(m, logger); err != nil {
			return err
		}
		if attached {
			continue
		}
		logger(fmt.Sprintf("Adding mount: %s -> %s", m.HostPath, m.ContainerPath))
		if err := mgr.MountDisk(m.DeviceName, m.HostPath, m.ContainerPath, useShift, false); err != nil {
			return fmt.Errorf("failed to add mount '%s': %w", m.DeviceName, err)
		}
	}
	return nil
}

// containerDirPuller reads a stopped container's files (the files API, no
// exec).
type containerDirPuller interface {
	PathKind(p string) (container.PathKind, error)
	PullDirectory(containerPath, localPath string) error
}

// copyContainerDataDir copies m's container dir into its host dir. The host
// dir is shared by every container on the workspace (one per slot), so it may
// already hold data: only entries it lacks are moved in, and the rest are
// skipped, never overwritten. A failed copy only warns: the data stays in the
// container, hidden by the mount.
func copyContainerDataDir(mgr container.ContainerDevices, m MountEntry, logger func(string)) {
	puller, ok := mgr.(containerDirPuller)
	if !ok {
		return
	}
	kind, err := puller.PathKind(m.ContainerPath)
	if err != nil {
		logger(fmt.Sprintf("Warning: could not check %s in the container (%v); its data is hidden by the new mount", m.ContainerPath, err))
		return
	}
	if kind != container.PathDir {
		return
	}
	warn := func(err error) {
		logger(fmt.Sprintf("Warning: could not copy %s from the container to %s (%v); its data is hidden by the new mount", m.ContainerPath, m.HostPath, err))
	}
	// Pull next to the host dir, so the moves below are renames on one
	// filesystem.
	if err := os.MkdirAll(filepath.Dir(m.HostPath), 0o755); err != nil {
		warn(err)
		return
	}
	tmp, err := os.MkdirTemp(filepath.Dir(m.HostPath), ".pull-*")
	if err != nil {
		warn(err)
		return
	}
	defer os.RemoveAll(tmp)
	pulled := filepath.Join(tmp, filepath.Base(m.HostPath))
	if err := puller.PullDirectory(m.ContainerPath, pulled); err != nil {
		warn(err)
		return
	}
	if _, err := os.Lstat(m.HostPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(pulled, m.HostPath); err != nil {
			warn(err)
			return
		}
		logger(fmt.Sprintf("Copied tool data out of the container: %s -> %s", m.ContainerPath, m.HostPath))
		return
	}
	entries, err := os.ReadDir(pulled)
	if err != nil {
		warn(err)
		return
	}
	for _, e := range entries {
		dst := filepath.Join(m.HostPath, e.Name())
		if _, err := os.Lstat(dst); err == nil || !errors.Is(err, os.ErrNotExist) {
			logger(fmt.Sprintf("Warning: %s already exists; %s/%s stays hidden in the container", dst, m.ContainerPath, e.Name()))
			continue
		}
		if err := os.Rename(filepath.Join(pulled, e.Name()), dst); err != nil {
			warn(err)
			return
		}
	}
	logger(fmt.Sprintf("Copied tool data out of the container: %s -> %s", m.ContainerPath, m.HostPath))
}
