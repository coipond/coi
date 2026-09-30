package session

import (
	"fmt"
	"os"

	"github.com/coipond/coi/internal/container"
)

// ResolveMountShift picks the effective UID/GID shift flag for a single
// configured mount, folding a per-mount `shift` override (#604) into the
// session-wide decision.
//
//   - override == nil        → sessionUseShift (the workspace's decision; the common case)
//   - *override && !rawIdmap → true  (force an idmapped mount; host files show as `code`)
//   - !*override             → false (opt this mount out of shifting)
//
// A per-mount shift=true is dropped to false (with a warning) when the
// container uses raw.idmap for UID mapping: shift and raw.idmap are mutually
// exclusive (Incus rejects the combination) and raw.idmap already remaps the
// mount to the container user, so the override is both unsafe and redundant.
func ResolveMountShift(sessionUseShift bool, override *bool, rawIdmapActive bool, deviceName string, logger func(string)) bool {
	if override == nil {
		return sessionUseShift
	}
	if *override && rawIdmapActive {
		if logger != nil {
			logger(fmt.Sprintf("Mount %s: shift=true ignored — this container uses raw.idmap for UID mapping (mutually exclusive with shift); the mount is already remapped to the container user", deviceName))
		}
		return false
	}
	return *override
}

// mountShiftDrift records a single mount whose attached shift flag no longer
// matches what the current config asks for (#604).
type mountShiftDrift struct {
	host, container string
	got, want       bool
}

// detectMountShiftDrift compares each configured mount that carries an EXPLICIT
// shift override against the shift flag of its attached disk device (keyed by
// host source path), returning the entries that drifted. Only explicit
// overrides are checked: the inherit case (Shift == nil) tracks the session-wide
// decision, which is out of scope here. `want` folds in the raw.idmap clamp so a
// shift=true override under raw.idmap (which resolves to false) is not reported
// as drift. A mount whose source is not attached (e.g. a readonly source that
// was missing at creation) is skipped. Pure so it is unit-testable without incus.
func detectMountShiftDrift(mounts []MountEntry, attachedShiftBySource map[string]bool, rawIdmapActive bool) []mountShiftDrift {
	var drifted []mountShiftDrift
	for _, m := range mounts {
		if m.Shift == nil {
			continue
		}
		got, ok := attachedShiftBySource[m.HostPath]
		if !ok {
			continue
		}
		want := *m.Shift && !rawIdmapActive
		if got != want {
			drifted = append(drifted, mountShiftDrift{m.HostPath, m.ContainerPath, got, want})
		}
	}
	return drifted
}

// WarnMountShiftDrift warns, on a REUSED container, when an attached mount
// device's shift no longer matches the shift the current config requests (#604).
// Mount devices are created once and never re-added on reuse (like mount-trust,
// see §4.6 in Setup), so a changed `shift` is otherwise a silent no-op — the
// container must be recreated to apply it. No-op when no mount carries an
// explicit override, when the device data can't be read, or when nothing drifted.
func WarnMountShiftDrift(containerName string, mounts []MountEntry, logger func(string)) {
	if logger == nil {
		return
	}
	hasOverride := false
	for _, m := range mounts {
		if m.Shift != nil {
			hasOverride = true
			break
		}
	}
	if !hasOverride {
		return
	}
	attached, err := container.DiskDeviceShiftBySource(containerName)
	if err != nil || attached == nil {
		return
	}
	for _, d := range detectMountShiftDrift(mounts, attached, container.ContainerUsesRawIdmap(containerName)) {
		logger(fmt.Sprintf(
			"Warning: mount %s -> %s is attached with shift=%t but the current config requests shift=%t; mount devices persist from creation, so recreate the container (coi kill + relaunch) to apply the change",
			d.host, d.container, d.got, d.want))
	}
}

// setupMounts mounts all configured directories to the container
func setupMounts(mgr container.ContainerDevices, mountConfig *MountConfig, useShift, rawIdmapActive bool, logger func(string)) error {
	if mountConfig == nil || len(mountConfig.Mounts) == 0 {
		return nil
	}

	for _, mount := range mountConfig.Mounts {
		if mount.Readonly {
			// For readonly mounts, skip creating host directory — if the source
			// doesn't exist, log a warning and skip the mount instead of creating
			// an empty directory (which defeats the purpose).
			if _, err := os.Stat(mount.HostPath); err != nil {
				if os.IsNotExist(err) {
					logger(fmt.Sprintf("Warning: readonly mount source %s does not exist, skipping", mount.HostPath))
					continue
				}
				return fmt.Errorf("failed to stat readonly mount source '%s': %w", mount.HostPath, err)
			}
		} else {
			// Create host directory if it doesn't exist (writable mounts only)
			if err := os.MkdirAll(mount.HostPath, 0o755); err != nil {
				return fmt.Errorf("failed to create mount directory '%s': %w", mount.HostPath, err)
			}
		}

		if mount.Readonly {
			logger(fmt.Sprintf("Adding mount (read-only): %s -> %s", mount.HostPath, mount.ContainerPath))
		} else {
			logger(fmt.Sprintf("Adding mount: %s -> %s", mount.HostPath, mount.ContainerPath))
		}

		// Apply the effective shift setting: the session-wide decision unless
		// the mount carries an explicit `shift` override (#604).
		shift := ResolveMountShift(useShift, mount.Shift, rawIdmapActive, mount.DeviceName, logger)
		if err := mgr.MountDisk(mount.DeviceName, mount.HostPath, mount.ContainerPath, shift, mount.Readonly); err != nil {
			return fmt.Errorf("failed to add mount '%s': %w", mount.DeviceName, err)
		}
	}

	return nil
}
