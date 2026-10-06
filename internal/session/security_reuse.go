package session

import (
	"fmt"
	"os"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// diskDeviceLister is implemented by *container.Manager; kept out of
// container.ContainerManager so test fakes needn't grow it.
type diskDeviceLister interface {
	DiskDevices() (map[string]container.DiskDevice, error)
}

// SecurityDeviceReconciler converges a STOPPED reused container's security
// disk devices (protect-*, mask-*, gitc-*, ...) to the current workspace
// without the old strip-everything-then-re-add round trips: a device that
// would be re-added with the identical source, path, shift and readonly is
// kept as is, a differing one is replaced, and any not requested this session
// is removed (finish). The end state is exactly what strip + re-add produced.
//
// Devices whose host source has disappeared are removed up front, before any
// other config change touches the container — the #610 "Missing source path"
// wedge — exactly as StripSecurityDevices did. The git-identity device gets the
// same check: its source is a file under ~/.coi, and with it gone every start of
// the container would abort on the mount. It is otherwise left to the
// git-identity step, which re-establishes it after start.
type SecurityDeviceReconciler struct {
	container.ContainerManager
	existing map[string]container.DiskDevice // security devices only
	wanted   map[string]bool
	logger   func(string)
}

// NewSecurityDeviceReconciler snapshots mgr's security devices. When the
// devices cannot be read in detail it falls back to StripSecurityDevices and
// returns a reconciler that adds everything (the old behavior).
func NewSecurityDeviceReconciler(mgr container.ContainerManager, logger func(string)) *SecurityDeviceReconciler {
	r := &SecurityDeviceReconciler{ContainerManager: mgr, existing: map[string]container.DiskDevice{}, wanted: map[string]bool{}, logger: logger}
	lister, ok := mgr.(diskDeviceLister)
	if !ok {
		StripSecurityDevices(mgr, logger)
		return r
	}
	disks, err := lister.DiskDevices()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not read devices (%v); re-creating security devices", err))
		StripSecurityDevices(mgr, logger)
		return r
	}
	for name, d := range disks {
		security := isSecurityDevice(name)
		if !security && name != gitReadonlyDeviceName {
			continue
		}
		if _, statErr := os.Lstat(d.Source); statErr != nil {
			if err := mgr.RemoveDevice(name); err != nil {
				logger(fmt.Sprintf("Warning: could not remove stale security device %s: %v", name, err))
			}
			continue
		}
		if security {
			r.existing[name] = d
		}
	}
	return r
}

func isSecurityDevice(name string) bool {
	for _, prefix := range stripSecurityDevicePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// MountDisk keeps an identical existing security device, replaces a
// differing one, and adds a new one. Non-security devices pass through.
func (r *SecurityDeviceReconciler) MountDisk(name, source, path string, shift, readonly bool) error {
	if !isSecurityDevice(name) {
		return r.ContainerManager.MountDisk(name, source, path, shift, readonly)
	}
	r.wanted[name] = true
	if cur, ok := r.existing[name]; ok {
		if cur == (container.DiskDevice{Source: source, Path: path, Shift: shift, Readonly: readonly}) {
			return nil
		}
		if err := r.RemoveDevice(name); err != nil {
			return fmt.Errorf("failed to replace device %s: %w", name, err)
		}
		delete(r.existing, name)
	}
	return r.ContainerManager.MountDisk(name, source, path, shift, readonly)
}

// Finish removes the snapshot's security devices this session did not
// request (e.g. a protected path the config dropped, or one whose host path
// turned into a symlink). Must run before the container starts.
func (r *SecurityDeviceReconciler) Finish() {
	for name := range r.existing {
		if r.wanted[name] {
			continue
		}
		if err := r.RemoveDevice(name); err != nil {
			r.logger(fmt.Sprintf("Warning: could not remove stale security device %s: %v", name, err))
		}
	}
}
