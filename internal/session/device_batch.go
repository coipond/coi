package session

import (
	"fmt"
	"sort"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// deviceBatch defers a STOPPED reused container's disk device changes and
// applies them in one Incus update at Flush, instead of one `incus config
// device remove`/`add` per device. A reuse with a new workspace source (every
// CoiPond run gets its own workspace directory) replaces the workspace, every
// protect-* device and every pin: 16 sequential calls at ~0.2-0.3 s each, now
// one PATCH.
//
// A PATCH merges the devices map, and a device it names replaces the existing
// device of that name completely, so a remove followed by an add of the same
// name is one PATCH entry. A device removed and not re-added cannot be
// expressed in a PATCH, so Flush removes those first, one by one (rare: a
// protected path the config dropped).
//
// Reads (GetWorkspaceSource, ListDevices, ...) pass through to the real
// container and see the state before the batch. Only use it where nothing
// between the queued changes and Flush reads back the devices it changed.
type deviceBatch struct {
	container.ContainerManager
	mounter diskBatchMounter
	logger  func(string)

	removed map[string]bool
	mounts  map[string]container.DiskMount
	order   []string
}

// newDeviceBatch wraps mgr. It needs mgr's MountDisks (one PATCH per batch);
// without it the changes are applied one call each, as before.
func newDeviceBatch(mgr container.ContainerManager, logger func(string)) *deviceBatch {
	b := &deviceBatch{
		ContainerManager: mgr,
		logger:           logger,
		removed:          map[string]bool{},
		mounts:           map[string]container.DiskMount{},
	}
	b.mounter, _ = mgr.(diskBatchMounter)
	return b
}

// MountDisk queues a disk device; a queued device of the same name is
// replaced.
func (b *deviceBatch) MountDisk(name, source, path string, shift, readonly bool) error {
	if b.mounter == nil {
		return b.ContainerManager.MountDisk(name, source, path, shift, readonly)
	}
	b.queue(container.DiskMount{Name: name, Source: source, Path: path, Shift: shift, Readonly: readonly})
	return nil
}

// MountDisks queues several disk devices (the pin batch path).
func (b *deviceBatch) MountDisks(mounts []container.DiskMount) error {
	if b.mounter == nil {
		return fmt.Errorf("batch mounting not supported")
	}
	for _, d := range mounts {
		b.queue(d)
	}
	return nil
}

// RemoveDevice queues a removal. A later MountDisk of the same name turns it
// into a replacement.
func (b *deviceBatch) RemoveDevice(name string) error {
	if b.mounter == nil {
		return b.ContainerManager.RemoveDevice(name)
	}
	b.removed[name] = true
	if _, ok := b.mounts[name]; ok {
		delete(b.mounts, name)
		b.dropFromOrder(name)
	}
	return nil
}

func (b *deviceBatch) queue(d container.DiskMount) {
	if _, ok := b.mounts[d.Name]; !ok {
		b.order = append(b.order, d.Name)
	}
	b.mounts[d.Name] = d
}

func (b *deviceBatch) dropFromOrder(name string) {
	for i, n := range b.order {
		if n == name {
			b.order = append(b.order[:i], b.order[i+1:]...)
			return
		}
	}
}

// Flush applies the queued changes: pure removals first (each only if the
// device exists), then every added or replaced device in one PATCH. When the
// PATCH fails it retries device by device so one bad device does not cost the
// others: a parent pin that fails is a warning (as in mountNestedAndPins),
// anything else is an error that names the container path of every device
// that failed, wrapping ErrProtectFailed when a protect device is among them.
// Must run before the container starts.
func (b *deviceBatch) Flush() error {
	if b.mounter == nil {
		return nil
	}
	if err := b.flushRemovals(); err != nil {
		return err
	}
	mounts := make([]container.DiskMount, 0, len(b.order))
	for _, name := range b.order {
		mounts = append(mounts, b.mounts[name])
	}
	b.removed, b.mounts, b.order = map[string]bool{}, map[string]container.DiskMount{}, nil
	if len(mounts) == 0 || b.mounter.MountDisks(mounts) == nil {
		return nil
	}
	var failed []string
	protectFailed := false
	for _, d := range mounts {
		if err := b.mounter.MountDisks([]container.DiskMount{d}); err != nil {
			if strings.HasPrefix(d.Name, pinDevicePrefix) {
				b.logger(fmt.Sprintf("Warning: parent dir %s not pinned: %v", d.Path, err))
				continue
			}
			failed = append(failed, fmt.Sprintf("%s: %v", d.Path, err))
			protectFailed = protectFailed || strings.HasPrefix(d.Name, protectDevicePrefix) || strings.HasPrefix(d.Name, gitcDevicePrefix)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	if protectFailed {
		return fmt.Errorf("%w: %s", ErrProtectFailed, strings.Join(failed, "; "))
	}
	return fmt.Errorf("failed to mount devices: %s", strings.Join(failed, "; "))
}

// flushRemovals removes the queued devices that are not re-added.
func (b *deviceBatch) flushRemovals() error {
	var gone []string
	for name := range b.removed {
		if _, readded := b.mounts[name]; !readded {
			gone = append(gone, name)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	sort.Strings(gone)
	existing, err := b.ListDevices()
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}
	have := map[string]bool{}
	for _, name := range existing {
		have[name] = true
	}
	for _, name := range gone {
		if !have[name] {
			continue
		}
		if err := b.ContainerManager.RemoveDevice(name); err != nil {
			b.logger(fmt.Sprintf("Warning: could not remove device %s: %v", name, err))
		}
	}
	return nil
}
