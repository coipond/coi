package session

import (
	"errors"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// batchFake is a stopped container with a MountDisks (one PATCH per call).
type batchFake struct {
	fakeDiskDevices
	patches   [][]container.DiskMount
	failBatch bool            // fail any MountDisks call with more than one device
	failNames map[string]bool // fail MountDisks for these devices
}

func (f *batchFake) MountDisks(mounts []container.DiskMount) error {
	if f.failBatch && len(mounts) > 1 {
		return errors.New("batch rejected")
	}
	for _, d := range mounts {
		if f.failNames[d.Name] {
			return errors.New("device rejected")
		}
	}
	f.patches = append(f.patches, append([]container.DiskMount(nil), mounts...))
	for _, d := range mounts {
		f.devices[d.Name] = container.DiskDevice{Source: d.Source, Path: d.Path, Shift: d.Shift, Readonly: d.Readonly}
	}
	return nil
}

func newBatchFake() *batchFake {
	return &batchFake{fakeDiskDevices: fakeDiskDevices{devices: map[string]container.DiskDevice{
		"workspace":       {Source: "/old", Path: "/workspace", Shift: true},
		"protect-husky":   {Source: "/old/.husky", Path: "/workspace/.husky", Readonly: true},
		"protect-dropped": {Source: "/old/.x", Path: "/workspace/.x", Readonly: true},
	}, names: []string{"workspace", "protect-husky", "protect-dropped"}}}
}

// A reuse with a new workspace source replaces every device in ONE update, and
// removes only what is not re-added.
func TestDeviceBatch_ReplacementsAreOnePatch(t *testing.T) {
	f := newBatchFake()
	b := newDeviceBatch(f, func(string) {})

	_ = b.RemoveDevice("workspace")
	_ = b.MountDisk("workspace", "/new", "/workspace", true, false)
	_ = b.RemoveDevice("protect-husky")
	_ = b.MountDisk("protect-husky", "/new/.husky", "/workspace/.husky", false, true)
	_ = b.RemoveDevice("protect-dropped")
	_ = b.MountDisks([]container.DiskMount{{Name: "pin-abc", Source: "/new", Path: "/workspace/sub"}})

	if len(f.patches)+len(f.adds)+len(f.removes) != 0 {
		t.Fatalf("changes applied before Flush: patches=%v adds=%v removes=%v", f.patches, f.adds, f.removes)
	}
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 || len(f.patches[0]) != 3 {
		t.Fatalf("want one PATCH with 3 devices, got %v", f.patches)
	}
	if got := strings.Join(f.removes, ","); got != "protect-dropped" {
		t.Fatalf("only the dropped device is removed, got %q", got)
	}
	if d := f.devices["workspace"]; d.Source != "/new" {
		t.Fatalf("workspace not replaced: %+v", d)
	}
	if d := f.devices["protect-husky"]; d.Source != "/new/.husky" || !d.Readonly {
		t.Fatalf("protect device not replaced: %+v", d)
	}
}

// A removal for a device that does not exist is skipped, not an error.
func TestDeviceBatch_RemovalOfMissingDeviceIsSkipped(t *testing.T) {
	f := newBatchFake()
	b := newDeviceBatch(f, func(string) {})
	_ = b.RemoveDevice("git-worktree-common")
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.removes) != 0 {
		t.Fatalf("removed a missing device: %v", f.removes)
	}
}

// When the PATCH fails, each device is retried alone: a failing pin is a
// warning, the rest still lands.
func TestDeviceBatch_FailedBatchRetriesPerDevice(t *testing.T) {
	f := newBatchFake()
	f.failBatch, f.failNames = true, map[string]bool{"pin-bad": true}
	var warnings []string
	b := newDeviceBatch(f, func(s string) { warnings = append(warnings, s) })
	_ = b.MountDisk("workspace", "/new", "/workspace", true, false)
	_ = b.MountDisks([]container.DiskMount{{Name: "pin-bad", Source: "/new", Path: "/workspace/p"}})

	if err := b.Flush(); err != nil {
		t.Fatalf("a failing pin must not fail the flush: %v", err)
	}
	if f.devices["workspace"].Source != "/new" {
		t.Fatal("workspace not mounted after per-device retry")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "not pinned") {
		t.Fatalf("want one pin warning, got %v", warnings)
	}
}

// A non-pin device that fails alone fails the flush (fail closed: the start is
// aborted rather than booting without a protect device). The error names the
// container path of every failed device, not the hashed device name, and the
// devices after a failed one are still mounted.
func TestDeviceBatch_FailedSecurityDeviceFailsFlush(t *testing.T) {
	f := newBatchFake()
	f.failBatch, f.failNames = true, map[string]bool{"protect-husky": true, "protect-vscode": true}
	b := newDeviceBatch(f, func(string) {})
	_ = b.MountDisk("workspace", "/new", "/workspace", true, false)
	_ = b.MountDisk("protect-husky", "/new/.husky", "/workspace/.husky", false, true)
	_ = b.MountDisk("protect-vscode", "/new/.vscode", "/workspace/.vscode", false, true)
	_ = b.MountDisk("protect-idea", "/new/.idea", "/workspace/.idea", false, true)
	err := b.Flush()
	if !errors.Is(err, ErrProtectFailed) {
		t.Fatalf("want ErrProtectFailed, got %v", err)
	}
	for _, want := range []string{"/workspace/.husky: device rejected", "/workspace/.vscode: device rejected"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "protect-") {
		t.Errorf("error %q names a device, want the path", err)
	}
	if f.devices["protect-idea"].Source != "/new/.idea" {
		t.Error("the device after the failed ones was not mounted")
	}
}

// Without MountDisks the batch is a pass-through (old behavior).
func TestDeviceBatch_PassThroughWithoutBatchMounter(t *testing.T) {
	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{"workspace": {Source: "/old"}}}
	b := newDeviceBatch(f, func(string) {})
	_ = b.RemoveDevice("workspace")
	_ = b.MountDisk("workspace", "/new", "/workspace", false, false)
	if strings.Join(f.removes, ",") != "workspace" || strings.Join(f.adds, ",") != "workspace" {
		t.Fatalf("want immediate remove+add, got removes=%v adds=%v", f.removes, f.adds)
	}
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
}

// The security reconciler routed through the batch: changed devices become
// one PATCH entry each, unrequested ones are removed at Flush.
func TestDeviceBatch_WithSecurityReconciler(t *testing.T) {
	f := newBatchFake()
	// Reconciler snapshot needs existing sources on disk; use the batch only
	// as its writer, as restartStoppedContainer does.
	r := &SecurityDeviceReconciler{ContainerManager: f, existing: map[string]container.DiskDevice{
		"protect-husky":   f.devices["protect-husky"],
		"protect-dropped": f.devices["protect-dropped"],
	}, wanted: map[string]bool{}, logger: func(string) {}}
	b := newDeviceBatch(f, func(string) {})
	r.ContainerManager = b

	if err := r.MountDisk("protect-husky", "/new/.husky", "/workspace/.husky", false, true); err != nil {
		t.Fatal(err)
	}
	r.Finish()
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(f.patches) != 1 || f.patches[0][0].Name != "protect-husky" {
		t.Fatalf("want one PATCH replacing protect-husky, got %v", f.patches)
	}
	if strings.Join(f.removes, ",") != "protect-dropped" {
		t.Fatalf("want protect-dropped removed, got %v", f.removes)
	}
}
