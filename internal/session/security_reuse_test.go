package session

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeDiskDevices is a container whose disk devices live in a map.
type fakeDiskDevices struct {
	container.ContainerManager
	devices map[string]container.DiskDevice
	listErr error
	adds    []string
	removes []string
	names   []string // for the ListDevices fallback
}

func (f *fakeDiskDevices) DiskDevices() (map[string]container.DiskDevice, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := map[string]container.DiskDevice{}
	for k, v := range f.devices {
		out[k] = v
	}
	return out, nil
}

func (f *fakeDiskDevices) ListDevices() ([]string, error) { return f.names, nil }

func (f *fakeDiskDevices) MountDisk(name, source, path string, shift, readonly bool) error {
	f.adds = append(f.adds, name)
	f.devices[name] = container.DiskDevice{Source: source, Path: path, Shift: shift, Readonly: readonly}
	return nil
}

func (f *fakeDiskDevices) RemoveDevice(name string) error {
	f.removes = append(f.removes, name)
	delete(f.devices, name)
	return nil
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// A reused container whose security devices already match is left alone:
// no remove + re-add round trips. A changed device is replaced, a new one is
// added, an unrequested one is removed, and a device whose host source is gone
// is removed up front (#610).
func TestSecurityDeviceReconciler_Converges(t *testing.T) {
	dir := t.TempDir()
	same := filepath.Join(dir, ".git", "hooks")
	changed := filepath.Join(dir, ".vscode")
	dropped := filepath.Join(dir, ".husky")
	gone := filepath.Join(dir, "missing")
	for _, p := range []string{same, changed, dropped} {
		mkdirAll(t, p)
	}

	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{
		"workspace":           {Source: dir, Path: "/workspace"},
		"protect-git-hooks":   {Source: same, Path: "/workspace/.git/hooks", Readonly: true},
		"protect-vscode":      {Source: changed, Path: "/workspace/.vscode", Readonly: true, Shift: true},
		"protect-husky":       {Source: dropped, Path: "/workspace/.husky", Readonly: true},
		"mask-secret-missing": {Source: gone, Path: "/workspace/missing", Readonly: true},
	}}
	r := NewSecurityDeviceReconciler(f, func(string) {})
	if got := sorted(f.removes); len(got) != 1 || got[0] != "mask-secret-missing" {
		t.Fatalf("a device with a missing source must be removed up front, got removes=%v", got)
	}

	must(t, r.MountDisk("protect-git-hooks", same, "/workspace/.git/hooks", false, true)) // identical: kept
	must(t, r.MountDisk("protect-vscode", changed, "/workspace/.vscode", false, true))    // shift differs: replaced
	must(t, r.MountDisk("protect-new", same, "/workspace/new", false, true))              // new: added
	must(t, r.MountDisk("workspace", dir, "/workspace", false, false))                    // not a security device: passes through
	r.Finish()

	if got := sorted(f.adds); len(got) != 3 || got[0] != "protect-new" || got[1] != "protect-vscode" || got[2] != "workspace" {
		t.Errorf("adds = %v, want [protect-new protect-vscode workspace]", got)
	}
	if got := sorted(f.removes); len(got) != 3 || got[0] != "mask-secret-missing" || got[1] != "protect-husky" || got[2] != "protect-vscode" {
		t.Errorf("removes = %v, want [mask-secret-missing protect-husky protect-vscode]", got)
	}
	if d := f.devices["protect-vscode"]; d.Shift {
		t.Error("replaced device must carry the new config")
	}
	if _, ok := f.devices["protect-git-hooks"]; !ok {
		t.Error("identical device must be kept")
	}
}

// The git-identity device's source is a file under ~/.coi. If it is gone, the
// next start aborts on the mount, so it is removed before start like a stale
// security device; while present it is left for the post-start git-identity step
// (never kept, replaced or finished by the reconciler).
func TestSecurityDeviceReconciler_GitIdentity(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.gitconfig")
	if err := os.WriteFile(present, []byte("[user]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("missing source is removed before start", func(t *testing.T) {
		f := &fakeDiskDevices{devices: map[string]container.DiskDevice{
			gitReadonlyDeviceName: {Source: filepath.Join(dir, "gone.gitconfig"), Path: "/home/code/.gitconfig", Readonly: true},
		}}
		r := NewSecurityDeviceReconciler(f, func(string) {})
		r.Finish()
		if got := f.removes; len(got) != 1 || got[0] != gitReadonlyDeviceName {
			t.Fatalf("removes = %v, want [%s]", got, gitReadonlyDeviceName)
		}
	})

	t.Run("present source is left alone", func(t *testing.T) {
		f := &fakeDiskDevices{devices: map[string]container.DiskDevice{
			gitReadonlyDeviceName: {Source: present, Path: "/home/code/.gitconfig", Readonly: true},
		}}
		r := NewSecurityDeviceReconciler(f, func(string) {})
		r.Finish()
		if len(f.removes) != 0 {
			t.Fatalf("a git-identity device with its source present must be kept, removes=%v", f.removes)
		}
	})
}

// When the device config can't be read, fall back to the old strip-all and
// re-add everything.
func TestSecurityDeviceReconciler_FallsBackToStrip(t *testing.T) {
	f := &fakeDiskDevices{
		devices: map[string]container.DiskDevice{},
		listErr: errors.New("incus down"),
		names:   []string{"workspace", "protect-a", "mask-b", "gitc-c"},
	}
	r := NewSecurityDeviceReconciler(f, func(string) {})
	if got := sorted(f.removes); len(got) != 3 {
		t.Fatalf("fallback must strip all security devices, got %v", got)
	}
	must(t, r.MountDisk("protect-a", "/src", "/dst", false, true))
	r.Finish()
	if len(f.adds) != 1 {
		t.Errorf("fallback must re-add, got adds=%v", f.adds)
	}
}

func TestParseDiskDevices(t *testing.T) {
	got, err := container.ParseDiskDevices(`architecture: x86_64
config:
  image.os: Ubuntu
devices:
  protect-git-hooks:
    path: /workspace/.git/hooks
    readonly: "true"
    source: /home/u/p/.git/hooks
    type: disk
  workspace:
    path: /workspace
    shift: "true"
    source: /home/u/p
    type: disk
  ssh-agent:
    connect: unix:/tmp/a
    type: proxy
ephemeral: false
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 disk devices, got %v", got)
	}
	if d := got["protect-git-hooks"]; !d.Readonly || d.Shift || d.Source != "/home/u/p/.git/hooks" || d.Path != "/workspace/.git/hooks" {
		t.Errorf("protect device parsed wrong: %+v", d)
	}
	if d := got["workspace"]; !d.Shift || d.Readonly {
		t.Errorf("workspace device parsed wrong: %+v", d)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}
