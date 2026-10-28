package session

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

func TestToolDataMounts_Opencode(t *testing.T) {
	ws := "/home/u/project"
	got := ToolDataMounts("/home/u/.coi", tool.NewOpencode(), ws)
	base := filepath.Join("/home/u/.coi", "tool-data", "opencode", WorkspaceHash(ws))
	want := []MountEntry{
		{
			HostPath:      filepath.Join(base, "share"),
			ContainerPath: "/home/code/.local/share/opencode",
			DeviceName:    "tool-data-opencode-share",
			MigrateFrom:   "/home/u/project/.local/share/opencode",
		},
		{
			HostPath:      filepath.Join(base, "state"),
			ContainerPath: "/home/code/.local/state/opencode",
			DeviceName:    "tool-data-opencode-state",
			MigrateFrom:   "/home/u/project/.local/state/opencode",
		},
	}
	if len(got) != len(want) {
		t.Fatalf("ToolDataMounts() = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].HostPath != want[i].HostPath || got[i].ContainerPath != want[i].ContainerPath ||
			got[i].DeviceName != want[i].DeviceName || got[i].MigrateFrom != want[i].MigrateFrom ||
			got[i].Readonly || got[i].Untrusted {
			t.Errorf("mount %d = %+v, want %+v", i, got[i], want[i])
		}
		// The host dir must never sit inside the workspace (#929).
		if rel, err := filepath.Rel(ws, got[i].HostPath); err == nil && !strings.HasPrefix(rel, "..") {
			t.Errorf("host path %s is inside the workspace", got[i].HostPath)
		}
	}
}

// opencode2's plan dir was never in the workspace, so it has no MigrateFrom: a
// project's own .opencode/plan stays where it is.
func TestToolDataMounts_Opencode2Plan(t *testing.T) {
	ws := "/home/u/project"
	got := ToolDataMounts("/home/u/.coi", tool.NewOpencode2(), ws)
	if len(got) != 3 {
		t.Fatalf("ToolDataMounts() = %+v, want share, state and plan", got)
	}
	plan := got[2]
	want := MountEntry{
		HostPath:      filepath.Join("/home/u/.coi", "tool-data", "opencode2", WorkspaceHash(ws), "plan"),
		ContainerPath: "/home/code/.opencode/plan",
		DeviceName:    "tool-data-opencode2-plan",
	}
	if plan.HostPath != want.HostPath || plan.ContainerPath != want.ContainerPath ||
		plan.DeviceName != want.DeviceName || plan.MigrateFrom != "" || plan.Readonly {
		t.Errorf("plan mount = %+v, want %+v", plan, want)
	}
	if got[0].MigrateFrom != "/home/u/project/.local/share/opencode" {
		t.Errorf("share MigrateFrom = %q, want the pre-#929 workspace path", got[0].MigrateFrom)
	}
}

func TestPrepareMountSource_PlanKeepsWorkspaceDir(t *testing.T) {
	ws := t.TempDir()
	own := filepath.Join(ws, ".opencode", "plan", "keep.md")
	if err := os.MkdirAll(filepath.Dir(own), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("project file"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := ToolDataMounts(t.TempDir(), tool.NewOpencode2(), ws)[2]

	if err := PrepareMountSource(plan, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(own); err != nil {
		t.Errorf("the workspace's own .opencode/plan was moved: %v", err)
	}
	if entries, _ := os.ReadDir(plan.HostPath); len(entries) != 0 {
		t.Errorf("host plan dir = %v, want it empty", entries)
	}
}

func TestToolDataMounts_ToolWithoutDataDirs(t *testing.T) {
	if got := ToolDataMounts("/c", tool.NewClaude(), "/ws"); got != nil {
		t.Errorf("claude has no data dirs, got %+v", got)
	}
	mc := &MountConfig{Mounts: []MountEntry{{DeviceName: "mount-0"}}}
	if got := WithToolDataMounts(mc, "/c", tool.NewClaude(), "/ws"); got != mc {
		t.Error("WithToolDataMounts should return mc unchanged for a tool without data dirs")
	}
	if got := WithToolDataMounts(nil, "/c", nil, "/ws"); got != nil {
		t.Errorf("nil tool: got %+v, want nil", got)
	}
}

func TestWithToolDataMounts_AppendsWithoutMutating(t *testing.T) {
	mc := &MountConfig{Mounts: []MountEntry{{DeviceName: "mount-0"}}}
	got := WithToolDataMounts(mc, "/c", tool.NewOpencode(), "/ws")
	if len(mc.Mounts) != 1 {
		t.Fatalf("input mutated: %+v", mc.Mounts)
	}
	if len(got.Mounts) != 3 || got.Mounts[0].DeviceName != "mount-0" || got.Mounts[1].DeviceName != "tool-data-opencode-share" {
		t.Errorf("got %+v", got.Mounts)
	}
	if got := WithToolDataMounts(nil, "/c", tool.NewOpencode(), "/ws"); got == nil || len(got.Mounts) != 2 {
		t.Errorf("nil mc: got %+v", got)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Data an older coi left in the workspace moves to the host dir, and the empty
// .local/share and .local dirs it leaves behind are pruned.
func TestPrepareMountSource_MigratesAndPrunes(t *testing.T) {
	ws := t.TempDir()
	host := filepath.Join(t.TempDir(), "tool-data", "opencode", "abc", "share")
	from := filepath.Join(ws, ".local", "share", "opencode")
	writeFile(t, filepath.Join(from, "opencode.db"), "db")

	var logs []string
	if err := PrepareMountSource(MountEntry{HostPath: host, MigrateFrom: from}, func(s string) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(host, "opencode.db")); err != nil || string(b) != "db" {
		t.Fatalf("db not moved: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(ws, ".local")); !os.IsNotExist(err) {
		t.Errorf("empty .local should be pruned, stat err = %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("want one migration log line, got %q", logs)
	}
}

// Unrelated content in the workspace .local is never touched.
func TestPrepareMountSource_KeepsNonEmptyParents(t *testing.T) {
	ws := t.TempDir()
	host := filepath.Join(t.TempDir(), "share")
	from := filepath.Join(ws, ".local", "share", "opencode")
	writeFile(t, filepath.Join(from, "opencode.db"), "db")
	writeFile(t, filepath.Join(ws, ".local", "share", "other", "keep"), "x")

	if err := PrepareMountSource(MountEntry{HostPath: host, MigrateFrom: from}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ws, ".local", "share", "other", "keep")); err != nil {
		t.Errorf("unrelated file removed: %v", err)
	}
}

// Once the host dir exists it wins: old workspace data is left alone rather
// than overwriting (or merging into) newer history.
func TestPrepareMountSource_DoesNotClobberExistingHostDir(t *testing.T) {
	ws := t.TempDir()
	host := filepath.Join(t.TempDir(), "share")
	writeFile(t, filepath.Join(host, "opencode.db"), "new")
	from := filepath.Join(ws, ".local", "share", "opencode")
	writeFile(t, filepath.Join(from, "opencode.db"), "old")

	if err := PrepareMountSource(MountEntry{HostPath: host, MigrateFrom: from}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(host, "opencode.db")); string(b) != "new" {
		t.Errorf("host db = %q, want new", b)
	}
	if b, _ := os.ReadFile(filepath.Join(from, "opencode.db")); string(b) != "old" {
		t.Errorf("workspace db = %q, want old (untouched)", b)
	}
}

func TestPrepareMountSource_NothingToMigrate(t *testing.T) {
	host := filepath.Join(t.TempDir(), "a", "share")
	if err := PrepareMountSource(MountEntry{HostPath: host, MigrateFrom: filepath.Join(t.TempDir(), "missing")}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(host); err != nil || !info.IsDir() {
		t.Errorf("host dir not created: %v", err)
	}
}

// A symlink at the old location is not followed: a workspace could otherwise
// point it at arbitrary host data and have coi move that under ~/.coi.
func TestPrepareMountSource_DoesNotFollowSymlink(t *testing.T) {
	ws := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, filepath.Join(target, "secret"), "s")
	from := filepath.Join(ws, ".local", "share", "opencode")
	if err := os.MkdirAll(filepath.Dir(from), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, from); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(t.TempDir(), "share")
	if err := PrepareMountSource(MountEntry{HostPath: host, MigrateFrom: from}, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "secret")); err != nil {
		t.Errorf("symlink target moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(host, "secret")); !os.IsNotExist(err) {
		t.Errorf("symlinked data should not be migrated, stat err = %v", err)
	}
}

// A reused container gets the tool data mounts it lacks; attached ones are
// left alone, and user [[mounts]] are never re-added.
func TestAttachMissingToolDataMounts(t *testing.T) {
	coiDir := t.TempDir()
	ws := t.TempDir()
	mc := WithToolDataMounts(&MountConfig{Mounts: []MountEntry{{DeviceName: "mount-0", HostPath: t.TempDir(), ContainerPath: "/x"}}}, coiDir, tool.NewOpencode(), ws)
	share := mc.Mounts[1]
	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{
		share.DeviceName: {Source: share.HostPath, Path: share.ContainerPath, Shift: true},
	}}

	if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(f.adds) != 1 || f.adds[0] != "tool-data-opencode-state" {
		t.Fatalf("adds = %v, want only the missing state mount", f.adds)
	}
	if d := f.devices["tool-data-opencode-state"]; !d.Shift || d.Readonly || d.Path != "/home/code/.local/state/opencode" {
		t.Errorf("state device = %+v", d)
	}
	// The attached device's host dir is (re)created so the container can start.
	if _, err := os.Stat(share.HostPath); err != nil {
		t.Errorf("share host dir not created: %v", err)
	}
}

// A tool data mount without MigrateFrom (opencode2's plan dir) is still one of
// coi's own, so a reused stopped container gets it too.
func TestAttachMissingToolDataMounts_AddsMountWithoutMigration(t *testing.T) {
	mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{}}

	if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	want := []string{"tool-data-opencode2-plan", "tool-data-opencode2-share", "tool-data-opencode2-state"}
	if got := sorted(f.adds); !slices.Equal(got, want) {
		t.Errorf("adds = %v, want %v", got, want)
	}
}

// The real manager must satisfy containerDirPuller, or the copy never runs.
var _ containerDirPuller = (*container.Manager)(nil)

// fakeDataDirContainer is a stopped container whose files are a map of
// container dir -> file name -> content.
type fakeDataDirContainer struct {
	fakeDiskDevices
	dirs    map[string]map[string]string
	pullErr error
	pulls   []string
}

func (f *fakeDataDirContainer) PathKind(p string) (container.PathKind, error) {
	if _, ok := f.dirs[p]; ok {
		return container.PathDir, nil
	}
	return container.PathNone, nil
}

func (f *fakeDataDirContainer) PullDirectory(containerPath, localPath string) error {
	f.pulls = append(f.pulls, containerPath)
	if f.pullErr != nil {
		return f.pullErr
	}
	if _, ok := f.devices["tool-data-opencode2-plan"]; ok {
		return errors.New("pulled after the mount was added")
	}
	for name, content := range f.dirs[containerPath] {
		if err := os.MkdirAll(localPath, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(localPath, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// A 0.16 opencode2 container keeps its plans in its rootfs. The new plan
// mount would hide them, so they are copied to the new host dir before the
// mount is added. Dirs with MigrateFrom come from the workspace instead.
func TestAttachMissingToolDataMounts_CopiesContainerPlans(t *testing.T) {
	mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
	plan := mc.Mounts[2]
	f := &fakeDataDirContainer{
		fakeDiskDevices: fakeDiskDevices{devices: map[string]container.DiskDevice{}},
		dirs: map[string]map[string]string{
			"/home/code/.opencode/plan":        {"old.md": "plan"},
			"/home/code/.local/share/opencode": {"opencode.db": "db"},
		},
	}
	var logs []string

	if err := AttachMissingToolDataMounts(f, mc, true, func(s string) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/home/code/.opencode/plan"}; !slices.Equal(f.pulls, want) {
		t.Fatalf("pulls = %v, want %v", f.pulls, want)
	}
	if b, _ := os.ReadFile(filepath.Join(plan.HostPath, "old.md")); string(b) != "plan" {
		t.Errorf("host old.md = %q, want plan", b)
	}
	if _, ok := f.devices[plan.DeviceName]; !ok {
		t.Errorf("plan mount not added")
	}
	if !slices.ContainsFunc(logs, func(s string) bool { return strings.Contains(s, "Copied tool data out of the container") }) {
		t.Errorf("logs = %v, want the copy reported", logs)
	}
}

// Nothing is copied when the host dir already holds data, when the mount is
// already attached, or when the container has no such dir.
func TestAttachMissingToolDataMounts_SkipsContainerCopy(t *testing.T) {
	newContainer := func(devices map[string]container.DiskDevice) *fakeDataDirContainer {
		return &fakeDataDirContainer{
			fakeDiskDevices: fakeDiskDevices{devices: devices},
			dirs:            map[string]map[string]string{"/home/code/.opencode/plan": {"old.md": "plan"}},
		}
	}

	t.Run("host dir exists", func(t *testing.T) {
		mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
		writeFile(t, filepath.Join(mc.Mounts[2].HostPath, "new.md"), "new")
		f := newContainer(map[string]container.DiskDevice{})
		if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
			t.Fatal(err)
		}
		if len(f.pulls) != 0 {
			t.Errorf("pulls = %v, want none", f.pulls)
		}
	})

	t.Run("already attached", func(t *testing.T) {
		mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
		plan := mc.Mounts[2]
		f := newContainer(map[string]container.DiskDevice{
			plan.DeviceName: {Source: plan.HostPath, Path: plan.ContainerPath, Shift: true},
		})
		if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
			t.Fatal(err)
		}
		if len(f.pulls) != 0 {
			t.Errorf("pulls = %v, want none", f.pulls)
		}
	})

	t.Run("no dir in container", func(t *testing.T) {
		mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
		f := newContainer(map[string]container.DiskDevice{})
		f.dirs = nil
		if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
			t.Fatal(err)
		}
		if len(f.pulls) != 0 {
			t.Errorf("pulls = %v, want none", f.pulls)
		}
		if info, err := os.Stat(mc.Mounts[2].HostPath); err != nil || !info.IsDir() {
			t.Errorf("plan host dir not created: %v", err)
		}
	})
}

// A failed copy warns and still adds the mount: the plans stay in the
// container, and the session starts.
func TestAttachMissingToolDataMounts_ContainerCopyFails(t *testing.T) {
	mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode2(), t.TempDir())
	f := &fakeDataDirContainer{
		fakeDiskDevices: fakeDiskDevices{devices: map[string]container.DiskDevice{}},
		dirs:            map[string]map[string]string{"/home/code/.opencode/plan": {"old.md": "plan"}},
		pullErr:         errors.New("boom"),
	}
	var logs []string

	if err := AttachMissingToolDataMounts(f, mc, true, func(s string) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.devices["tool-data-opencode2-plan"]; !ok {
		t.Errorf("plan mount not added")
	}
	if !slices.ContainsFunc(logs, func(s string) bool { return strings.Contains(s, "Warning: could not copy /home/code/.opencode/plan") }) {
		t.Errorf("logs = %v, want a copy warning", logs)
	}
}

func TestAttachMissingToolDataMounts_NoToolDataMounts(t *testing.T) {
	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{}}
	mc := &MountConfig{Mounts: []MountEntry{{DeviceName: "mount-0", HostPath: t.TempDir(), ContainerPath: "/x"}}}
	if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if err := AttachMissingToolDataMounts(f, nil, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if len(f.adds) != 0 {
		t.Errorf("adds = %v, want none", f.adds)
	}
}

// Switching a reused container between tools that share a data path (opencode
// and opencode2 both use ~/.local/share/opencode) must drop the other tool's
// mount first: Incus can't start a container with two disk devices on one path.
// Unrelated devices — another path, or a user [[mounts]] entry — stay.
func TestAttachMissingToolDataMounts_ReplacesOtherToolOnSamePath(t *testing.T) {
	mc := WithToolDataMounts(nil, t.TempDir(), tool.NewOpencode(), t.TempDir())
	f := &fakeDiskDevices{devices: map[string]container.DiskDevice{
		"tool-data-opencode2-share": {Source: "/h/opencode2/share", Path: "/home/code/.local/share/opencode", Shift: true},
		"tool-data-opencode2-state": {Source: "/h/opencode2/state", Path: "/home/code/.local/state/opencode", Shift: true},
		"tool-data-other-cache":     {Source: "/h/other", Path: "/home/code/.cache/other", Shift: true},
		"mount-0":                   {Source: "/h/user", Path: "/home/code/user", Shift: true},
	}}

	if err := AttachMissingToolDataMounts(f, mc, true, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if got, want := sorted(f.removes), []string{"tool-data-opencode2-share", "tool-data-opencode2-state"}; !slices.Equal(got, want) {
		t.Errorf("removes = %v, want %v", got, want)
	}
	if got, want := sorted(f.adds), []string{"tool-data-opencode-share", "tool-data-opencode-state"}; !slices.Equal(got, want) {
		t.Errorf("adds = %v, want %v", got, want)
	}
	for _, keep := range []string{"tool-data-other-cache", "mount-0"} {
		if _, ok := f.devices[keep]; !ok {
			t.Errorf("%s was removed", keep)
		}
	}
}
