package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
	"github.com/coipond/coi/internal/tool"
)

func TestContainerSessionInfo_FromKeys(t *testing.T) {
	dir := t.TempDir()
	// Stale saves must not win over the keys on the containers.
	writeSavedSession(t, dir, "s1", "coi-aaaaaaaa-1", "/old/path", false)
	writeSavedSession(t, dir, "s2", "coi-bbbbbbbb-1", "/old/other", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", Persistent: true, PersistentSet: true},
		{Name: "coi-bbbbbbbb-1", Workspace: "/home/u/eph", PersistentSet: true},
	}, []string{dir})

	if ws["coi-aaaaaaaa-1"] != "/home/u/proj" || !persistent["coi-aaaaaaaa-1"] {
		t.Errorf("aaaa: workspace=%q persistent=%v; want /home/u/proj, true", ws["coi-aaaaaaaa-1"], persistent["coi-aaaaaaaa-1"])
	}
	if ws["coi-bbbbbbbb-1"] != "/home/u/eph" || persistent["coi-bbbbbbbb-1"] {
		t.Errorf("bbbb: workspace=%q persistent=%v; want /home/u/eph, false", ws["coi-bbbbbbbb-1"], persistent["coi-bbbbbbbb-1"])
	}
}

func TestContainerSessionInfo_FallbackWithoutKeys(t *testing.T) {
	dir := t.TempDir()
	writeSavedSession(t, dir, "s1", "coi-cccccccc-1", "/home/u/other", false)
	writeSavedSession(t, dir, "s2", "coi-bbbbbbbb-1", "/home/u/legacy", true)
	writeSavedSession(t, dir, "s3", "coi-dddddddd-1", "/home/u/saved", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", PersistentSet: true},
		// Created before coi set any key.
		{Name: "coi-bbbbbbbb-1"},
		// Workspace key without the persistence key: the key's workspace wins.
		{Name: "coi-dddddddd-1", Workspace: "/home/u/keyed", Managed: true},
	}, []string{dir})

	want := map[string]string{"coi-aaaaaaaa-1": "/home/u/proj", "coi-bbbbbbbb-1": "/home/u/legacy", "coi-dddddddd-1": "/home/u/keyed"}
	for name, w := range want {
		if ws[name] != w {
			t.Errorf("%s workspace = %q; want %q", name, ws[name], w)
		}
	}
	if _, ok := ws["coi-cccccccc-1"]; ok {
		t.Errorf("a save of a container not listed must not appear: %v", ws)
	}
	if persistent["coi-aaaaaaaa-1"] || !persistent["coi-bbbbbbbb-1"] || !persistent["coi-dddddddd-1"] {
		t.Errorf("persistent = %v; want aaaa false, bbbb and dddd true", persistent)
	}
}

func TestContainerSessionInfo_FallbackReadsEveryToolsSessions(t *testing.T) {
	base := t.TempDir()
	dirs := session.AllSessionsDirs(base, tool.NewClaude())
	// Launched by opencode while the configured tool is claude.
	opencodeDir := filepath.Join(base, "sessions-opencode")
	if !slices.Contains(dirs, opencodeDir) || !slices.Contains(dirs, filepath.Join(base, "sessions-claude")) {
		t.Fatalf("AllSessionsDirs = %v; want the claude and opencode dirs", dirs)
	}
	writeSavedSession(t, opencodeDir, "s1", "coi-aaaaaaaa-1", "/home/u/proj", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{{Name: "coi-aaaaaaaa-1"}}, dirs)

	if ws["coi-aaaaaaaa-1"] != "/home/u/proj" || !persistent["coi-aaaaaaaa-1"] {
		t.Errorf("workspace=%q persistent=%v; want /home/u/proj, true from the opencode save",
			ws["coi-aaaaaaaa-1"], persistent["coi-aaaaaaaa-1"])
	}
}

func TestContainerSessionInfo_FallbackPrefersConfiguredToolsSave(t *testing.T) {
	base := t.TempDir()
	// The same name in two tools' dirs: an old ephemeral claude run in the
	// slot, then a persistent opencode one, the configured tool.
	writeSavedSession(t, filepath.Join(base, "sessions-claude"), "s1", "coi-aaaaaaaa-1", "/home/u/old", false)
	writeSavedSession(t, filepath.Join(base, "sessions-opencode"), "s2", "coi-aaaaaaaa-1", "/home/u/proj", true)
	dirs := session.AllSessionsDirs(base, tool.NewOpencode())
	if dirs[0] != filepath.Join(base, "sessions-opencode") || len(dirs) != len(tool.ListSupported()) {
		t.Fatalf("AllSessionsDirs = %v; want sessions-opencode first, each tool once", dirs)
	}
	ws, persistent := containerSessionInfo([]ContainerInfo{{Name: "coi-aaaaaaaa-1"}}, dirs)

	if ws["coi-aaaaaaaa-1"] != "/home/u/proj" || !persistent["coi-aaaaaaaa-1"] {
		t.Errorf("workspace=%q persistent=%v; want /home/u/proj, true from the configured tool's save",
			ws["coi-aaaaaaaa-1"], persistent["coi-aaaaaaaa-1"])
	}
}

func TestContainerSessionInfo_FallbackNewestSaveWins(t *testing.T) {
	dir := t.TempDir()
	// Session dirs are read in name order, so each older save comes first.
	saves := []session.SessionMetadata{
		{SessionID: "s1", ContainerName: "coi-aaaaaaaa-1", Workspace: "/home/u/old", SavedAt: "2026-10-01T10:00:00Z"},
		{SessionID: "s2", ContainerName: "coi-aaaaaaaa-1", Workspace: "/home/u/new", Persistent: true, SavedAt: "2026-11-01T10:00:00Z"},
		// 09:30-01:00 is 10:30 UTC: the newer save, though it sorts first as
		// a string.
		{SessionID: "s3", ContainerName: "coi-bbbbbbbb-1", Workspace: "/home/u/local", Persistent: true, SavedAt: "2026-11-01T09:30:00-01:00"},
		{SessionID: "s4", ContainerName: "coi-bbbbbbbb-1", Workspace: "/home/u/utc", SavedAt: "2026-11-01T10:00:00Z"},
		// A valid saved_at wins over an unparsable one in either order.
		{SessionID: "s5", ContainerName: "coi-cccccccc-1", Workspace: "/home/u/valid", Persistent: true, SavedAt: "2026-10-01T10:00:00Z"},
		{SessionID: "s6", ContainerName: "coi-cccccccc-1", Workspace: "/home/u/bad", SavedAt: "yesterday"},
		{SessionID: "s7", ContainerName: "coi-dddddddd-1", Workspace: "/home/u/none"},
		{SessionID: "s8", ContainerName: "coi-dddddddd-1", Workspace: "/home/u/dated", Persistent: true, SavedAt: "2026-10-01T10:00:00Z"},
	}
	for _, m := range saves {
		writeSessionMetadata(t, dir, m)
	}
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1"}, {Name: "coi-bbbbbbbb-1"}, {Name: "coi-cccccccc-1"}, {Name: "coi-dddddddd-1"},
	}, []string{dir})

	want := map[string]string{
		"coi-aaaaaaaa-1": "/home/u/new", "coi-bbbbbbbb-1": "/home/u/local",
		"coi-cccccccc-1": "/home/u/valid", "coi-dddddddd-1": "/home/u/dated",
	}
	for name, w := range want {
		if ws[name] != w || !persistent[name] {
			t.Errorf("%s: workspace=%q persistent=%v; want %q, true", name, ws[name], persistent[name], w)
		}
	}
}

func TestContainerSessionInfo_ManagedWithoutWorkspaceSkipsFallback(t *testing.T) {
	dir := t.TempDir()
	// Even a matching save is not read: the marker says coi set no workspace.
	writeSavedSession(t, dir, "s1", "coi-launched-1", "/home/u/stale", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{{Name: "coi-launched-1", Managed: true}}, []string{dir})

	if w, ok := ws["coi-launched-1"]; ok || persistent["coi-launched-1"] {
		t.Errorf("workspace=%q (present %v) persistent=%v; want none for a managed container without %s",
			w, ok, persistent["coi-launched-1"], session.WorkspaceConfigKey)
	}
}

func TestContainerSessionInfo_ShellIntoLaunchedContainerShowsNoWorkspace(t *testing.T) {
	dir := t.TempDir()
	// `coi shell --container` on a `coi container launch` container saves the
	// dir it ran in, but that dir is not mounted: the container lists without
	// a workspace, in the mode the session recorded on it.
	writeSavedSession(t, dir, "s1", "coi-launched-1", "/home/u/w", false)
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-launched-1", Managed: true, Persistent: true, PersistentSet: true},
	}, []string{dir})

	if w, ok := ws["coi-launched-1"]; ok || !persistent["coi-launched-1"] {
		t.Errorf("workspace=%q (present %v) persistent=%v; want no workspace, persistent from the key",
			w, ok, persistent["coi-launched-1"])
	}
}

func TestContainerSessionInfo_NoSaves(t *testing.T) {
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", Persistent: true, PersistentSet: true},
		{Name: "coi-bbbbbbbb-1"},
	}, []string{filepath.Join(t.TempDir(), "missing")})

	if ws["coi-aaaaaaaa-1"] != "/home/u/proj" || !persistent["coi-aaaaaaaa-1"] {
		t.Errorf("keyed: workspace=%q persistent=%v; want /home/u/proj, true", ws["coi-aaaaaaaa-1"], persistent["coi-aaaaaaaa-1"])
	}
	if w, ok := ws["coi-bbbbbbbb-1"]; ok || persistent["coi-bbbbbbbb-1"] {
		t.Errorf("keyless: workspace=%q (present %v) persistent=%v; want none", w, ok, persistent["coi-bbbbbbbb-1"])
	}
}

func TestListActiveContainers_ReadsSessionKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	listJSON := `[{"name":"coi-aaaaaaaa-1","status":"Running","config":{"` +
		session.WorkspaceConfigKey + `":"/home/u/proj","` + session.PersistentConfigKey + `":"true","` +
		container.ManagedConfigKey + `":"true"}},{"name":"coi-bbbbbbbb-1","status":"Stopped","config":{"` +
		container.StateReasonKey + `":"max_duration","` + container.StateReasonAtKey + `":"2026-11-28T03:00:00Z"}},` +
		`{"name":"coi-cccccccc-1","status":"Running","config":{"` + session.PersistentConfigKey + `":"false"}}]`
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(listJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \"$*\" in\n  *\"list \"*) cat " + filepath.Join(dir, "list.json") + " ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := listActiveContainers()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d containers, want 3: %+v", len(got), got)
	}
	if c := got[0]; c.Workspace != "/home/u/proj" || !c.Persistent || !c.PersistentSet || !c.Managed {
		t.Errorf("keyed container = %+v; want workspace, persistent, both keys set", c)
	}
	if c := got[1]; c.Workspace != "" || c.Persistent || c.PersistentSet || c.Managed {
		t.Errorf("keyless container = %+v; want no session keys", c)
	}
	if c := got[1]; c.StateReason != "max_duration" || c.StateReasonAt != "2026-11-28T03:00:00Z" {
		t.Errorf("stopped container reason = %q at %q; want max_duration at 2026-11-28T03:00:00Z", c.StateReason, c.StateReasonAt)
	}
	if c := got[0]; c.StateReason != "" || c.StateReasonAt != "" {
		t.Errorf("running container reason = %q at %q; want none", c.StateReason, c.StateReasonAt)
	}
	if c := got[2]; c.Persistent || !c.PersistentSet {
		t.Errorf("ephemeral container = %+v; want the persistence key set to false", c)
	}
}

// BenchmarkContainerSessionInfo_SavedSessions shows `coi list` time does not
// grow with the number of saved sessions when containers carry the keys or
// the managed marker.
func BenchmarkContainerSessionInfo_SavedSessions(b *testing.B) {
	for _, saves := range []int{0, 1000, 20000} {
		b.Run(fmt.Sprintf("saves=%d", saves), func(b *testing.B) {
			dir := b.TempDir()
			for i := range saves {
				writeSavedSession(b, dir, fmt.Sprintf("s%05d", i), fmt.Sprintf("coi-%08x-1", i), fmt.Sprintf("/home/u/p%d", i), false)
			}
			var containers []ContainerInfo
			for i := range 5 {
				containers = append(containers, ContainerInfo{
					Name: fmt.Sprintf("coi-run%05d-1", i), Workspace: fmt.Sprintf("/home/u/run%d", i),
					PersistentSet: true, Managed: true,
				})
			}
			// A `coi container launch` container: no workspace, no save.
			containers = append(containers, ContainerInfo{Name: "coi-launched-1", Managed: true})
			for b.Loop() {
				containerSessionInfo(containers, []string{dir})
			}
		})
	}
}
