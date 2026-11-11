package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
)

// writeListSave writes one saved session's metadata.json with its mode.
func writeListSave(tb testing.TB, sessionsDir, id, containerName, workspace string, persistent bool) {
	tb.Helper()
	dir := filepath.Join(sessionsDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatal(err)
	}
	data, err := json.Marshal(session.SessionMetadata{SessionID: id, ContainerName: containerName, Workspace: workspace, Persistent: persistent})
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644); err != nil {
		tb.Fatal(err)
	}
}

func TestContainerSessionInfo_FromKeys(t *testing.T) {
	dir := t.TempDir()
	// Stale saves must not win over the keys on the containers.
	writeListSave(t, dir, "s1", "coi-aaaaaaaa-1", "/old/path", false)
	writeListSave(t, dir, "s2", "coi-bbbbbbbb-1", "/old/other", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", Persistent: true, PersistentSet: true},
		{Name: "coi-bbbbbbbb-1", Workspace: "/home/u/eph", PersistentSet: true},
	}, dir)

	if ws["coi-aaaaaaaa-1"] != "/home/u/proj" || !persistent["coi-aaaaaaaa-1"] {
		t.Errorf("aaaa: workspace=%q persistent=%v; want /home/u/proj, true", ws["coi-aaaaaaaa-1"], persistent["coi-aaaaaaaa-1"])
	}
	if ws["coi-bbbbbbbb-1"] != "/home/u/eph" || persistent["coi-bbbbbbbb-1"] {
		t.Errorf("bbbb: workspace=%q persistent=%v; want /home/u/eph, false", ws["coi-bbbbbbbb-1"], persistent["coi-bbbbbbbb-1"])
	}
}

func TestContainerSessionInfo_FallbackWithoutKeys(t *testing.T) {
	dir := t.TempDir()
	writeListSave(t, dir, "s1", "coi-cccccccc-1", "/home/u/other", false)
	writeListSave(t, dir, "s2", "coi-bbbbbbbb-1", "/home/u/legacy", true)
	writeListSave(t, dir, "s3", "coi-dddddddd-1", "/home/u/saved", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", PersistentSet: true},
		// Created before coi set any key.
		{Name: "coi-bbbbbbbb-1"},
		// Workspace key without the persistence key: the key's workspace wins.
		{Name: "coi-dddddddd-1", Workspace: "/home/u/keyed", Managed: true},
	}, dir)

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

func TestContainerSessionInfo_ManagedWithoutWorkspaceSkipsFallback(t *testing.T) {
	dir := t.TempDir()
	// Even a matching save is not read: the marker says coi set no workspace.
	writeListSave(t, dir, "s1", "coi-launched-1", "/home/u/stale", true)
	ws, persistent := containerSessionInfo([]ContainerInfo{{Name: "coi-launched-1", Managed: true}}, dir)

	if w, ok := ws["coi-launched-1"]; ok || persistent["coi-launched-1"] {
		t.Errorf("workspace=%q (present %v) persistent=%v; want none for a managed container without %s",
			w, ok, persistent["coi-launched-1"], session.WorkspaceConfigKey)
	}
}

func TestContainerSessionInfo_NoSaves(t *testing.T) {
	ws, persistent := containerSessionInfo([]ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Workspace: "/home/u/proj", Persistent: true, PersistentSet: true},
		{Name: "coi-bbbbbbbb-1"},
	}, filepath.Join(t.TempDir(), "missing"))

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
		container.ManagedConfigKey + `":"true"}},{"name":"coi-bbbbbbbb-1","status":"Stopped","config":{}}]`
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
	if len(got) != 2 {
		t.Fatalf("got %d containers, want 2: %+v", len(got), got)
	}
	if c := got[0]; c.Workspace != "/home/u/proj" || !c.Persistent || !c.PersistentSet || !c.Managed {
		t.Errorf("keyed container = %+v; want workspace, persistent, both keys set", c)
	}
	if c := got[1]; c.Workspace != "" || c.Persistent || c.PersistentSet || c.Managed {
		t.Errorf("keyless container = %+v; want no session keys", c)
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
				writeListSave(b, dir, fmt.Sprintf("s%05d", i), fmt.Sprintf("coi-%08x-1", i), fmt.Sprintf("/home/u/p%d", i), false)
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
				containerSessionInfo(containers, dir)
			}
		})
	}
}

func TestPersistCommand_SetsPersistentKey(t *testing.T) {
	sessionsDir := useTopHome(t)
	writeListSave(t, sessionsDir, "s1", "coi-aaaaaaaa-1", "/home/u/proj", false)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n  *\"list \"*) echo coi-aaaaaaaa-1 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := persistCommand(persistCmd, []string{"coi-aaaaaaaa-1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "config set coi-aaaaaaaa-1 "+session.PersistentConfigKey+"=true") {
		t.Errorf("want %s=true set on the container; calls:\n%s", session.PersistentConfigKey, b)
	}
	md, err := session.LoadSessionMetadata(filepath.Join(sessionsDir, "s1", "metadata.json"))
	if err != nil || !md.Persistent {
		t.Errorf("metadata persistent = %v (err %v); want true", md.Persistent, err)
	}
}
