package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/session"
)

// useTopHome points HOME at a temp dir with the default tool configured and
// returns that tool's sessions dir (not created).
func useTopHome(tb testing.TB) string {
	tb.Helper()
	home := tb.TempDir()
	tb.Setenv("HOME", home)
	origApp := app
	tb.Cleanup(func() { app = origApp })
	app = &App{cfg: &config.Config{}}
	t, err := getConfiguredTool(app.cfg)
	if err != nil {
		tb.Fatal(err)
	}
	return session.GetSessionsDir(filepath.Join(home, ".coi"), t)
}

// writeSavedSession writes one saved session's metadata.json.
func writeSavedSession(tb testing.TB, sessionsDir, id, containerName, workspace string) {
	tb.Helper()
	dir := filepath.Join(sessionsDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatal(err)
	}
	data, err := json.Marshal(session.SessionMetadata{SessionID: id, ContainerName: containerName, Workspace: workspace})
	if err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644); err != nil {
		tb.Fatal(err)
	}
}

func stubTopRunning(tb testing.TB, entries []incusTopEntry) {
	tb.Helper()
	origList, origRes := topListEntries, topCollectResources
	tb.Cleanup(func() { topListEntries, topCollectResources = origList, origRes })
	topListEntries = func() ([]incusTopEntry, error) { return entries, nil }
	topCollectResources = func(context.Context, string) (monitor.ResourceStats, error) {
		return monitor.ResourceStats{}, nil
	}
}

func workspacesByName(tb testing.TB) map[string]string {
	tb.Helper()
	rows, err := sampleContainerRows(context.Background(), 0)
	if err != nil {
		tb.Fatalf("sampleContainerRows: %v", err)
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Name] = r.Workspace
	}
	return out
}

func TestSampleContainerRows_WorkspaceFromConfigKey(t *testing.T) {
	sessionsDir := useTopHome(t)
	// A stale save must not win over the key on the container.
	writeSavedSession(t, sessionsDir, "s1", "coi-aaaaaaaa-1", "/old/path")
	stubTopRunning(t, []incusTopEntry{{
		Name: "coi-aaaaaaaa-1", Status: "Running",
		Config: map[string]string{session.WorkspaceConfigKey: "/home/u/proj"},
	}})

	got := workspacesByName(t)
	if got["coi-aaaaaaaa-1"] != "/home/u/proj" {
		t.Errorf("workspace = %q; want /home/u/proj from %s", got["coi-aaaaaaaa-1"], session.WorkspaceConfigKey)
	}
}

func TestSampleContainerRows_WorkspaceFallbackWithoutKey(t *testing.T) {
	sessionsDir := useTopHome(t)
	writeSavedSession(t, sessionsDir, "s1", "coi-bbbbbbbb-1", "/home/u/legacy")
	writeSavedSession(t, sessionsDir, "s2", "coi-cccccccc-1", "/home/u/other")
	stubTopRunning(t, []incusTopEntry{
		{Name: "coi-aaaaaaaa-1", Status: "Running", Config: map[string]string{session.WorkspaceConfigKey: "/home/u/proj"}},
		{Name: "coi-bbbbbbbb-1", Status: "Running", Config: map[string]string{}},
	})

	got := workspacesByName(t)
	want := map[string]string{"coi-aaaaaaaa-1": "/home/u/proj", "coi-bbbbbbbb-1": "/home/u/legacy"}
	for name, ws := range want {
		if got[name] != ws {
			t.Errorf("%s workspace = %q; want %q", name, got[name], ws)
		}
	}
}

func TestSampleContainerRows_WorkspaceNoSaves(t *testing.T) {
	useTopHome(t) // no sessions dir at all
	stubTopRunning(t, []incusTopEntry{
		{Name: "coi-aaaaaaaa-1", Status: "Running", Config: map[string]string{session.WorkspaceConfigKey: "/home/u/proj"}},
		{Name: "coi-bbbbbbbb-1", Status: "Running", Config: map[string]string{}},
	})

	got := workspacesByName(t)
	if got["coi-aaaaaaaa-1"] != "/home/u/proj" {
		t.Errorf("keyed workspace = %q; want /home/u/proj", got["coi-aaaaaaaa-1"])
	}
	if ws, ok := got["coi-bbbbbbbb-1"]; !ok || ws != "" {
		t.Errorf("keyless container: row present=%v workspace=%q; want a row with no workspace", ok, ws)
	}
}

// BenchmarkSampleContainerRows_SavedSessions shows `coi top` time does not
// grow with the number of saved sessions when containers carry the key.
func BenchmarkSampleContainerRows_SavedSessions(b *testing.B) {
	for _, saves := range []int{0, 1000, 20000} {
		b.Run(fmt.Sprintf("saves=%d", saves), func(b *testing.B) {
			sessionsDir := useTopHome(b)
			for i := range saves {
				writeSavedSession(b, sessionsDir, fmt.Sprintf("s%05d", i), fmt.Sprintf("coi-%08x-1", i), fmt.Sprintf("/home/u/p%d", i))
			}
			var running []incusTopEntry
			for i := range 5 {
				running = append(running, incusTopEntry{
					Name: fmt.Sprintf("coi-run%05d-1", i), Status: "Running",
					Config: map[string]string{session.WorkspaceConfigKey: fmt.Sprintf("/home/u/run%d", i)},
				})
			}
			stubTopRunning(b, running)
			for b.Loop() {
				if _, err := sampleContainerRows(context.Background(), 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
