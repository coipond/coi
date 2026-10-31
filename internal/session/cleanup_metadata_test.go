package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

func TestSaveAndLoadMetadata_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")

	in := SessionMetadata{
		SessionID:     "abc123",
		ContainerName: "claude-aabbcc-1",
		Persistent:    true,
		ProfileName:   "default",
		Workspace:     "/home/user/myproject",
		SavedAt:       "2024-01-15T10:30:00Z",
	}

	if err := saveMetadata(path, in); err != nil {
		t.Fatalf("saveMetadata: %v", err)
	}

	out, err := LoadSessionMetadata(path)
	if err != nil {
		t.Fatalf("LoadSessionMetadata: %v", err)
	}

	if *out != in {
		t.Errorf("roundtrip mismatch:\n got  %+v\n want %+v", *out, in)
	}
}

func TestSaveAndLoadMetadata_SpecialCharsInPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")

	// Characters that would break fmt.Sprintf hand-built JSON
	in := SessionMetadata{
		SessionID:     "sess-99",
		ContainerName: "claude-ff0011-2",
		Persistent:    false,
		ProfileName:   `my"special"profile`,
		Workspace:     `/home/user/path with spaces/and "quotes" and \backslash`,
		SavedAt:       "2024-06-01T00:00:00Z",
	}

	if err := saveMetadata(path, in); err != nil {
		t.Fatalf("saveMetadata: %v", err)
	}

	out, err := LoadSessionMetadata(path)
	if err != nil {
		t.Fatalf("LoadSessionMetadata: %v", err)
	}

	if *out != in {
		t.Errorf("roundtrip mismatch for special chars:\n got  %+v\n want %+v", *out, in)
	}
}

func TestSaveMetadata_ProducesValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")

	in := SessionMetadata{
		SessionID:     "json-check",
		ContainerName: "claude-001122-3",
		Persistent:    false,
		ProfileName:   "default",
		Workspace:     "/workspace",
		SavedAt:       "2024-01-01T00:00:00Z",
	}

	if err := saveMetadata(path, in); err != nil {
		t.Fatalf("saveMetadata: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Errorf("saved file is not valid JSON: %v\ncontent: %s", err, data)
	}
}

func TestLoadSessionMetadata_MissingSessionID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")

	if err := os.WriteFile(path, []byte(`{"container_name":"c","persistent":false}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSessionMetadata(path)
	if err == nil {
		t.Fatal("expected error for missing session_id, got nil")
	}
}

func TestLoadSessionMetadata_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")

	if err := os.WriteFile(path, []byte(`not json at all`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadSessionMetadata(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestLoadSessionMetadata_FileNotFound(t *testing.T) {
	_, err := LoadSessionMetadata("/nonexistent/path/metadata.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestSaveMetadata_PersistentFlagRoundTrip(t *testing.T) {
	dir := t.TempDir()

	for _, persistent := range []bool{true, false} {
		path := filepath.Join(dir, "meta.json")
		in := SessionMetadata{
			SessionID:     "p-test",
			ContainerName: "claude-aabb-1",
			Persistent:    persistent,
			ProfileName:   "default",
			Workspace:     "/workspace",
			SavedAt:       "2024-01-01T00:00:00Z",
		}
		if err := saveMetadata(path, in); err != nil {
			t.Fatalf("saveMetadata(persistent=%v): %v", persistent, err)
		}
		out, err := LoadSessionMetadata(path)
		if err != nil {
			t.Fatalf("LoadSessionMetadata(persistent=%v): %v", persistent, err)
		}
		if out.Persistent != persistent {
			t.Errorf("Persistent=%v roundtrip: got %v", persistent, out.Persistent)
		}
	}
}

func TestSaveMetadataEarly_CreatesFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	sessionsDir := filepath.Join(dir, "sessions")

	err := SaveMetadataEarly(sessionsDir, "early-sess", "claude-early-1", "/workspace", false, "default", true)
	if err != nil {
		t.Fatalf("SaveMetadataEarly: %v", err)
	}

	metaPath := filepath.Join(sessionsDir, "early-sess", "metadata.json")
	out, err := LoadSessionMetadata(metaPath)
	if err != nil {
		t.Fatalf("LoadSessionMetadata after SaveMetadataEarly: %v", err)
	}

	if out.SessionID != "early-sess" {
		t.Errorf("SessionID: got %q, want %q", out.SessionID, "early-sess")
	}
	if out.ContainerName != "claude-early-1" {
		t.Errorf("ContainerName: got %q, want %q", out.ContainerName, "claude-early-1")
	}
	if out.Workspace != "/workspace" {
		t.Errorf("Workspace: got %q, want %q", out.Workspace, "/workspace")
	}
	if out.ProfileName != "default" {
		t.Errorf("ProfileName: got %q, want %q", out.ProfileName, "default")
	}
	if !out.ProfileFromDefault {
		t.Error("ProfileFromDefault: got false, want true")
	}
}

// pullDirManager fakes a successful PullDirectory; other methods are unused.
type pullDirManager struct {
	container.ContainerManager
}

func (pullDirManager) PullDirectory(_, localPath string) error {
	return os.MkdirAll(localPath, 0o755)
}

func TestSaveSessionData_SavesProfileFromDefault(t *testing.T) {
	for _, fromDefault := range []bool{true, false} {
		sessionsDir := t.TempDir()
		err := saveSessionData(pullDirManager{}, "c-1", "s1", false, "work", fromDefault, "/ws", sessionsDir, tool.GetDefault(), func(string) {})
		if err != nil {
			t.Fatalf("saveSessionData: %v", err)
		}
		out, err := LoadSessionMetadata(filepath.Join(sessionsDir, "s1", "metadata.json"))
		if err != nil {
			t.Fatalf("LoadSessionMetadata: %v", err)
		}
		if out.ProfileName != "work" || out.ProfileFromDefault != fromDefault {
			t.Errorf("metadata profile = %q, from default %v; want %q, %v", out.ProfileName, out.ProfileFromDefault, "work", fromDefault)
		}
	}
}
