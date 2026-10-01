package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

func TestResolveContextJSON(t *testing.T) {
	info := tool.ContextInfo{
		ContainerName: "coi-xyz",
		WorkspacePath: "/workspace",
		HomeDir:       "/home/code",
		NetworkMode:   "restricted",
	}
	discard := func(string) {}

	assertGenerated := func(t *testing.T, out string) {
		t.Helper()
		var got tool.SandboxContextJSON
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("fallback output is not valid JSON: %v\n%s", err, out)
		}
		if got.SchemaVersion == 0 || got.ContainerName != "coi-xyz" {
			t.Errorf("expected the generated JSON (schema_version + container_name), got %+v", got)
		}
	}

	t.Run("no custom path -> generated", func(t *testing.T) {
		out, err := resolveContextJSON("", info, discard)
		if err != nil {
			t.Fatal(err)
		}
		assertGenerated(t, out)
	})

	t.Run("valid custom file -> injected verbatim", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "custom.json")
		custom := `{"schema_version": 99, "custom_marker": "X"}`
		if err := os.WriteFile(p, []byte(custom), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := resolveContextJSON(p, info, discard)
		if err != nil {
			t.Fatal(err)
		}
		if out != custom {
			t.Errorf("valid custom file should be injected verbatim, got %q", out)
		}
	})

	t.Run("invalid custom file -> warns and falls back to generated", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, []byte("{ this is not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		var warned string
		out, err := resolveContextJSON(p, info, func(m string) { warned += m })
		if err != nil {
			t.Fatal(err)
		}
		assertGenerated(t, out)
		if !strings.Contains(warned, "not valid JSON") {
			t.Errorf("expected an 'not valid JSON' warning, got %q", warned)
		}
	})

	t.Run("missing custom file -> warns and falls back to generated", func(t *testing.T) {
		var warned string
		out, err := resolveContextJSON("/no/such/file.json", info, func(m string) { warned += m })
		if err != nil {
			t.Fatal(err)
		}
		assertGenerated(t, out)
		if !strings.Contains(warned, "could not read") {
			t.Errorf("expected a 'could not read' warning, got %q", warned)
		}
	})
}
