package credentials

import (
	"reflect"
	"testing"
)

func TestLookup_KnownBundles(t *testing.T) {
	for _, name := range []string{"claude", "opencode", "opencode2", "pi", "codex", "ollama", "omp"} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("Lookup(%q): expected bundle to exist", name)
		}
	}
}

func TestLookup_UnknownBundle(t *testing.T) {
	if _, ok := Lookup("not-a-real-bundle"); ok {
		t.Fatal(`Lookup("not-a-real-bundle"): expected ok=false`)
	}
}

func TestNames_Sorted(t *testing.T) {
	names := Names()
	if !reflect.DeepEqual(names, []string{"claude", "codex", "ollama", "omp", "opencode", "opencode2", "pi"}) {
		t.Errorf("Names() = %v, want sorted [claude codex ollama omp opencode opencode2 pi]", names)
	}
}

// TestClaudeBundle_MatchesHardcodedValues locks the claude catalog entry to
// the values ClaudeTool hardcoded before the catalog existed — a regression
// guard for the refactor (task builtin-tool-catalog-wiring) that points
// ClaudeTool's ToolWithConfigDirFiles methods at this bundle instead.
func TestClaudeBundle_MatchesHardcodedValues(t *testing.T) {
	b, ok := Lookup("claude")
	if !ok {
		t.Fatal("claude bundle not found")
	}
	if b.ConfigDir != ".claude" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".claude")
	}
	want := []string{".credentials.json", "config.yml", "settings.json", "CLAUDE.md"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.StateFile != ".claude.json" {
		t.Errorf("StateFile = %q, want %q", b.StateFile, ".claude.json")
	}
	if b.SandboxSettingsFile != "settings.json" {
		t.Errorf("SandboxSettingsFile = %q, want %q", b.SandboxSettingsFile, "settings.json")
	}
	if b.AlwaysSetup {
		t.Error("AlwaysSetup = true, want false")
	}
	if b.AutoContextFile != ".claude/CLAUDE.md" {
		t.Errorf("AutoContextFile = %q, want %q", b.AutoContextFile, ".claude/CLAUDE.md")
	}
}

func TestOpencodeBundle_MatchesHardcodedValues(t *testing.T) {
	b, ok := Lookup("opencode")
	if !ok {
		t.Fatal("opencode bundle not found")
	}
	if b.ConfigDir != ".config/opencode" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".config/opencode")
	}
	want := []string{"opencode.json", "tui.json"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.SandboxSettingsFile != "opencode.json" {
		t.Errorf("SandboxSettingsFile = %q, want %q", b.SandboxSettingsFile, "opencode.json")
	}
	if b.StateFile != "" {
		t.Errorf("StateFile = %q, want empty", b.StateFile)
	}
	if !b.AlwaysSetup {
		t.Error("AlwaysSetup = false, want true")
	}
}

func TestPiBundle_MatchesHardcodedValues(t *testing.T) {
	b, ok := Lookup("pi")
	if !ok {
		t.Fatal("pi bundle not found")
	}
	if b.ConfigDir != ".pi/agent" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".pi/agent")
	}
	want := []string{"settings.json", "models.json", "auth.json", "AGENTS.md"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.SandboxSettingsFile != "settings.json" {
		t.Errorf("SandboxSettingsFile = %q, want %q", b.SandboxSettingsFile, "settings.json")
	}
	if b.StateFile != "" {
		t.Errorf("StateFile = %q, want empty", b.StateFile)
	}
	if !b.AlwaysSetup {
		t.Error("AlwaysSetup = false, want true")
	}
}

// TestCodexBundle_Shape locks the codex catalog entry: no sandbox settings file
// (codex config is TOML — coi's settings merge is JSON-only, so everything is
// delivered as launch flags), no sibling state file, setup skipped without a
// host ~/.codex (like claude), context injected into ~/.codex/AGENTS.md.
func TestCodexBundle_Shape(t *testing.T) {
	b, ok := Lookup("codex")
	if !ok {
		t.Fatal("codex bundle not found")
	}
	if b.ConfigDir != ".codex" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".codex")
	}
	want := []string{"auth.json", "config.toml", "AGENTS.md"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.SandboxSettingsFile != "" {
		t.Errorf("SandboxSettingsFile = %q, want empty", b.SandboxSettingsFile)
	}
	if b.StateFile != "" {
		t.Errorf("StateFile = %q, want empty", b.StateFile)
	}
	if b.AlwaysSetup {
		t.Error("AlwaysSetup = true, want false")
	}
	if b.AutoContextFile != ".codex/AGENTS.md" {
		t.Errorf("AutoContextFile = %q, want %q", b.AutoContextFile, ".codex/AGENTS.md")
	}
}

func TestOllamaBundle_Shape(t *testing.T) {
	b, ok := Lookup("ollama")
	if !ok {
		t.Fatal("ollama bundle not found")
	}
	if b.ConfigDir != ".ollama" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".ollama")
	}
	want := []string{"id_ed25519"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.Mode != "0600" {
		t.Errorf("Mode = %q, want %q", b.Mode, "0600")
	}
}

func TestOmpBundle_MatchesHardcodedValues(t *testing.T) {
	b, ok := Lookup("omp")
	if !ok {
		t.Fatal("omp bundle not found")
	}
	if b.ConfigDir != ".omp" {
		t.Errorf("ConfigDir = %q, want %q", b.ConfigDir, ".omp")
	}
	want := []string{"settings.json", "models.json", "auth.json", "AGENTS.md"}
	if !reflect.DeepEqual(b.Files, want) {
		t.Errorf("Files = %v, want %v", b.Files, want)
	}
	if b.SandboxSettingsFile != "settings.json" {
		t.Errorf("SandboxSettingsFile = %q, want %q", b.SandboxSettingsFile, "settings.json")
	}
	if !b.AlwaysSetup {
		t.Error("AlwaysSetup = false, want true")
	}
}
