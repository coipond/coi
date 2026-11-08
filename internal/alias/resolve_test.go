package alias

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProjectAlias(t *testing.T) {
	t.Run("valid config with alias", func(t *testing.T) {
		dir := t.TempDir()
		coiDir := filepath.Join(dir, ".coi")
		if err := os.MkdirAll(coiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nalias = \"myproject\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		got := loadProjectAlias(dir)
		if got != "myproject" {
			t.Errorf("loadProjectAlias() = %q, want %q", got, "myproject")
		}
	})

	t.Run("no config file", func(t *testing.T) {
		dir := t.TempDir()
		got := loadProjectAlias(dir)
		if got != "" {
			t.Errorf("loadProjectAlias() = %q, want empty", got)
		}
	})

	t.Run("config without alias", func(t *testing.T) {
		dir := t.TempDir()
		coiDir := filepath.Join(dir, ".coi")
		if err := os.MkdirAll(coiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nimage = \"ubuntu\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		got := loadProjectAlias(dir)
		if got != "" {
			t.Errorf("loadProjectAlias() = %q, want empty", got)
		}
	})

	t.Run("empty alias", func(t *testing.T) {
		dir := t.TempDir()
		coiDir := filepath.Join(dir, ".coi")
		if err := os.MkdirAll(coiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nalias = \"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		got := loadProjectAlias(dir)
		if got != "" {
			t.Errorf("loadProjectAlias() = %q, want empty", got)
		}
	})

	t.Run("malformed toml", func(t *testing.T) {
		dir := t.TempDir()
		coiDir := filepath.Join(dir, ".coi")
		if err := os.MkdirAll(coiDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("not valid toml [[["), 0o644); err != nil {
			t.Fatal(err)
		}

		got := loadProjectAlias(dir)
		if got != "" {
			t.Errorf("loadProjectAlias() = %q, want empty", got)
		}
	})
}

// withTempHome sets HOME to a temp directory so Load() uses an isolated
// aliases.json. Returns a cleanup function to restore the original HOME.
func withTempHome(t *testing.T) string {
	t.Helper()
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpHome)
	t.Cleanup(func() { os.Setenv("HOME", origHome) })
	return tmpHome
}

func TestResolveAliasForLaunch_CWDFallback(t *testing.T) {
	tmpHome := withTempHome(t)

	// Create a workspace directory with .coi/config.toml
	workspace := t.TempDir()
	coiDir := filepath.Join(workspace, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nalias = \"testfallback\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Change CWD to the workspace to trigger the fallback
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	// Call the production function — alias is not in registry, so
	// CWD fallback should kick in and auto-register it.
	resolved, err := ResolveAliasForLaunch("testfallback")
	if err != nil {
		t.Fatalf("ResolveAliasForLaunch() returned error: %v", err)
	}

	absWorkspace, _ := filepath.Abs(workspace)
	if resolved.Workspace != absWorkspace {
		t.Errorf("Workspace = %q, want %q", resolved.Workspace, absWorkspace)
	}

	// Verify the alias was persisted to the registry
	regPath := filepath.Join(tmpHome, ".coi", "aliases.json")
	reg, err := LoadFrom(regPath)
	if err != nil {
		t.Fatalf("LoadFrom failed: %v", err)
	}
	entry := reg.Lookup("testfallback")
	if entry == nil {
		t.Fatal("alias not found in registry after CWD fallback auto-registration")
	}
	if entry.Workspace != absWorkspace {
		t.Errorf("persisted Workspace = %q, want %q", entry.Workspace, absWorkspace)
	}
}

func TestResolveAliasForLaunch_CWDFallback_NoMatch(t *testing.T) {
	withTempHome(t)

	// Create a workspace directory with a different alias
	workspace := t.TempDir()
	coiDir := filepath.Join(workspace, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nalias = \"differentalias\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Change CWD to the workspace
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	// Querying a non-matching alias should fail — CWD has "differentalias"
	// but we ask for "nonexistent".
	_, err = ResolveAliasForLaunch("nonexistent")
	if err == nil {
		t.Fatal("expected error for non-matching alias, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestResolveAliasForLaunch_CWDFallback_SlotSuffix(t *testing.T) {
	withTempHome(t)

	workspace := t.TempDir()
	coiDir := filepath.Join(workspace, ".coi")
	if err := os.MkdirAll(coiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(coiDir, "config.toml"), []byte("[container]\nalias = \"slottest\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	origDir, _ := os.Getwd()
	os.Chdir(workspace)
	t.Cleanup(func() { os.Chdir(origDir) })

	// Alias with slot suffix should resolve via CWD fallback
	resolved, err := ResolveAliasForLaunch("slottest-3")
	if err != nil {
		t.Fatalf("ResolveAliasForLaunch(\"slottest-3\") returned error: %v", err)
	}
	if resolved.Slot != 3 {
		t.Errorf("Slot = %d, want 3", resolved.Slot)
	}
}

// An alias whose name ends in -<digits> (valid per ValidateAlias) must
// resolve as the whole name first; the -N slot split applies only when no
// alias has that whole name.

func TestResolveAliasForLaunch_WholeNameWinsOverSlotSuffix(t *testing.T) {
	tmpHome := withTempHome(t)
	t.Chdir(t.TempDir()) // CWD without .coi/config.toml: no fallback

	reg, err := LoadFrom(filepath.Join(tmpHome, ".coi", "aliases.json"))
	if err != nil {
		t.Fatal(err)
	}
	for a, ws := range map[string]string{"app-2": "/ws/a", "app": "/ws/b", "site-2025": "/ws/s", "web": "/ws/w"} {
		if err := reg.Register(a, ws, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		arg       string
		workspace string
		slot      int
	}{
		{"app-2", "/ws/a", 0},     // whole name is an alias: no split (master: /ws/b, slot 2)
		{"app-2-3", "/ws/a", 3},   // no alias "app-2-3": split to alias app-2, slot 3
		{"site-2025", "/ws/s", 0}, // master: error, alias "site" not found
		{"app-3", "/ws/b", 3},     // no alias "app-3": split to alias app, slot 3
		{"web-2", "/ws/w", 2},     // plain alias-N keeps working
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, err := ResolveAliasForLaunch(tt.arg)
			if err != nil {
				t.Fatalf("ResolveAliasForLaunch(%q) error: %v", tt.arg, err)
			}
			if got.Workspace != tt.workspace || got.Slot != tt.slot {
				t.Errorf("ResolveAliasForLaunch(%q) = {%s, slot %d}, want {%s, slot %d}",
					tt.arg, got.Workspace, got.Slot, tt.workspace, tt.slot)
			}
		})
	}
}

func TestResolveAliasForLaunch_CWDFallback_WholeNameWithDigits(t *testing.T) {
	withTempHome(t)
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".coi", "config.toml"), []byte("[container]\nalias = \"app-2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workspace)

	got, err := ResolveAliasForLaunch("app-2") // master: alias "app" not found
	if err != nil {
		t.Fatalf("ResolveAliasForLaunch(\"app-2\") error: %v", err)
	}
	abs, _ := filepath.Abs(workspace)
	if got.Workspace != abs || got.Slot != 0 {
		t.Errorf("got {%s, slot %d}, want {%s, slot 0}", got.Workspace, got.Slot, abs)
	}
}

// fakeIncus puts an `incus` on PATH that answers `list` with listJSON.
func fakeIncus(t *testing.T, listJSON string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(listJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat " + filepath.Join(dir, "list.json") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestResolveAliasForRunning_WholeNameWinsOverSlotSuffix(t *testing.T) {
	withTempHome(t)
	fakeIncus(t, `[
 {"name":"coi-aaaaaaaa-1","status":"Running","config":{"user.coi.alias":"app-2"}},
 {"name":"coi-bbbbbbbb-1","status":"Running","config":{"user.coi.alias":"app"}},
 {"name":"coi-bbbbbbbb-2","status":"Running","config":{"user.coi.alias":"app"}},
 {"name":"coi-cccccccc-1","status":"Running","config":{"user.coi.alias":"site-2025"}}
]`)
	tests := map[string]string{
		"app-2":     "coi-aaaaaaaa-1", // master: coi-bbbbbbbb-2 (other workspace)
		"site-2025": "coi-cccccccc-1", // master: error, alias "site" not found
		"app-1":     "coi-bbbbbbbb-1", // no alias "app-1": split still works
	}
	for arg, want := range tests {
		t.Run(arg, func(t *testing.T) {
			got, err := ResolveAliasForRunning(arg)
			if err != nil {
				t.Fatalf("ResolveAliasForRunning(%q) error: %v", arg, err)
			}
			if got != want {
				t.Errorf("ResolveAliasForRunning(%q) = %q, want %q", arg, got, want)
			}
		})
	}
}

func TestResolveAliasForRunning_RegisteredStoppedAliasNotSplit(t *testing.T) {
	tmpHome := withTempHome(t)
	reg, err := LoadFrom(filepath.Join(tmpHome, ".coi", "aliases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("app-2", "/ws/a", ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}
	fakeIncus(t, `[
 {"name":"coi-aaaaaaaa-1","status":"Stopped","config":{"user.coi.alias":"app-2"}},
 {"name":"coi-bbbbbbbb-2","status":"Running","config":{"user.coi.alias":"app"}}
]`)

	got, err := ResolveAliasForRunning("app-2")
	if err == nil {
		t.Fatalf("ResolveAliasForRunning(\"app-2\") = %q, want error", got)
	}
	if !strings.Contains(err.Error(), `"app-2" not found`) {
		t.Errorf("error = %q, want it to name alias \"app-2\"", err)
	}
}

func TestResolveAliasForRunning_SlotZeroNotSplit(t *testing.T) {
	withTempHome(t)
	fakeIncus(t, `[
 {"name":"coi-bbbbbbbb-1","status":"Running","config":{"user.coi.alias":"app"}}
]`)

	got, err := ResolveAliasForRunning("app-0")
	if err == nil {
		t.Fatalf("ResolveAliasForRunning(\"app-0\") = %q, want error", got)
	}
}

func TestResolveAliasForRunning_UnreadableRegistryNotSplit(t *testing.T) {
	tmpHome := withTempHome(t)
	if err := os.MkdirAll(filepath.Join(tmpHome, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".coi", "aliases.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeIncus(t, `[
 {"name":"coi-bbbbbbbb-2","status":"Running","config":{"user.coi.alias":"app"}}
]`)

	got, err := ResolveAliasForRunning("app-2")
	if err == nil {
		t.Fatalf("ResolveAliasForRunning(\"app-2\") = %q, want error", got)
	}
}

func TestResolveAliasForLaunch_SlotZeroNotSplit(t *testing.T) {
	tmpHome := withTempHome(t)
	t.Chdir(t.TempDir()) // CWD without .coi/config.toml: no fallback

	reg, err := LoadFrom(filepath.Join(tmpHome, ".coi", "aliases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register("app", "/ws/b", ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.Save(); err != nil {
		t.Fatal(err)
	}

	if got, err := ResolveAliasForLaunch("app-0"); err == nil {
		t.Errorf("ResolveAliasForLaunch(\"app-0\") = {%s, slot %d}, want error", got.Workspace, got.Slot)
	}

	got, err := ResolveAliasForLaunch("app-1")
	if err != nil {
		t.Fatalf("ResolveAliasForLaunch(\"app-1\") error: %v", err)
	}
	if got.Workspace != "/ws/b" || got.Slot != 1 {
		t.Errorf("ResolveAliasForLaunch(\"app-1\") = {%s, slot %d}, want {/ws/b, slot 1}", got.Workspace, got.Slot)
	}
}
