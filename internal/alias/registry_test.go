package alias

import (
	"os"
	"path/filepath"
	"testing"
)

func tempRegistryPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "aliases.json")
}

func TestRegister_NewAlias(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	err := r.Register("myproject", "/home/user/projects/myproject", "")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	entry := r.Lookup("myproject")
	if entry == nil {
		t.Fatal("Lookup returned nil for registered alias")
	}
	if entry.Workspace != "/home/user/projects/myproject" {
		t.Errorf("Workspace = %q, want %q", entry.Workspace, "/home/user/projects/myproject")
	}
}

func TestRegister_SameWorkspace_Idempotent(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if err := r.Register("myproject", "/workspace/a", ""); err != nil {
		t.Fatal(err)
	}
	// Re-register same alias+workspace should succeed
	if err := r.Register("myproject", "/workspace/a", ""); err != nil {
		t.Fatalf("Re-register same workspace should succeed, got: %v", err)
	}
}

func TestRegister_DifferentWorkspace_Conflict(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if err := r.Register("myproject", "/workspace/a", ""); err != nil {
		t.Fatal(err)
	}
	err := r.Register("myproject", "/workspace/b", "")
	if err == nil {
		t.Fatal("Expected conflict error when registering same alias for different workspace")
	}
}

func TestRegisterWorkspace_KeepsSavedProfile(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if err := r.Register("myproject", "/workspace/a", "pa"); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterWorkspace("myproject", "/workspace/a"); err != nil {
		t.Fatalf("RegisterWorkspace failed: %v", err)
	}
	if entry := r.Lookup("myproject"); entry == nil || entry.Profile != "pa" {
		t.Errorf("RegisterWorkspace must keep the saved profile, got %+v", entry)
	}

	// A non-empty profile from Register still replaces it.
	if err := r.Register("myproject", "/workspace/a", "pb"); err != nil {
		t.Fatal(err)
	}
	if entry := r.Lookup("myproject"); entry == nil || entry.Profile != "pb" {
		t.Errorf("Register must replace the saved profile, got %+v", entry)
	}
}

func TestRegisterWorkspace_NewAlias(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if err := r.RegisterWorkspace("myproject", "/workspace/a"); err != nil {
		t.Fatalf("RegisterWorkspace failed: %v", err)
	}
	if entry := r.Lookup("myproject"); entry == nil || entry.Workspace != "/workspace/a" || entry.Profile != "" {
		t.Errorf("unexpected entry %+v", entry)
	}
}

func TestRegisterWorkspace_DifferentWorkspace_Conflict(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if err := r.Register("myproject", "/workspace/a", "pa"); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterWorkspace("myproject", "/workspace/b"); err == nil {
		t.Fatal("Expected conflict error when registering same alias for different workspace")
	}
	if entry := r.Lookup("myproject"); entry == nil || entry.Workspace != "/workspace/a" || entry.Profile != "pa" {
		t.Errorf("a conflict must leave the entry unchanged, got %+v", entry)
	}
}

func TestLookup_Found(t *testing.T) {
	r := &Registry{
		path: tempRegistryPath(t),
		entries: map[string]AliasEntry{
			"test": {Workspace: "/ws", Profile: "dev"},
		},
	}

	entry := r.Lookup("test")
	if entry == nil {
		t.Fatal("Lookup returned nil")
	}
	if entry.Profile != "dev" {
		t.Errorf("Profile = %q, want %q", entry.Profile, "dev")
	}
}

func TestLookup_NotFound(t *testing.T) {
	r := &Registry{
		path:    tempRegistryPath(t),
		entries: make(map[string]AliasEntry),
	}

	if entry := r.Lookup("nonexistent"); entry != nil {
		t.Errorf("Expected nil for nonexistent alias, got %+v", entry)
	}
}

func TestSaveLoad_Roundtrip(t *testing.T) {
	path := tempRegistryPath(t)

	// Create and save
	r := &Registry{
		path:    path,
		entries: make(map[string]AliasEntry),
	}
	_ = r.Register("proj1", "/workspace/one", "dev")
	_ = r.Register("proj2", "/workspace/two", "")

	if err := r.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load back
	r2, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(r2.entries) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(r2.entries))
	}

	entry := r2.Lookup("proj1")
	if entry == nil || entry.Workspace != "/workspace/one" || entry.Profile != "dev" {
		t.Errorf("proj1 roundtrip mismatch: %+v", entry)
	}

	entry = r2.Lookup("proj2")
	if entry == nil || entry.Workspace != "/workspace/two" {
		t.Errorf("proj2 roundtrip mismatch: %+v", entry)
	}
}

func TestLoadFrom_NonexistentFile(t *testing.T) {
	r, err := LoadFrom("/nonexistent/path/aliases.json")
	if err != nil {
		t.Fatalf("LoadFrom nonexistent should return empty registry, got error: %v", err)
	}
	if len(r.entries) != 0 {
		t.Error("Expected empty registry for nonexistent file")
	}
}

func TestLoadFrom_EmptyFile(t *testing.T) {
	path := tempRegistryPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom empty file should succeed, got: %v", err)
	}
	if len(r.entries) != 0 {
		t.Error("Expected empty registry for empty file")
	}
}

func TestValidateAlias(t *testing.T) {
	tests := []struct {
		alias string
		valid bool
	}{
		{"", true},             // empty is valid (no alias)
		{"myproject", true},    // simple
		{"my-project", true},   // hyphens
		{"my_project", true},   // underscores
		{"MyProject123", true}, // mixed case + digits
		{"a", true},            // single letter
		{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901", true}, // 64 chars
		{"123project", false}, // starts with digit
		{"my project", false}, // space
		{"my.project", false}, // dot
		{"my!project", false}, // special char
		{"-myproject", false}, // starts with hyphen
		{"_myproject", false}, // starts with underscore
		{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789012", false}, // 65 chars (too long)
	}

	for _, tt := range tests {
		err := ValidateAlias(tt.alias)
		if tt.valid && err != nil {
			t.Errorf("ValidateAlias(%q) = %v, want valid", tt.alias, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateAlias(%q) = nil, want error", tt.alias)
		}
	}
}

func TestSplitAliasSlot(t *testing.T) {
	tests := []struct {
		input     string
		wantAlias string
		wantSlot  int
	}{
		{"myproject", "myproject", 0},
		{"myproject-2", "myproject", 2},
		{"myproject-10", "myproject", 10},
		{"my-project-3", "my-project", 3},
		{"myproject-abc", "myproject-abc", 0}, // non-numeric suffix
		{"-1", "-1", 0},                       // no base alias
		{"a-0", "a", 0},                       // slot 0 (treated as no slot)
	}

	for _, tt := range tests {
		gotAlias, gotSlot := splitAliasSlot(tt.input)
		if gotAlias != tt.wantAlias || gotSlot != tt.wantSlot {
			t.Errorf("splitAliasSlot(%q) = (%q, %d), want (%q, %d)",
				tt.input, gotAlias, gotSlot, tt.wantAlias, tt.wantSlot)
		}
	}
}

func TestIsContainerName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"coi-a1b2c3d4-1", true},
		{"coi-abcdef12-10", true},
		{"coi-00000000-1", true},
		{"myproject", false},
		{"coi-short-1", true},     // starts with prefix → treated as container name
		{"coi-a1b2c3d4", true},    // starts with prefix → treated as container name
		{"coi-a1b2c3d4-", true},   // starts with prefix → treated as container name
		{"coi-nonexistent", true}, // starts with prefix → treated as container name
		{"other-a1b2c3d4-1", false},
	}

	for _, tt := range tests {
		// Override pattern for test (since COI_CONTAINER_PREFIX might be set)
		got := IsContainerName(tt.name)
		if os.Getenv("COI_CONTAINER_PREFIX") == "" && got != tt.want {
			t.Errorf("IsContainerName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
