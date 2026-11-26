package session

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

func TestPathToDeviceName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{".git/hooks", "protect-git-hooks"},
		{".git/config", "protect-git-config"},
		{".husky", "protect-husky"},
		{".vscode", "protect-vscode"},
		{".idea", "protect-idea"},
		{"some/deep/path", "protect-some-deep-path"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pathToDeviceName(tt.path)
			if result != tt.expected {
				t.Errorf("pathToDeviceName(%q) = %q, expected %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestPathToDeviceName_IncusValidity(t *testing.T) {
	// Incus 7.6 IsDeviceName (IsAPIName plus the charset), capped at the 6.x
	// limit of 63 characters.
	valid := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	unchanged := map[string]string{
		"Src_Dir2/Build-9":      "protect-Src_Dir2-Build-9",
		strings.Repeat("x", 55): "protect-" + strings.Repeat("x", 55),
	}
	for p, want := range unchanged {
		if got := pathToDeviceName(p); got != want {
			t.Errorf("pathToDeviceName(%q) = %q, expected %q", p, got, want)
		}
	}

	hashed := []string{
		"node_modules/@scope/pkg",
		"a:b",
		"my dir",
		"żółw",
		"a+b",
		"a~b",
		"a[b",
		"__pycache__",
		"build-",
		strings.Repeat("x", 56),
	}
	seen := map[string]string{}
	for _, p := range hashed {
		name := pathToDeviceName(p)
		if !valid.MatchString(name) {
			t.Errorf("pathToDeviceName(%q) = %q, not a valid Incus device name", p, name)
		}
		if !strings.HasPrefix(name, protectDevicePrefix) || len(name) != len(protectDevicePrefix)+16 {
			t.Errorf("pathToDeviceName(%q) = %q, expected a hashed %q name", p, name, protectDevicePrefix)
		}
		if prev, ok := seen[name]; ok {
			t.Errorf("pathToDeviceName(%q) and (%q) collide: %q", p, prev, name)
		}
		seen[name] = p
	}
}

func TestIsFileTypeProtected(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{".git/config", true},
		{".git/hooks", false},
		{".husky", false},
		{".vscode", false},
		{".idea", false},
		{"Makefile", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isFileTypeProtected(tt.path)
			if result != tt.expected {
				t.Errorf("isFileTypeProtected(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsDirTypeProtected(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{".git/hooks", true},
		{".husky", true},
		{".vscode", true},
		{".git/config", false},
		{".idea", false},
		{"Makefile", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isDirTypeProtected(tt.path)
			if result != tt.expected {
				t.Errorf("isDirTypeProtected(%q) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestSetupSecurityMounts_EmptyPaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Empty paths should return nil
	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Errorf("Expected nil error for empty paths, got: %v", err)
	}

	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", nil, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Errorf("Expected nil error for nil paths, got: %v", err)
	}
}

func TestSetupSecurityMounts_NonExistentPaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// In a non-git workspace, .git/hooks and .git/config are silently
	// skipped by the .git guard, so SetupSecurityMounts returns nil
	// even with a nil manager (MountDisk is never reached).
	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace",
		[]string{".git/hooks", ".git/config"}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Errorf("Expected nil error when .git is missing, got: %v", err)
	}

	// Confirm the .git guard did NOT synthesize a .git/ directory.
	if _, statErr := os.Lstat(filepath.Join(tmpDir, ".git")); !os.IsNotExist(statErr) {
		t.Errorf(".git/ should not have been created in a non-git workspace, stat err=%v", statErr)
	}
}

func TestSetupSecurityMounts_SymlinkRejection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a target directory
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}

	// Create .vscode as a symlink
	vscodeDir := filepath.Join(tmpDir, ".vscode")
	if err := os.Symlink(targetDir, vscodeDir); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Should return error for symlinked paths
	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{".vscode"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Error("Expected error for symlinked path, got nil")
	}
}

// A root protected path below a symlinked dir is refused.
func TestPrepareProtectedPath_SymlinkedParentDir(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	mkGitDir(t, ws, ".git")
	if err := os.WriteFile(filepath.Join(outside, "attributes"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := filepath.Join(ws, ".git", "info")
	if err := os.RemoveAll(info); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, info); err != nil {
		t.Fatal(err)
	}

	_, err := prepareProtectedPath(ws, "/workspace", ".git/info/attributes", false, nil)
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Errorf("err = %v; want a symlinked parent error", err)
	}
}

// A shared realDirs still finds a symlinked dir next to a checked one.
func TestRealDirs_SymlinkedParentNextToChecked(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(ws, "a", "c")); err != nil {
		t.Fatal(err)
	}

	dirs := realDirs{}
	if got := dirs.symlinkedParent(ws, "a/b/x"); got != "" {
		t.Errorf("a/b/x: %q; want none", got)
	}
	if got := dirs.symlinkedParent(ws, "a/c/d/x"); got != filepath.Join("a", "c") {
		t.Errorf("a/c/d/x: %q; want a/c", got)
	}
	if dirs[filepath.Join("a", "c")] {
		t.Error("symlinked a/c cached as a real dir")
	}
}

// A protected path that is, or lies below, a symlink is refused with a
// warning; the later paths, the nested batch and the pins are still mounted.
func TestSetupSecurityMounts_SymlinkRefusalKeepsLaterPaths(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	mkGitDir(t, ws, ".git/modules/lib")
	for _, d := range []string{"shared", "docs/claude"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"shared/attributes", "docs/claude/settings.json"} {
		if err := os.WriteFile(filepath.Join(ws, f), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(ws, ".git", "info")); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{".git/info": "../shared", ".claude": "docs/claude", ".vscode": "docs"} {
		if err := os.Symlink(target, filepath.Join(ws, link)); err != nil {
			t.Fatal(err)
		}
	}

	dev := &batchDevices{}
	refused := []string{".git/info/attributes", ".claude/settings.json", ".vscode"}
	paths := append(append([]string(nil), refused...), ".git/hooks", ".git/config", ".codex/config.toml")
	_, err := SetupSecurityMounts(dev, ws, "/workspace", paths, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("want warnings for the symlinked paths")
	}
	for _, rel := range refused {
		if !strings.Contains(err.Error(), rel+": refusing to mount through a symlink") {
			t.Errorf("no warning for %s in %v", rel, err)
		}
	}
	var mounted []string
	for _, m := range dev.mounts {
		mounted = append(mounted, strings.TrimPrefix(m.path, "/workspace/"))
	}
	assertContainsAll(t, mounted, []string{".git/hooks", ".git/config", ".codex/config.toml"})
	for _, rel := range refused {
		if slices.Contains(mounted, rel) {
			t.Errorf("symlinked %s mounted", rel)
		}
	}
	if len(dev.batches) != 1 || !slices.ContainsFunc(dev.batches[0], func(m container.DiskMount) bool {
		return m.Path == "/workspace/.git/modules/lib/config"
	}) {
		t.Errorf("nested batch not mounted: %v", dev.batches)
	}
}

func TestSetupSecurityMounts_GitSymlinkWarns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a target directory
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}

	// Create .git as a symlink (simulating a worktree)
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Symlink(targetDir, gitDir); err != nil {
		t.Fatalf("Failed to create .git symlink: %v", err)
	}

	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{".git/hooks"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("Expected warning error when .git is symlink, got nil")
	}
	if !strings.Contains(err.Error(), ".git is a symlink") {
		t.Errorf("Expected .git symlink warning, got: %v", err)
	}
}

func TestSetupSecurityMounts_GitFileWarns(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create .git as a file (simulating a worktree/submodule)
	gitFile := filepath.Join(tmpDir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: /some/path"), 0o644); err != nil {
		t.Fatalf("Failed to create .git file: %v", err)
	}

	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{".git/hooks"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("Expected warning error when .git is file, got nil")
	}
	if !strings.Contains(err.Error(), ".git is a file") {
		t.Errorf("Expected .git file warning, got: %v", err)
	}
}

func TestSetupSecurityMounts_GitFileWarningDoesNotSkipOtherPaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, ".git"), []byte("gitdir: /some/path"), 0o644); err != nil {
		t.Fatalf("Failed to create .git file: %v", err)
	}
	vscodeDir := filepath.Join(tmpDir, ".vscode")
	if err := os.Mkdir(vscodeDir, 0o755); err != nil {
		t.Fatalf("Failed to create .vscode: %v", err)
	}

	rec := &recordingDevices{}
	_, err = SetupSecurityMounts(rec, tmpDir, "/workspace", []string{".git/hooks", ".vscode"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("Expected warning error when .git is file, got nil")
	}
	if len(rec.mounts) != 1 {
		t.Fatalf("Expected one non-git protected mount, got %d", len(rec.mounts))
	}
	if rec.mounts[0].path != "/workspace/.vscode" {
		t.Errorf("Expected .vscode to remain protected, got mount path %q", rec.mounts[0].path)
	}
}

func TestGetProtectedPathsForLogging(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some paths
	os.MkdirAll(filepath.Join(tmpDir, ".git", "hooks"), 0o755)
	os.MkdirAll(filepath.Join(tmpDir, ".vscode"), 0o755)

	// Create a symlink (should be excluded)
	os.Mkdir(filepath.Join(tmpDir, "target"), 0o755)
	os.Symlink(filepath.Join(tmpDir, "target"), filepath.Join(tmpDir, ".husky"))

	paths := GetProtectedPathsForLogging(tmpDir, []string{".git/hooks", ".vscode", ".husky", ".idea"})

	// Should include .git/hooks and .vscode, but not .husky (symlink) or .idea (non-existent)
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d: %v", len(paths), paths)
	}

	found := make(map[string]bool)
	for _, p := range paths {
		found[p] = true
	}

	if !found[".git/hooks"] {
		t.Error("Expected .git/hooks in paths")
	}
	if !found[".vscode"] {
		t.Error("Expected .vscode in paths")
	}
	if found[".husky"] {
		t.Error("Should not include .husky (symlink)")
	}
	if found[".idea"] {
		t.Error("Should not include .idea (non-existent)")
	}
}

func TestDefaultProtectedPaths(t *testing.T) {
	cfg := config.GetDefaultConfig()
	paths := cfg.Security.ProtectedPaths

	expected := []string{
		".git/hooks", ".git/config", ".git/config.worktree", ".git/info/attributes",
		".git/commondir", ".husky", ".vscode", ".coi", ".claude/settings.json", ".claude/settings.local.json",
		".codex/config.toml",
	}

	if len(paths) != len(expected) {
		t.Errorf("Expected %d default paths, got %d", len(expected), len(paths))
	}

	pathMap := make(map[string]bool)
	for _, p := range paths {
		pathMap[p] = true
	}

	for _, exp := range expected {
		if !pathMap[exp] {
			t.Errorf("Expected %q in default protected paths", exp)
		}
	}
}

func TestSecurityConfig_GetEffectiveProtectedPaths(t *testing.T) {
	t.Run("default paths", func(t *testing.T) {
		cfg := &config.SecurityConfig{
			ProtectedPaths:           []string{".git/hooks", ".git/config", ".husky", ".vscode"},
			AdditionalProtectedPaths: []string{},
			DisableProtection:        false,
		}

		paths := cfg.GetEffectiveProtectedPaths()
		if len(paths) != 4 {
			t.Errorf("Expected 4 paths, got %d", len(paths))
		}
	})

	t.Run("with additional paths", func(t *testing.T) {
		cfg := &config.SecurityConfig{
			ProtectedPaths:           []string{".git/hooks", ".git/config", ".husky", ".vscode"},
			AdditionalProtectedPaths: []string{".idea", "Makefile"},
			DisableProtection:        false,
		}

		paths := cfg.GetEffectiveProtectedPaths()
		if len(paths) != 6 {
			t.Errorf("Expected 6 paths, got %d", len(paths))
		}
	})

	t.Run("disabled protection", func(t *testing.T) {
		cfg := &config.SecurityConfig{
			ProtectedPaths:           []string{".git/hooks", ".git/config", ".husky", ".vscode"},
			AdditionalProtectedPaths: []string{".idea"},
			DisableProtection:        true,
		}

		paths := cfg.GetEffectiveProtectedPaths()
		if paths != nil {
			t.Errorf("Expected nil paths when disabled, got %v", paths)
		}
	})

	t.Run("custom paths replace defaults", func(t *testing.T) {
		cfg := &config.SecurityConfig{
			ProtectedPaths:           []string{".git/hooks"},
			AdditionalProtectedPaths: []string{},
			DisableProtection:        false,
		}

		paths := cfg.GetEffectiveProtectedPaths()
		if len(paths) != 1 {
			t.Errorf("Expected 1 path, got %d", len(paths))
		}
		if paths[0] != ".git/hooks" {
			t.Errorf("Expected .git/hooks, got %s", paths[0])
		}
	})
}

func TestSetupGitHooksMount_HooksDirCreation(t *testing.T) {
	// Test that SetupGitHooksMount creates the hooks dir if missing
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create .git directory (simulating a git repo)
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}

	hooksDir := filepath.Join(gitDir, "hooks")

	// Verify hooks dir doesn't exist yet
	if _, err := os.Stat(hooksDir); !os.IsNotExist(err) {
		t.Fatal("Hooks dir should not exist yet")
	}

	// Simulate what SetupSecurityMounts does
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("Failed to create hooks dir: %v", err)
	}

	// Verify hooks dir was created
	info, err := os.Stat(hooksDir)
	if err != nil {
		t.Fatalf("Failed to stat hooks dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("Hooks path should be a directory")
	}
}

func TestSetupGitHooksMount_PreservesExistingHooks(t *testing.T) {
	// Test that existing hooks are not deleted during setup
	tmpDir, err := os.MkdirTemp("", "security-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create .git/hooks directory with a sample hook
	hooksDir := filepath.Join(tmpDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("Failed to create hooks dir: %v", err)
	}

	hookContent := "#!/bin/sh\necho 'pre-commit hook'\n"
	hookFile := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookFile, []byte(hookContent), 0o755); err != nil {
		t.Fatalf("Failed to create hook file: %v", err)
	}

	// Simulate MkdirAll (what SetupSecurityMounts does)
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Verify hook file still exists
	content, err := os.ReadFile(hookFile)
	if err != nil {
		t.Fatalf("Failed to read hook file: %v", err)
	}

	if string(content) != hookContent {
		t.Errorf("Hook content was modified. Expected %q, got %q", hookContent, string(content))
	}
}

func TestEnsureProtectedExists_CreatesMissingDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vscodePath := filepath.Join(tmpDir, ".vscode")
	if err := ensureProtectedExists(tmpDir, vscodePath, ".vscode"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	info, err := os.Stat(vscodePath)
	if err != nil {
		t.Fatalf("Expected .vscode to exist, got err: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("Expected .vscode to be a directory")
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("Expected mode 0755, got %o", info.Mode().Perm())
	}
}

func TestEnsureProtectedExists_CreatesMissingHuskyDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	huskyPath := filepath.Join(tmpDir, ".husky")
	if err := ensureProtectedExists(tmpDir, huskyPath, ".husky"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	info, err := os.Stat(huskyPath)
	if err != nil {
		t.Fatalf("Expected .husky to exist, got err: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("Expected .husky to be a directory")
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("Expected mode 0755, got %o", info.Mode().Perm())
	}
}

func TestEnsureProtectedExists_PreservesExistingDir(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vscodePath := filepath.Join(tmpDir, ".vscode")
	if err := os.MkdirAll(vscodePath, 0o755); err != nil {
		t.Fatalf("Failed to pre-create .vscode: %v", err)
	}

	tasksPath := filepath.Join(vscodePath, "tasks.json")
	original := []byte(`{"version": "2.0.0", "tasks": []}` + "\n")
	if err := os.WriteFile(tasksPath, original, 0o644); err != nil {
		t.Fatalf("Failed to write tasks.json: %v", err)
	}

	if err := ensureProtectedExists(tmpDir, vscodePath, ".vscode"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	after, err := os.ReadFile(tasksPath)
	if err != nil {
		t.Fatalf("Failed to read tasks.json after call: %v", err)
	}
	if string(after) != string(original) {
		t.Errorf("tasks.json content changed: got %q, want %q", after, original)
	}
}

func TestEnsureProtectedExists_PreservesExistingFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatalf("Failed to create .git: %v", err)
	}

	configPath := filepath.Join(gitDir, "config")
	original := []byte("[core]\n\trepositoryformatversion = 0\n")
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatalf("Failed to write .git/config: %v", err)
	}

	if err := ensureProtectedExists(tmpDir, configPath, ".git/config"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read .git/config after call: %v", err)
	}
	if string(after) != string(original) {
		t.Errorf(".git/config content changed: got %q, want %q", after, original)
	}
}

func TestEnsureProtectedExists_CreatesFilePlaceholderWhenParentExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatalf("Failed to create .git: %v", err)
	}

	configPath := filepath.Join(gitDir, "config")
	if err := ensureProtectedExists(tmpDir, configPath, ".git/config"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	info, err := os.Lstat(configPath)
	if err != nil {
		t.Fatalf("Expected .git/config placeholder to exist, got err: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("Expected regular file, got mode %v", info.Mode())
	}
	if info.Size() != 0 {
		t.Errorf("Expected empty placeholder, got size %d", info.Size())
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("Expected mode 0644, got %o", info.Mode().Perm())
	}
}

func TestEnsureProtectedExists_FilePlaceholderParentMissing(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// .git/ does NOT exist
	configPath := filepath.Join(tmpDir, ".git", "config")
	err = ensureProtectedExists(tmpDir, configPath, ".git/config")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected os.ErrNotExist, got %v", err)
	}

	// .git/ must not have been created.
	if _, statErr := os.Lstat(filepath.Join(tmpDir, ".git")); !os.IsNotExist(statErr) {
		t.Errorf(".git/ should not be created when parent is missing, stat err=%v", statErr)
	}
}

// .claude/settings.json must be materialized even when the .claude dir is
// absent (the planting case): the parent dir is auto-created (writable) and the
// settings file gets an empty read-only placeholder. Regression for #504 — an
// agent must not be able to plant an absent settings file.
func TestEnsureProtectedExists_ClaudeSettingsCreatesParentAndPlaceholder(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// .claude/ does NOT exist yet.
	settingsPath := filepath.Join(tmpDir, ".claude", "settings.json")
	if err := ensureProtectedExists(tmpDir, settingsPath, ".claude/settings.json"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	// .claude/ was auto-created as a real directory.
	dirInfo, err := os.Lstat(filepath.Join(tmpDir, ".claude"))
	if err != nil || !dirInfo.IsDir() {
		t.Fatalf("expected .claude/ to be auto-created as a dir, info=%v err=%v", dirInfo, err)
	}
	// The settings file is an empty regular placeholder ready for the RO mount.
	info, err := os.Lstat(settingsPath)
	if err != nil {
		t.Fatalf("expected .claude/settings.json placeholder, got err: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		t.Errorf("expected empty regular placeholder, got mode=%v size=%d", info.Mode(), info.Size())
	}
}

// When .claude already exists but the settings file is absent, the placeholder
// is still materialized (parent already present).
func TestEnsureProtectedExists_ClaudeSettingsPlaceholderWhenDirExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := os.Mkdir(filepath.Join(tmpDir, ".claude"), 0o755); err != nil {
		t.Fatalf("Failed to create .claude: %v", err)
	}

	localPath := filepath.Join(tmpDir, ".claude", "settings.local.json")
	if err := ensureProtectedExists(tmpDir, localPath, ".claude/settings.local.json"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}
	info, err := os.Lstat(localPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Errorf("expected empty regular placeholder, info=%v err=%v", info, err)
	}
}

// .codex/config.toml gets the same planting protection as the Claude settings
// files (#698): parent auto-created, empty read-only placeholder materialized —
// a contained agent must not be able to plant project-scoped codex config that
// a host codex session could auto-execute (notify commands, MCP launchers).
func TestEnsureProtectedExists_CodexConfigCreatesParentAndPlaceholder(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// .codex/ does NOT exist yet.
	configPath := filepath.Join(tmpDir, ".codex", "config.toml")
	if err := ensureProtectedExists(tmpDir, configPath, ".codex/config.toml"); err != nil {
		t.Fatalf("ensureProtectedExists returned error: %v", err)
	}

	dirInfo, err := os.Lstat(filepath.Join(tmpDir, ".codex"))
	if err != nil || !dirInfo.IsDir() {
		t.Fatalf("expected .codex/ to be auto-created as a dir, info=%v err=%v", dirInfo, err)
	}
	info, err := os.Lstat(configPath)
	if err != nil {
		t.Fatalf("expected .codex/config.toml placeholder, got err: %v", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 {
		t.Errorf("expected empty regular placeholder, got mode=%v size=%d", info.Mode(), info.Size())
	}
}

func TestEnsureProtectedExists_SymlinkNotFollowed(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real sibling target directory
	targetDir := filepath.Join(tmpDir, "target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatalf("Failed to create target dir: %v", err)
	}

	// Create .vscode as a symlink to the target
	vscodePath := filepath.Join(tmpDir, ".vscode")
	if err := os.Symlink(targetDir, vscodePath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	if err := ensureProtectedExists(tmpDir, vscodePath, ".vscode"); err != nil {
		t.Errorf("ensureProtectedExists returned error for existing symlink: %v", err)
	}

	// Verify the symlink itself is unchanged (still a symlink).
	info, err := os.Lstat(vscodePath)
	if err != nil {
		t.Fatalf("Failed to Lstat .vscode: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Expected .vscode to remain a symlink, got mode %v", info.Mode())
	}
}

func TestEnsureProtectedExists_UserAddedMissingDirNotCreated(t *testing.T) {
	// A user-added missing directory-type path (e.g. ".idea") must NOT be
	// auto-materialized. Returns os.ErrNotExist so the caller skips silently.
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ideaPath := filepath.Join(tmpDir, ".idea")
	err = ensureProtectedExists(tmpDir, ideaPath, ".idea")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected os.ErrNotExist for user-added missing path, got %v", err)
	}
	if _, statErr := os.Lstat(ideaPath); !os.IsNotExist(statErr) {
		t.Errorf(".idea must not be created for user-added missing path, stat err=%v", statErr)
	}
}

func TestEnsureProtectedExists_UserAddedMissingMakefileNotCreatedAsDir(t *testing.T) {
	// The copilot-flagged regression: a user-added "Makefile" must NOT be
	// created as a directory (which would break the user's build).
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	makefilePath := filepath.Join(tmpDir, "Makefile")
	err = ensureProtectedExists(tmpDir, makefilePath, "Makefile")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected os.ErrNotExist for missing Makefile, got %v", err)
	}
	if _, statErr := os.Lstat(makefilePath); !os.IsNotExist(statErr) {
		t.Errorf("Makefile must not be created, stat err=%v", statErr)
	}
}

func TestEnsureProtectedExists_PreservesExistingUserAddedDir(t *testing.T) {
	// A user-added directory that DOES already exist must be left alone
	// (returns nil, doesn't clobber) so the caller can mount it RO.
	tmpDir, err := os.MkdirTemp("", "ensure-exists-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	ideaPath := filepath.Join(tmpDir, ".idea")
	if err := os.Mkdir(ideaPath, 0o755); err != nil {
		t.Fatalf("Failed to pre-create .idea: %v", err)
	}
	marker := filepath.Join(ideaPath, "workspace.xml")
	if err := os.WriteFile(marker, []byte("<project/>"), 0o644); err != nil {
		t.Fatalf("Failed to write marker: %v", err)
	}

	if err := ensureProtectedExists(tmpDir, ideaPath, ".idea"); err != nil {
		t.Errorf("Expected nil for existing user-added path, got %v", err)
	}

	content, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker file disappeared: %v", err)
	}
	if string(content) != "<project/>" {
		t.Errorf("marker content changed: got %q", string(content))
	}
}

func TestValidateRelPath(t *testing.T) {
	tests := []struct {
		name    string
		relPath string
		wantErr bool
	}{
		{"valid simple", ".vscode", false},
		{"valid nested", ".git/hooks", false},
		{"empty", "", true},
		{"absolute", "/etc/passwd", true},
		{"dotdot", "..", true},
		{"dot", ".", true},
		{"leading dotdot", "../etc", true},
		{"inner dotdot", "foo/../bar", true},
		{"trailing dotdot", "foo/..", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRelPath(tt.relPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRelPath(%q) err=%v, wantErr=%v", tt.relPath, err, tt.wantErr)
			}
		})
	}
}

func TestSafeMkdirAll_RejectsSymlinkedParent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "safe-mkdir-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a sibling target directory outside the "workspace".
	outsideDir, err := os.MkdirTemp("", "outside-*")
	if err != nil {
		t.Fatalf("Failed to create outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)

	// Create a symlink inside the workspace pointing outside.
	linkPath := filepath.Join(tmpDir, "evil")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Attempting to create a child under the symlinked parent must be rejected.
	target := filepath.Join(tmpDir, "evil", "child")
	err = safeMkdirAll(tmpDir, target, "evil/child")
	if err == nil {
		t.Fatal("safeMkdirAll should have rejected symlinked parent, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("Expected symlink-related error, got: %v", err)
	}

	// The target must not exist under the symlink target either.
	if _, statErr := os.Lstat(filepath.Join(outsideDir, "child")); !os.IsNotExist(statErr) {
		t.Errorf("target must not be created outside workspace, stat err=%v", statErr)
	}
}

func TestSetupProtectedPath_RejectsAbsolutePath(t *testing.T) {
	// Absolute path in protected_paths must be rejected (non-ErrNotExist,
	// so the caller surfaces the error rather than skipping silently).
	tmpDir, err := os.MkdirTemp("", "setup-protected-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{"/etc/passwd"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("Expected error for absolute protected path, got nil")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected validation error, got ErrNotExist: %v", err)
	}
	// Sanity: nothing was created on the host.
	if _, statErr := os.Lstat("/etc/passwd.coi"); !os.IsNotExist(statErr) {
		t.Errorf("unexpected state: %v", statErr)
	}
}

func TestSetupProtectedPath_RejectsTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "setup-protected-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	_, err = SetupSecurityMounts(nil, tmpDir, "/workspace", []string{"../outside"}, false, nil, NestedGitScan{}, false)
	if err == nil {
		t.Fatal("Expected error for traversal protected path, got nil")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected validation error, got ErrNotExist: %v", err)
	}
}

// ExpandGitWorktreeProtectedPaths must add an entry for each per-worktree
// config.worktree file, creating an absent one, and leave inputs unchanged
// when there are no worktrees.
func TestExpandGitWorktreeProtectedPaths(t *testing.T) {
	tmp := t.TempDir()
	in := []string{".git/config"}

	// No .git/worktrees → unchanged.
	if out := ExpandGitWorktreeProtectedPaths(tmp, in, nil); len(out) != len(in) {
		t.Fatalf("expected no expansion without .git/worktrees, got %v", out)
	}

	// A real worktree with a config.worktree file.
	wtDir := filepath.Join(tmp, ".git", "worktrees", "wt")
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wtDir, "config.worktree"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-dir entry is ignored; a worktree without config.worktree gets an
	// empty one.
	if err := os.WriteFile(filepath.Join(tmp, ".git", "worktrees", "stray"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".git", "worktrees", "noconfig"), 0o755); err != nil {
		t.Fatal(err)
	}

	out := ExpandGitWorktreeProtectedPaths(tmp, in, nil)
	want := filepath.Join(".git", "worktrees", "wt", "config.worktree")
	created := filepath.Join(".git", "worktrees", "noconfig", "config.worktree")
	assertContainsAll(t, out, []string{want, created})
	if len(out) != len(in)+2 {
		t.Errorf("expected exactly two added paths, got %v", out)
	}
	if data, err := os.ReadFile(filepath.Join(tmp, created)); err != nil || len(data) != 0 {
		t.Errorf("%s = %q, %v; want an empty placeholder", created, data, err)
	}
	if _, err := os.Lstat(filepath.Join(tmp, ".git", "worktrees", "noconfig", "commondir")); !os.IsNotExist(err) {
		t.Errorf("absent commondir must not be created: %v", err)
	}

	// disable_protection must suppress expansion — the discovered worktree config
	// is not resurrected when the user turned all protection off.
	sec := &config.SecurityConfig{DisableProtection: true}
	if out := ExpandGitWorktreeProtectedPaths(tmp, in, sec); len(out) != len(in) {
		t.Errorf("disable_protection should suppress worktree expansion, got %v", out)
	}

	// writable_paths must opt a specific discovered worktree config out of protection.
	sec = &config.SecurityConfig{WritablePaths: []string{want}}
	out = ExpandGitWorktreeProtectedPaths(tmp, in, sec)
	for _, p := range out {
		if p == want {
			t.Errorf("writable_paths entry %q should be excluded from expansion, got %v", want, out)
		}
	}

	// Idempotent: expanding an already-expanded list must not duplicate the entry
	// (a duplicate would collide on the derived device name and fail the 2nd mount).
	expanded := ExpandGitWorktreeProtectedPaths(tmp, in, nil)
	again := ExpandGitWorktreeProtectedPaths(tmp, expanded, nil)
	if len(again) != len(expanded) {
		t.Errorf("re-expanding an expanded list must be a no-op, got %v then %v", expanded, again)
	}
	count := 0
	for _, p := range again {
		if p == want {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected %q exactly once after double expansion, got %d (%v)", want, count, again)
	}
}

// recordingDevices is a container.ContainerDevices that records MountDisk calls,
// so a test can assert what SetupSecurityMounts actually mounted.
type recordingDevices struct {
	mounts []mountedDevice
}

type mountedDevice struct {
	name, source, path string
	shift, readonly    bool
}

func (r *recordingDevices) MountDisk(name, source, path string, shift, readonly bool) error {
	r.mounts = append(r.mounts, mountedDevice{name, source, path, shift, readonly})
	return nil
}
func (r *recordingDevices) AddProxyDevice(_, _, _ string, _, _ int) error { return nil }

func (r *recordingDevices) AddHostPortDevice(name, listenAddr string, hostPort, containerPort int) error {
	return nil
}
func (r *recordingDevices) RemoveDevice(_ string) error    { return nil }
func (r *recordingDevices) ListDevices() ([]string, error) { return nil, nil }
func (r *recordingDevices) SetTmpfsSize(_ string) error    { return nil }

// SetupSecurityMounts must expand the dynamic per-worktree git configs itself —
// the single chokepoint every caller passes through (issue #545). Passing an EMPTY
// static list plus an on-disk .git/worktrees/<name>/config.worktree must still
// result in that file being mounted read-only, proving no caller has to remember
// to expand.
func TestSetupSecurityMounts_ExpandsWorktreeConfigsAtChokepoint(t *testing.T) {
	tmp := t.TempDir()
	wtDir := filepath.Join(tmp, ".git", "worktrees", "wt")
	if err := os.MkdirAll(wtDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wtDir, "config.worktree"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := &recordingDevices{}
	effective, err := SetupSecurityMounts(rec, tmp, "/workspace", nil, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := filepath.Join(".git", "worktrees", "wt", "config.worktree")
	inList := false
	for _, p := range effective {
		if p == want {
			inList = true
		}
	}
	if !inList {
		t.Errorf("expected %q in returned effective paths, got %v", want, effective)
	}

	wantContainerPath := filepath.Join("/workspace", want)
	mounted := false
	for _, m := range rec.mounts {
		if m.path == wantContainerPath {
			mounted = true
			if !m.readonly {
				t.Errorf("worktree config mounted but not read-only: %+v", m)
			}
		}
	}
	if !mounted {
		t.Errorf("SetupSecurityMounts did not mount %q through the chokepoint; mounts=%+v", wantContainerPath, rec.mounts)
	}

	// disable_protection at the chokepoint: nothing is expanded or mounted.
	rec2 := &recordingDevices{}
	eff2, err := SetupSecurityMounts(rec2, tmp, "/workspace", nil, false, &config.SecurityConfig{DisableProtection: true}, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(eff2) != 0 || len(rec2.mounts) != 0 {
		t.Errorf("disable_protection must mount nothing at the chokepoint, got paths=%v mounts=%+v", eff2, rec2.mounts)
	}
}

// failingDevices fails, like a refused Incus device, any mount at a path in
// fail and records the others.
type failingDevices struct {
	container.ContainerManager
	fail     map[string]bool
	attempts []string
	mounted  []string
}

func (d *failingDevices) MountDisk(_, _, path string, _, _ bool) error {
	d.attempts = append(d.attempts, path)
	if d.fail[path] {
		return errors.New("Failed to add device")
	}
	d.mounted = append(d.mounted, path)
	return nil
}

// failingBatchDevices is failingDevices with the MountDisks batch method.
type failingBatchDevices struct {
	failingDevices
}

func (d *failingBatchDevices) MountDisks(mounts []container.DiskMount) error {
	for _, m := range mounts {
		if d.fail[m.Path] {
			d.attempts = append(d.attempts, m.Path)
			return errors.New("Failed to add device")
		}
	}
	for _, m := range mounts {
		d.attempts = append(d.attempts, m.Path)
		d.mounted = append(d.mounted, m.Path)
	}
	return nil
}

// newFailingDevices returns devices failing every path in fail, with the
// MountDisks batch method when batch is set, and their record.
func newFailingDevices(batch bool, fail ...string) (container.ContainerDevices, *failingDevices) {
	f := &failingDevices{fail: map[string]bool{}}
	for _, p := range fail {
		f.fail[p] = true
	}
	if !batch {
		return f, f
	}
	bd := &failingBatchDevices{failingDevices: *f}
	return bd, &bd.failingDevices
}

// A protected path that cannot be mounted fails the setup with an error
// naming it, after every later path, the nested git entries and the parent
// pins were tried: one failure skips nothing.
func TestSetupSecurityMounts_MountFailureTriesEveryPath(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	if err := os.MkdirAll(filepath.Join(tmp, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	later := []string{"/workspace/.git/config", "/workspace/.vscode", "/workspace/.git/modules/lib/hooks", "/workspace/.git/modules/lib/config", "/workspace/.git/modules"}

	for _, batch := range []bool{true, false} {
		dev, f := newFailingDevices(batch, "/workspace/.git/hooks")
		_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".git/hooks", ".git/config", ".vscode"}, false, nil, NestedGitScan{}, false)
		if want := ".git/hooks: Failed to add device"; !errors.Is(err, ErrProtectFailed) || !strings.Contains(err.Error(), want) {
			t.Errorf("batch=%v: want ErrProtectFailed naming %q, got %v", batch, want, err)
		}
		for _, p := range later {
			if !slices.Contains(f.mounted, p) {
				t.Errorf("batch=%v: %s skipped after the .git/hooks failure, mounted %v", batch, p, f.mounted)
			}
		}
	}
}

// A nested git entry that cannot be mounted fails the setup with an error
// naming it; the other nested entries and the parent pins are still mounted.
func TestSetupSecurityMounts_NestedMountFailureNamesEntry(t *testing.T) {
	tmp := t.TempDir()
	mkGitDir(t, tmp, ".git")
	mkGitDir(t, tmp, ".git/modules/lib")
	bad := "/workspace/.git/modules/lib/config"

	for _, batch := range []bool{true, false} {
		dev, f := newFailingDevices(batch, bad)
		_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".git/hooks"}, false, nil, NestedGitScan{}, false)
		if !errors.Is(err, ErrProtectFailed) || !strings.Contains(err.Error(), bad+": Failed to add device") {
			t.Errorf("batch=%v: want ErrProtectFailed naming %s, got %v", batch, bad, err)
		}
		for _, p := range []string{"/workspace/.git/hooks", "/workspace/.git/modules/lib/hooks", "/workspace/.git/modules/lib/commondir", "/workspace/.git/modules", "/workspace/.git/modules/lib/info"} {
			if !slices.Contains(f.mounted, p) {
				t.Errorf("batch=%v: %s skipped after the %s failure, mounted %v", batch, p, bad, f.mounted)
			}
		}
	}
}

// A missing protected path is still skipped silently: nothing to protect.
func TestSetupSecurityMounts_MissingPathIsNotAFailure(t *testing.T) {
	tmp := t.TempDir()
	dev, f := newFailingDevices(true)
	if _, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".git/hooks", "missing/dir"}, false, nil, NestedGitScan{}, false); err != nil {
		t.Fatalf("want no error for missing paths, got %v", err)
	}
	if len(f.attempts) != 0 {
		t.Errorf("want no mounts, got %v", f.attempts)
	}
}

// A protected path that cannot be mounted aborts the session start: the
// error reaches the caller instead of a warning.
func TestApplySessionSecurity_MountFailureAbortsStart(t *testing.T) {
	ws := t.TempDir()
	mkGitDir(t, ws, ".git")
	var logged []string
	opts := SetupOptions{WorkspacePath: ws, Logger: func(s string) { logged = append(logged, s) }}
	opts.Security.ProtectedPaths = []string{".git/hooks", ".git/config"}
	dev, f := newFailingDevices(true, "/workspace/.git/hooks")

	_, _, err := applySessionSecurity(dev.(container.ContainerManager), opts, "/workspace", false, nil, false, "c1", NestedGitScan{})
	if !errors.Is(err, ErrProtectFailed) || !strings.Contains(err.Error(), ".git/hooks") {
		t.Fatalf("want ErrProtectFailed naming .git/hooks, got %v (logged %q)", err, logged)
	}
	if !slices.Contains(f.mounted, "/workspace/.git/config") {
		t.Errorf(".git/config skipped after the .git/hooks failure, mounted %v", f.mounted)
	}
}

// Entries that clean to the same path are mounted once: Incus refuses a
// second device with the same name, which must not abort the start.
func TestSetupSecurityMounts_DuplicateEntriesMountOnce(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	dev := &uniqueNameDevices{names: map[string]bool{}}
	if err := os.MkdirAll(filepath.Join(tmp, ".husky"), 0o755); err != nil {
		t.Fatal(err)
	}
	eff, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".vscode", "./.vscode", ".vscode/", ".husky", "../x"}, false, nil, NestedGitScan{}, false)
	if errors.Is(err, ErrProtectFailed) {
		t.Fatalf("want no ErrProtectFailed for duplicate entries, got %v", err)
	}
	if want := []string{".vscode", ".husky", "../x"}; !slices.Equal(eff, want) {
		t.Errorf("want paths %v, got %v", want, eff)
	}
	if len(dev.names) != 2 {
		t.Errorf("want one .vscode and one .husky mount, got %v", dev.names)
	}
}

// A missing default path whose placeholder cannot be created (an unwritable
// workspace) has nothing to protect: a warning, not ErrProtectFailed.
func TestSetupSecurityMounts_UnwritableWorkspaceWarns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(tmp, ".claude")
	if err := os.Mkdir(claude, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmp, 0o755); _ = os.Chmod(claude, 0o755) })
	dev, f := newFailingDevices(true)
	_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".vscode", ".husky", ".claude/settings.json", ".git"}, false, nil, NestedGitScan{}, false)
	if err == nil || errors.Is(err, ErrProtectFailed) {
		t.Fatalf("want a warning, not ErrProtectFailed, got %v", err)
	}
	for _, want := range []string{".vscode", ".husky", "placeholder .claude/settings.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("warning %q does not name %s", err, want)
		}
	}
	if !slices.Contains(f.mounted, "/workspace/.git") {
		t.Errorf(".git skipped after the placeholder failures, mounted %v", f.mounted)
	}
}

// uniqueNameDevices refuses, like Incus, a second device with the same name.
type uniqueNameDevices struct {
	container.ContainerManager
	names map[string]bool
}

func (d *uniqueNameDevices) MountDisk(name, _, _ string, _, _ bool) error {
	if d.names[name] {
		return errors.New("The device already exists")
	}
	d.names[name] = true
	return nil
}

// Entries that name no workspace path are warnings, not failures: there is
// nothing to protect. The valid entries after them are still mounted.
func TestSetupSecurityMounts_InvalidEntriesWarn(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	dev, f := newFailingDevices(true)
	_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{"../x", "/etc/passwd", "", ".vscode"}, false, nil, NestedGitScan{}, false)
	if err == nil || errors.Is(err, ErrProtectFailed) {
		t.Fatalf("want a warning, not ErrProtectFailed, got %v", err)
	}
	for _, want := range []string{`"../x"`, `"/etc/passwd"`, "protected path is empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("warning %q does not name %s", err, want)
		}
	}
	if !slices.Contains(f.mounted, "/workspace/.vscode") {
		t.Errorf(".vscode skipped after the invalid entries, mounted %v", f.mounted)
	}
}

// A protected path below a parent that is a file cannot exist: it is
// skipped like a missing path, not a failure.
func TestSetupSecurityMounts_ParentIsFileIsNotAFailure(t *testing.T) {
	tmp := t.TempDir()
	for _, f := range []string{".claude", ".idea"} {
		if err := os.WriteFile(filepath.Join(tmp, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dev, f := newFailingDevices(true)
	_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".claude/settings.json", ".claude/settings.local.json", ".idea/x/y"}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if len(f.attempts) != 0 {
		t.Errorf("want no mounts, got %v", f.attempts)
	}
}

// A dir created by another start between the Lstat and the Mkdir exists:
// it is mounted read-only, not skipped with a warning.
func TestSetupSecurityMounts_MkdirRaceStillMounts(t *testing.T) {
	tmp := t.TempDir()
	orig := mkdir
	t.Cleanup(func() { mkdir = orig })
	mkdir = func(path string, perm os.FileMode) error {
		if err := orig(path, perm); err != nil {
			return err
		}
		return orig(path, perm)
	}
	dev, f := newFailingDevices(false)
	_, err := SetupSecurityMounts(dev, tmp, "/workspace", []string{".husky"}, false, nil, NestedGitScan{}, false)
	if err != nil {
		t.Fatalf("want no error after a lost mkdir race, got %v", err)
	}
	if !slices.Contains(f.mounted, "/workspace/.husky") {
		t.Errorf(".husky not mounted after a lost mkdir race, mounted %v", f.mounted)
	}
}
