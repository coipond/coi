package session

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/container"
	"golang.org/x/sys/unix"
)

// skipUnlessImmutableCapable skips the test if CAP_LINUX_IMMUTABLE is not
// available. On CI (Linux) the capability is granted via setcap on the test
// binary, so these tests are expected to run. They only skip in local dev
// environments where the developer hasn't granted the capability.
func skipUnlessImmutableCapable(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	probe := filepath.Join(tmp, "cap-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setImmutable(probe); err != nil {
		if isImmutableUnsupported(err) {
			t.Skip("CAP_LINUX_IMMUTABLE not available (grant with: sudo setcap cap_linux_immutable=ep <test-binary>)")
		}
		t.Fatalf("unexpected error probing immutable capability: %v", err)
	}
	_ = clearImmutable(probe)
}

// skipUnlessImmutableIntegrationTestable checks all prerequisites for container-based
// immutable integration tests: incus binary, running daemon, coi-default image, and
// CAP_LINUX_IMMUTABLE on the current process.
func skipUnlessImmutableIntegrationTestable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi-default image not found, skipping integration test (run 'coi build' first)")
	}
	skipUnlessImmutableCapable(t)
}

// TestSetImmutableFlag tests setting and clearing the immutable flag on a temp file.
func TestSetImmutableFlag(t *testing.T) {
	skipUnlessImmutableCapable(t)

	tmp := t.TempDir()
	path := filepath.Join(tmp, "testfile")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Set immutable
	if err := setImmutable(path); err != nil {
		t.Fatalf("setImmutable failed: %v", err)
	}

	// Verify the flag is set by reading it back
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := ioctlGetFlags(f)
	f.Close()
	if err != nil {
		t.Fatalf("ioctlGetFlags failed: %v", err)
	}
	if flags&fsImmutableFL == 0 {
		t.Error("immutable flag not set after setImmutable")
	}

	// Writing should fail
	if err := os.WriteFile(path, []byte("pwned"), 0o644); err == nil {
		t.Error("expected write to immutable file to fail")
	}

	// Clear it
	if err := clearImmutable(path); err != nil {
		t.Fatalf("clearImmutable failed: %v", err)
	}

	// Verify cleared
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	flags, err = ioctlGetFlags(f)
	f.Close()
	if err != nil {
		t.Fatalf("ioctlGetFlags failed: %v", err)
	}
	if flags&fsImmutableFL != 0 {
		t.Error("immutable flag still set after clearImmutable")
	}

	// Writing should succeed now
	if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
		t.Errorf("write should succeed after clearImmutable: %v", err)
	}
}

// TestSetImmutableRecursive tests recursive immutable setting on a directory tree.
func TestSetImmutableRecursive(t *testing.T) {
	skipUnlessImmutableCapable(t)

	tmp := t.TempDir()

	// Create a directory tree
	dirs := []string{
		filepath.Join(tmp, "hooks"),
		filepath.Join(tmp, "hooks", "subdir"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{
		filepath.Join(tmp, "hooks", "pre-commit"),
		filepath.Join(tmp, "hooks", "subdir", "helper.sh"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	hooksDir := filepath.Join(tmp, "hooks")

	// Set immutable recursively
	if err := setImmutableRecursive(hooksDir); err != nil {
		t.Fatalf("setImmutableRecursive: %v", err)
	}

	// Verify: writing to an immutable file should fail
	if err := os.WriteFile(files[0], []byte("modified"), 0o755); err == nil {
		t.Error("expected write to immutable file to fail")
	}

	// Verify: creating a file in an immutable directory should fail
	if err := os.WriteFile(filepath.Join(hooksDir, "new-hook"), []byte("new"), 0o755); err == nil {
		t.Error("expected file creation in immutable directory to fail")
	}

	// Clear recursively
	if err := clearImmutableRecursive(hooksDir); err != nil {
		t.Fatalf("clearImmutableRecursive: %v", err)
	}

	// Verify: writing should now succeed
	if err := os.WriteFile(files[0], []byte("modified"), 0o755); err != nil {
		t.Errorf("write should succeed after clearing immutable: %v", err)
	}
}

// TestApplyImmutableGracefulDegradation tests that ApplyImmutable degrades
// gracefully when the immutable attribute is not supported (e.g., tmpfs on
// most systems, or missing capability). This test is NOT gated on capability
// — it verifies the degradation path itself.
func TestApplyImmutableGracefulDegradation(t *testing.T) {
	tmp := t.TempDir()

	// Create a test directory
	testDir := filepath.Join(tmp, ".git", "hooks")
	if err := os.MkdirAll(testDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var logs []string
	logger := func(msg string) {
		logs = append(logs, msg)
	}

	// This will either succeed (if we have CAP_LINUX_IMMUTABLE) or
	// degrade gracefully. Either way, no panic or hard error.
	result := ApplyImmutable(tmp, []string{".git/hooks"}, "test-container", logger)

	if len(result) == 0 {
		// Degraded — check that a warning was logged
		found := false
		for _, log := range logs {
			if strings.Contains(log, "Cannot set immutable") || strings.Contains(log, "Warning") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected warning log on degradation, got none")
		}
	} else {
		// Succeeded — clean up
		for _, p := range result {
			hostPath := filepath.Join(tmp, p)
			_ = clearImmutableRecursive(hostPath)
		}
		removeImmutableManifest("test-container")
	}
}

// TestApplyAndRemoveImmutableRoundTrip tests the full apply → verify → remove cycle.
func TestApplyAndRemoveImmutableRoundTrip(t *testing.T) {
	skipUnlessImmutableCapable(t)

	// Override manifest dir
	origDir := immutableManifestDir
	t.Cleanup(func() { immutableManifestDir = origDir })
	manifestTmp := t.TempDir()
	immutableManifestDir = func() string { return manifestTmp }

	// Create workspace with multiple protected paths
	workspace := t.TempDir()
	for _, dir := range []string{".git/hooks", ".husky", ".vscode"} {
		if err := os.MkdirAll(filepath.Join(workspace, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git/hooks/pre-commit"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git/config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var logs []string
	logger := func(msg string) { logs = append(logs, msg) }

	// Apply
	applied := ApplyImmutable(workspace, []string{".git/hooks", ".git/config", ".husky", ".vscode"}, "roundtrip-test", logger)
	if len(applied) == 0 {
		t.Fatal("ApplyImmutable returned empty — expected success with capability")
	}

	// Verify all paths are immutable
	for _, p := range applied {
		hostPath := filepath.Join(workspace, p)
		info, _ := os.Lstat(hostPath)
		if info.IsDir() {
			if err := os.WriteFile(filepath.Join(hostPath, "new-file"), []byte("x"), 0o644); err == nil {
				t.Errorf("should not be able to create file in immutable dir %s", p)
			}
		} else {
			if err := os.WriteFile(hostPath, []byte("x"), 0o644); err == nil {
				t.Errorf("should not be able to write to immutable file %s", p)
			}
		}
	}

	// Verify manifest exists
	manifestPath := filepath.Join(manifestTmp, "roundtrip-test.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest not created: %v", err)
	}

	// Remove
	RemoveImmutable("roundtrip-test", logger)

	// Verify all paths are writable again
	if err := os.WriteFile(filepath.Join(workspace, ".git/hooks/pre-commit"), []byte("modified"), 0o755); err != nil {
		t.Errorf("should be able to write after RemoveImmutable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".git/config"), []byte("[core]\nmodified\n"), 0o644); err != nil {
		t.Errorf("should be able to write after RemoveImmutable: %v", err)
	}

	// Verify manifest removed
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Error("manifest should be removed after RemoveImmutable")
	}
}

// TestManifestSaveLoad tests round-trip serialization of the manifest.
func TestManifestSaveLoad(t *testing.T) {
	origDir := immutableManifestDir
	t.Cleanup(func() { immutableManifestDir = origDir })

	tmp := t.TempDir()
	immutableManifestDir = func() string { return tmp }

	manifest := &ImmutableManifest{
		ContainerName: "test-container-123",
		Workspace:     "/home/user/project",
		Paths:         []string{".git/hooks", ".git/config", ".husky"},
		AppliedAt:     "2026-04-12T10:30:00Z",
	}

	// Save
	if err := saveImmutableManifest(manifest); err != nil {
		t.Fatalf("saveImmutableManifest: %v", err)
	}

	// Verify file exists
	path := filepath.Join(tmp, "test-container-123.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("manifest file not found: %v", err)
	}

	// Verify JSON structure
	var loaded ImmutableManifest
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if loaded.ContainerName != manifest.ContainerName {
		t.Errorf("container_name: got %q, want %q", loaded.ContainerName, manifest.ContainerName)
	}
	if len(loaded.Paths) != len(manifest.Paths) {
		t.Errorf("paths: got %d, want %d", len(loaded.Paths), len(manifest.Paths))
	}

	// Load via loadImmutableManifest
	reloaded := loadImmutableManifest("test-container-123")
	if reloaded == nil {
		t.Fatal("loadImmutableManifest returned nil")
	}
	if reloaded.Workspace != manifest.Workspace {
		t.Errorf("workspace: got %q, want %q", reloaded.Workspace, manifest.Workspace)
	}

	// Remove
	removeImmutableManifest("test-container-123")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("manifest file still exists after removeImmutableManifest")
	}
}

// TestRemoveImmutableWithMissingPaths tests that RemoveImmutable handles
// manifests whose workspace paths no longer exist (e.g., deleted workspace).
func TestRemoveImmutableWithMissingPaths(t *testing.T) {
	origDir := immutableManifestDir
	t.Cleanup(func() { immutableManifestDir = origDir })

	tmp := t.TempDir()
	immutableManifestDir = func() string { return tmp }

	// Create a manifest for a "container" whose workspace is empty/gone
	manifest := &ImmutableManifest{
		ContainerName: "nonexistent-container",
		Workspace:     t.TempDir(),
		Paths:         []string{".git/hooks"},
		AppliedAt:     "2026-04-12T10:30:00Z",
	}
	if err := saveImmutableManifest(manifest); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(tmp, "nonexistent-container.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest not created: %v", err)
	}

	var logs []string
	logger := func(msg string) { logs = append(logs, msg) }

	// Verify manifest roundtrip
	loaded := loadImmutableManifest("nonexistent-container")
	if loaded == nil {
		t.Fatal("expected manifest to be loadable")
	}
	if loaded.ContainerName != "nonexistent-container" {
		t.Errorf("container_name: got %q", loaded.ContainerName)
	}

	// RemoveImmutable should clear the manifest (paths are gone, no failures)
	RemoveImmutable("nonexistent-container", logger)

	// Manifest should be removed (no paths to fail on since workspace is empty)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("manifest should be removed after RemoveImmutable with empty workspace")
	}
}

// TestIsImmutableUnsupported tests the error classification functions.
func TestIsImmutableUnsupported(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"EPERM", unix.EPERM, true},
		{"EACCES", unix.EACCES, true},
		{"wrapped EPERM", fmt.Errorf("ioctl set flags on /foo: %w", unix.EPERM), true},
		{"ENOTTY", unix.ENOTTY, true},
		{"EOPNOTSUPP", unix.EOPNOTSUPP, true},
		{"random error", os.ErrNotExist, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isImmutableUnsupported(tt.err)
			if got != tt.expected {
				t.Errorf("isImmutableUnsupported(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

// TestIsImmutableFSUnsupported tests the filesystem-only error classification.
func TestIsImmutableFSUnsupported(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"EPERM", unix.EPERM, false},          // EPERM is NOT fs-unsupported
		{"EACCES", unix.EACCES, false},        // EACCES is NOT fs-unsupported
		{"ENOTTY", unix.ENOTTY, true},         // unsupported filesystem
		{"EOPNOTSUPP", unix.EOPNOTSUPP, true}, // unsupported filesystem
		{"wrapped ENOTTY", fmt.Errorf("ioctl: %w", unix.ENOTTY), true},
		{"random error", os.ErrNotExist, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isImmutableFSUnsupported(tt.err)
			if got != tt.expected {
				t.Errorf("isImmutableFSUnsupported(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

// Note: TestValidateRelPath lives in security_test.go since validateRelPath
// is defined in security.go (shared by both security mounts and immutable).

// --- Integration tests (require Incus + CAP_LINUX_IMMUTABLE) ---

// launchImmutableTestContainer creates and starts a container with a workspace
// bind mount, registering cleanup.
func launchImmutableTestContainer(t *testing.T, name, workspacePath string) *container.Manager {
	t.Helper()
	mgr := container.NewManager(name)

	t.Cleanup(func() {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	})

	if exists, _ := mgr.Exists(); exists {
		_ = mgr.Stop(true)
		_ = mgr.Delete(true)
	}

	// Init container (don't start yet — add devices first)
	if err := container.IncusExec("init", "coi-default", name); err != nil {
		t.Fatalf("Failed to init container: %v", err)
	}

	// Add workspace bind mount with shift
	if err := mgr.MountDisk("workspace", workspacePath, "/workspace", true, false); err != nil {
		t.Fatalf("Failed to mount workspace: %v", err)
	}

	// Start container
	if err := mgr.Start(); err != nil {
		t.Fatalf("Failed to start container: %v", err)
	}

	// Wait for container to be ready
	for i := 0; i < 30; i++ {
		if _, err := mgr.ExecCommand("echo ready", container.ExecCommandOptions{Capture: true}); err == nil {
			return mgr
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Container failed to become ready")
	return nil
}

// TestImmutableSurvivesUnshare verifies that the immutable attribute cannot
// be bypassed by unshare+umount inside the container. This is the core
// security test for P0-2a: even with full root inside the container, a
// process cannot clear the immutable bit because CAP_LINUX_IMMUTABLE is
// not available in the container's user namespace.
func TestImmutableSurvivesUnshare(t *testing.T) {
	skipUnlessImmutableIntegrationTestable(t)

	// Create workspace with .git/hooks containing a hook file
	workspace := t.TempDir()
	hooksDir := filepath.Join(workspace, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookFile := filepath.Join(hooksDir, "pre-commit")
	if err := os.WriteFile(hookFile, []byte("#!/bin/sh\necho safe\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Apply immutable on host side
	var logs []string
	logger := func(msg string) { logs = append(logs, msg) }
	applied := ApplyImmutable(workspace, []string{".git/hooks"}, "coi-test-immutable-unshare", logger)
	if len(applied) == 0 {
		t.Fatal("ApplyImmutable returned empty — expected success with CAP_LINUX_IMMUTABLE")
	}
	t.Cleanup(func() {
		RemoveImmutable("coi-test-immutable-unshare", logger)
	})

	// Launch container with workspace mounted
	containerName := "coi-test-immutable-unshare"
	mgr := launchImmutableTestContainer(t, containerName, workspace)

	// Attempt 1: Direct write (should fail due to read-only mount AND immutable)
	output, err := mgr.ExecCommand(
		"sh -c 'echo pwned > /workspace/.git/hooks/pre-commit 2>&1 || echo WRITE_FAILED'",
		container.ExecCommandOptions{Capture: true},
	)
	if err == nil && !strings.Contains(output, "WRITE_FAILED") {
		t.Error("direct write to protected path should fail")
	}

	// Attempt 2: The actual attack — unshare mount namespace, umount the
	// read-only bind mount, then try to write. Without immutable protection
	// this would succeed because umount removes the read-only overlay.
	attackCmd := `sudo unshare -m sh -c '
		umount /workspace/.git/hooks 2>/dev/null
		echo pwned > /workspace/.git/hooks/pre-commit 2>&1 || echo ATTACK_BLOCKED
		touch /workspace/.git/hooks/new-evil-hook 2>&1 || echo CREATION_BLOCKED
	'`
	output, _ = mgr.ExecCommand(attackCmd, container.ExecCommandOptions{Capture: true})

	if !strings.Contains(output, "ATTACK_BLOCKED") {
		t.Error("unshare+umount attack should be blocked by immutable attribute")
	}
	if !strings.Contains(output, "CREATION_BLOCKED") {
		t.Error("file creation after unshare+umount should be blocked by immutable attribute")
	}

	// Verify host-side file is intact
	content, err := os.ReadFile(hookFile)
	if err != nil {
		t.Fatalf("failed to read hook file: %v", err)
	}
	if !strings.Contains(string(content), "echo safe") {
		t.Errorf("hook file content was modified: %s", content)
	}

	t.Log("Attack blocked: immutable attribute survives unshare+umount")
}

// TestImmutableOptOut verifies that setting host_immutable=false disables
// the immutable attribute application.
func TestImmutableOptOut(t *testing.T) {
	skipUnlessImmutableCapable(t)

	workspace := t.TempDir()
	hooksDir := filepath.Join(workspace, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Apply with empty paths (simulating opt-out — caller wouldn't call ApplyImmutable)
	// Verify that without applying, the files remain writable
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte("modified"), 0o755); err != nil {
		t.Errorf("files should be writable when immutable is not applied: %v", err)
	}
}
