//go:build integration

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

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// skipUnlessContextFileTestable skips the test if integration prerequisites are missing.
func skipUnlessContextFileTestable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}
}

// launchContextTestContainer creates and starts a container, registering cleanup.
func launchContextTestContainer(t *testing.T, name string) *container.Manager {
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

	if err := mgr.Launch("coi-default", false, ""); err != nil {
		t.Fatalf("Failed to launch container: %v", err)
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

// TestContextFile_DefaultInjection verifies that ~/SANDBOX_CONTEXT.md is created
// inside the container with default template content when no custom file is provided.
func TestContextFile_DefaultInjection(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-default"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }

	ctxInfo := tool.ContextInfo{
		WorkspacePath:     "/workspace",
		HomeDir:           homeDir,
		Persistent:        false,
		NetworkMode:       "restricted",
		SSHAgentForwarded: false,
		RunAsRoot:         false,
	}

	// Inject the context file
	err := injectContextFile(mgr, ctxInfo, "", homeDir, logger)
	if err != nil {
		t.Fatalf("injectContextFile failed: %v", err)
	}

	// Verify file exists
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	exists, err := mgr.FileExists(destPath)
	if err != nil {
		t.Fatalf("Failed to check if context file exists: %v", err)
	}
	if !exists {
		t.Fatalf("Expected %s to exist in container", destPath)
	}

	// Read the file and verify content
	user := container.CodeUID
	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	// Verify key template values were rendered
	checks := []struct {
		name   string
		substr string
	}{
		{"header", "COI Sandbox Environment"},
		{"workspace path", "/workspace"},
		{"home dir", homeDir},
		{"ephemeral mode", "Ephemeral"},
		{"restricted network", "Restricted"},
		{"ssh not available", "Not available"},
		{"github cli not auth", "Not authenticated"},
		{"non-root user", "Non-root user"},
		{"OS info", "Ubuntu"},
		{"mise section", "Runtime Manager (mise)"},
		{"python in mise table", "Python 3"},
		{"pnpm in mise table", "pnpm"},
		{"troubleshooting section", "Troubleshooting"},
		{"limitations section", "Limitations"},
		{"default timezone", "UTC"},
		{"default tool name", "AI coding tool"},
	}

	for _, check := range checks {
		if !strings.Contains(content, check.substr) {
			t.Errorf("Context file missing %s (expected substring %q)", check.name, check.substr)
		}
	}

	// Verify ownership (should be owned by code user, not root)
	statOut, err := mgr.ExecCommand("stat -c '%u:%g' "+destPath, container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("Failed to stat context file: %v", err)
	}
	expectedOwnership := strings.TrimSpace(statOut)
	if expectedOwnership != "1000:1000" {
		t.Errorf("Expected ownership 1000:1000, got %s", expectedOwnership)
	}

	t.Logf("Context file content:\n%s", content)
}

// TestContextFile_CustomFile verifies that a user-provided custom context file
// is used instead of the default template when context_file is set in config.
func TestContextFile_CustomFile(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-custom"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }

	// Create a custom context file on the host
	customContent := "# My Custom Sandbox\n\nThis is a custom context file for testing.\nWorkspace: /my/project\n"
	customFile := filepath.Join(t.TempDir(), "custom-context.md")
	if err := os.WriteFile(customFile, []byte(customContent), 0o644); err != nil {
		t.Fatalf("Failed to write custom context file: %v", err)
	}

	ctxInfo := tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
	}

	// Inject with custom file path
	err := injectContextFile(mgr, ctxInfo, customFile, homeDir, logger)
	if err != nil {
		t.Fatalf("injectContextFile with custom file failed: %v", err)
	}

	// Verify file exists
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	exists, err := mgr.FileExists(destPath)
	if err != nil {
		t.Fatalf("Failed to check if context file exists: %v", err)
	}
	if !exists {
		t.Fatalf("Expected %s to exist in container", destPath)
	}

	// Read and verify it's the custom content, not the default template
	user := container.CodeUID
	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	if !strings.Contains(content, "My Custom Sandbox") {
		t.Errorf("Expected custom content, got:\n%s", content)
	}
	if !strings.Contains(content, "custom context file for testing") {
		t.Errorf("Expected custom content body, got:\n%s", content)
	}

	// Should NOT contain default template content
	if strings.Contains(content, "COI Sandbox Environment") {
		t.Error("Custom file should not contain default template header")
	}

	t.Logf("Custom context file content:\n%s", content)
}

// TestContextFile_CustomFileNotFound verifies that injectContextFile returns
// an error when the custom file path doesn't exist.
func TestContextFile_CustomFileNotFound(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-notfound"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }

	ctxInfo := tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
	}

	// Try to inject with non-existent file
	err := injectContextFile(mgr, ctxInfo, "/tmp/nonexistent-context-file-12345.md", homeDir, logger)
	if err == nil {
		t.Fatal("Expected error when custom file doesn't exist, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read custom context file") {
		t.Errorf("Expected 'failed to read custom context file' error, got: %v", err)
	}
}

// TestContextFile_Regeneration verifies that the context file is regenerated
// on each call (important for resumed sessions with updated dynamic info).
func TestContextFile_Regeneration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-regen"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	user := container.CodeUID

	// First injection: ephemeral, restricted
	ctxInfo1 := tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		Persistent:    false,
		NetworkMode:   "restricted",
	}
	if err := injectContextFile(mgr, ctxInfo1, "", homeDir, logger); err != nil {
		t.Fatalf("First injectContextFile failed: %v", err)
	}

	content1, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read first context file: %v", err)
	}
	if !strings.Contains(content1, "Ephemeral") {
		t.Error("First injection should contain 'Ephemeral'")
	}
	if !strings.Contains(content1, "Restricted") {
		t.Error("First injection should contain 'Restricted'")
	}

	// Second injection: persistent, open (simulating resumed session with changed config)
	ctxInfo2 := tool.ContextInfo{
		WorkspacePath:     "/workspace",
		HomeDir:           homeDir,
		Persistent:        true,
		NetworkMode:       "open",
		SSHAgentForwarded: true,
	}
	if err := injectContextFile(mgr, ctxInfo2, "", homeDir, logger); err != nil {
		t.Fatalf("Second injectContextFile failed: %v", err)
	}

	content2, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read second context file: %v", err)
	}
	if !strings.Contains(content2, "Persistent") {
		t.Error("Second injection should contain 'Persistent'")
	}
	if !strings.Contains(content2, "Open") {
		t.Error("Second injection should contain 'Open'")
	}
	if !strings.Contains(content2, "Forwarded from host") {
		t.Error("Second injection should contain 'Forwarded from host'")
	}

	// Should no longer contain the old values
	if strings.Contains(content2, "Ephemeral") {
		t.Error("Second injection should not contain 'Ephemeral' from first run")
	}
}

// TestContextFile_GitHubCLIAuthenticated verifies that the context file reflects
// GitHub CLI authentication status when GH_TOKEN or GITHUB_TOKEN is forwarded.
func TestContextFile_GitHubCLIAuthenticated(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-ghauth"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	user := container.CodeUID

	// Test with GH CLI authenticated
	ctxInfo := tool.ContextInfo{
		WorkspacePath:      "/workspace",
		HomeDir:            homeDir,
		GHCLIAuthenticated: true,
	}
	if err := injectContextFile(mgr, ctxInfo, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextFile failed: %v", err)
	}

	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	if !strings.Contains(content, "Authenticated via forwarded token") {
		t.Error("Context file should indicate GitHub CLI is authenticated")
	}
	if !strings.Contains(content, "token may have limited scope/permissions") {
		t.Error("Context file should include scope warning for forwarded token")
	}
	if strings.Contains(content, "Not authenticated") {
		t.Error("Context file should not say 'Not authenticated' when GH CLI is authenticated")
	}

	// Test without GH CLI authenticated
	ctxInfo2 := tool.ContextInfo{
		WorkspacePath:      "/workspace",
		HomeDir:            homeDir,
		GHCLIAuthenticated: false,
	}
	if err := injectContextFile(mgr, ctxInfo2, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextFile (unauthenticated) failed: %v", err)
	}

	content2, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	if !strings.Contains(content2, "Not authenticated") {
		t.Error("Context file should indicate GitHub CLI is not authenticated")
	}

	t.Logf("Authenticated context file content:\n%s", content)
}

// TestSetupGitIdentityGuard verifies that SetupGitIdentityGuard configures
// user.useConfigOnly=true globally and that git refuses to commit without
// explicit user.name and user.email.
func TestSetupGitIdentityGuard(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-git-identity"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[git-identity] %s", msg) }
	user := container.CodeUID

	// Apply the guard
	SetupGitIdentityGuard(mgr, homeDir, logger)

	// Verify the config value is set
	out, err := mgr.ExecCommand(
		"HOME="+homeDir+" git config --global user.useConfigOnly",
		container.ExecCommandOptions{Capture: true, User: &user},
	)
	if err != nil {
		t.Fatalf("Failed to read git config: %v", err)
	}
	if strings.TrimSpace(out) != "true" {
		t.Errorf("Expected user.useConfigOnly=true, got %q", strings.TrimSpace(out))
	}

	// Create a test repo and try to commit without setting identity — should fail
	initCmd := "HOME=" + homeDir + " bash -c 'cd /tmp && mkdir testrepo && cd testrepo && git init && touch file && git add file && git commit -m test 2>&1; echo EXIT:$?'"
	commitOut, err := mgr.ExecCommand(initCmd, container.ExecCommandOptions{Capture: true, User: &user})
	if err != nil {
		t.Logf("Command error (expected): %v", err)
	}
	if !strings.Contains(commitOut, "EXIT:128") && !strings.Contains(commitOut, "user.useConfigOnly") && !strings.Contains(commitOut, "tell me who you are") {
		// Git should fail with a message about needing identity
		if strings.Contains(commitOut, "EXIT:0") {
			t.Errorf("Expected git commit to fail without identity, but it succeeded.\nOutput: %s", commitOut)
		}
	}

	// Now set identity and verify commit succeeds
	fixCmd := "HOME=" + homeDir + " bash -c 'cd /tmp/testrepo && git config user.name \"Test User\" && git config user.email \"test@example.com\" && git commit -m test 2>&1; echo EXIT:$?'"
	fixOut, err := mgr.ExecCommand(fixCmd, container.ExecCommandOptions{Capture: true, User: &user})
	if err != nil {
		t.Fatalf("Failed to run git commit with identity: %v", err)
	}
	if !strings.Contains(fixOut, "EXIT:0") {
		t.Errorf("Expected git commit to succeed after setting identity.\nOutput: %s", fixOut)
	}
}

// TestContextFile_ForwardedEnvVars verifies that forwarded environment variable
// names appear in the context file when provided.
func TestContextFile_ForwardedEnvVars(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-envvars"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	user := container.CodeUID

	// Test with forwarded env vars
	ctxInfo := tool.ContextInfo{
		WorkspacePath:    "/workspace",
		HomeDir:          homeDir,
		ForwardedEnvVars: []string{"ANTHROPIC_API_KEY", "GH_TOKEN", "CUSTOM_VAR"},
	}
	if err := injectContextFile(mgr, ctxInfo, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextFile failed: %v", err)
	}

	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	checks := []struct {
		name   string
		substr string
	}{
		{"forwarded env section", "Forwarded Environment Variables"},
		{"anthropic key listed", "ANTHROPIC_API_KEY"},
		{"gh token listed", "GH_TOKEN"},
		{"custom var listed", "CUSTOM_VAR"},
	}
	for _, check := range checks {
		if !strings.Contains(content, check.substr) {
			t.Errorf("Context file missing %s (expected substring %q)", check.name, check.substr)
		}
	}

	// Test without forwarded env vars — section should not appear
	ctxInfo2 := tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
	}
	if err := injectContextFile(mgr, ctxInfo2, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextFile (no env vars) failed: %v", err)
	}

	content2, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	if strings.Contains(content2, "Forwarded Environment Variables") {
		t.Error("Context file should not contain forwarded env vars section when none are forwarded")
	}

	t.Logf("Forwarded env vars context file content:\n%s", content)
}

// TestContextFile_WithAllNewFields verifies that all 6 new context fields
// (timezone, tool name, container name, extra mounts, resource limits, session timeout)
// appear correctly in the rendered context file.
func TestContextFile_WithAllNewFields(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-newfields"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }
	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.md")
	user := container.CodeUID

	ctxInfo := tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		Timezone:      "Europe/Warsaw",
		ToolName:      "claude",
		ContainerName: containerName,
		ExtraMounts: []tool.MountInfo{
			{ContainerPath: "/data"},
			{ContainerPath: "/config"},
		},
		CPULimit:    "2",
		MemoryLimit: "4GiB",
		MaxDuration: "2h",
	}

	if err := injectContextFile(mgr, ctxInfo, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextFile failed: %v", err)
	}

	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{
		Capture: true,
		User:    &user,
	})
	if err != nil {
		t.Fatalf("Failed to read context file: %v", err)
	}

	checks := []struct {
		name   string
		substr string
	}{
		{"timezone", "Europe/Warsaw"},
		{"tool name", "claude"},
		{"container name", containerName},
		{"extra mount /data", "/data"},
		{"extra mount /config", "/config"},
		{"additional mounts section", "Additional Mounts"},
		{"resource limits", "Resource limits"},
		{"cpu limit", "2 CPUs"},
		{"memory limit", "4GiB memory"},
		{"session timeout", "Session timeout"},
		{"max duration", "2h"},
	}

	for _, check := range checks {
		if !strings.Contains(content, check.substr) {
			t.Errorf("Context file missing %s (expected substring %q)", check.name, check.substr)
		}
	}

	t.Logf("New fields context file content:\n%s", content)
}

// TestContextFile_JSONInjection verifies ~/SANDBOX_CONTEXT.json is created inside
// the container, is valid JSON carrying the sandbox facts, and is owned by the
// code user (#705).
func TestContextFile_JSONInjection(t *testing.T) {
	skipUnlessContextFileTestable(t)

	containerName := "coi-test-ctx-json"
	mgr := launchContextTestContainer(t, containerName)

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[context] %s", msg) }

	ctxInfo := tool.ContextInfo{
		ContainerName: containerName,
		ToolName:      "claude",
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		Persistent:    false,
		NetworkMode:   "restricted",
		AllowedPorts:  []int{443},
	}

	if err := injectContextJSONFile(mgr, ctxInfo, "", homeDir, logger); err != nil {
		t.Fatalf("injectContextJSONFile failed: %v", err)
	}

	destPath := filepath.Join(homeDir, "SANDBOX_CONTEXT.json")
	exists, err := mgr.FileExists(destPath)
	if err != nil {
		t.Fatalf("Failed to check if JSON context file exists: %v", err)
	}
	if !exists {
		t.Fatalf("Expected %s to exist in container", destPath)
	}

	user := container.CodeUID
	content, err := mgr.ExecCommand("cat "+destPath, container.ExecCommandOptions{Capture: true, User: &user})
	if err != nil {
		t.Fatalf("Failed to read JSON context file: %v", err)
	}

	var got tool.SandboxContextJSON
	if err := json.Unmarshal([]byte(content), &got); err != nil {
		t.Fatalf("SANDBOX_CONTEXT.json is not valid JSON: %v\n%s", err, content)
	}
	if got.SchemaVersion == 0 {
		t.Errorf("schema_version missing/zero: %+v", got)
	}
	if got.WorkspacePath != "/workspace" || got.Network.Mode != "restricted" {
		t.Errorf("fields not carried through: %+v", got)
	}
	if len(got.Network.AllowedPorts) != 1 || got.Network.AllowedPorts[0] != 443 {
		t.Errorf("allowed_ports = %v, want [443]", got.Network.AllowedPorts)
	}
	if got.OS == "" || got.Architecture == "" {
		t.Errorf("os/arch defaults not applied: os=%q arch=%q", got.OS, got.Architecture)
	}

	statOut, err := mgr.ExecCommand("stat -c '%u:%g' "+destPath, container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("Failed to stat JSON context file: %v", err)
	}
	if ownership := strings.TrimSpace(statOut); ownership != "1000:1000" {
		t.Errorf("Expected ownership 1000:1000, got %s", ownership)
	}
}

// injectContextFile creates ~/SANDBOX_CONTEXT.md inside the container (see
// contextFileOp) in one exec.
func injectContextFile(mgr container.ContainerManager, info tool.ContextInfo, customPath, homeDir string, logger func(string)) error {
	op, err := contextFileOp(info, customPath, homeDir, logger)
	if err != nil {
		return err
	}
	if err := runGuestOps(mgr, []guestOp{op}, container.ExecCommandOptions{}); err != nil {
		return fmt.Errorf("failed to create context file %s: %w", op.write.path, err)
	}
	logger(fmt.Sprintf("Context file injected at %s", op.write.path))
	return nil
}

// injectContextJSONFile creates ~/SANDBOX_CONTEXT.json inside the container
// (see contextJSONFileOp) in one exec.
func injectContextJSONFile(mgr container.ContainerManager, info tool.ContextInfo, customPath, homeDir string, logger func(string)) error {
	op, err := contextJSONFileOp(info, customPath, homeDir, logger)
	if err != nil {
		return err
	}
	if err := runGuestOps(mgr, []guestOp{op}, container.ExecCommandOptions{}); err != nil {
		return fmt.Errorf("failed to create context JSON file %s: %w", op.write.path, err)
	}
	logger(fmt.Sprintf("Context JSON file injected at %s", op.write.path))
	return nil
}
