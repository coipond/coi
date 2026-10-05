//go:build integration

package session

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestSetupClaudeManagedSettings_Integration proves the fix's observable
// contract in a real container: the pushed policy file is root-owned and
// world-readable, so the unprivileged code user can read it. Before the fix
// the file landed 0600 owned by the host UID, and Claude Code failed OAuth
// with EACCES on the policy file. Skipped without a local Incus daemon
// (skipUnlessContextFileTestable, shared with context_file_integration_test.go).
func TestSetupClaudeManagedSettings_Integration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	mgr := launchContextTestContainer(t, "coi-test-managed-settings")
	logger := func(msg string) { t.Logf("[managed-settings] %s", msg) }

	SetupClaudeManagedSettings(mgr, true, true, logger)

	const path = "/etc/claude-code/managed-settings.json"

	owner, err := mgr.ExecCommand("stat -c %u:%g "+path, container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("stat owner: %v", err)
	}
	if strings.TrimSpace(owner) != "0:0" {
		t.Errorf("owner = %q, want 0:0", strings.TrimSpace(owner))
	}

	mode, err := mgr.ExecCommand("stat -c %a "+path, container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("stat mode: %v", err)
	}
	if strings.TrimSpace(mode) != "644" {
		t.Errorf("mode = %q, want 644", strings.TrimSpace(mode))
	}

	// The load-bearing assertion: the unprivileged code user must be able to
	// read the policy file. This is what actually failed before the fix.
	codeUID := container.CodeUID
	content, err := mgr.ExecCommand("cat "+path, container.ExecCommandOptions{
		Capture: true,
		User:    &codeUID,
	})
	if err != nil {
		t.Fatalf("code user cannot read managed settings (the EACCES regression): %v", err)
	}
	if !strings.Contains(content, "disableAutoMode") {
		t.Errorf("unexpected managed settings content: %q", content)
	}
}
