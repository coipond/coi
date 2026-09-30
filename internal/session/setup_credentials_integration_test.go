//go:build integration

package session

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestSetupCredentials_Integration pushes an ad-hoc credential file into a
// real container, verifying content, ownership, and chmod. Skipped without a
// local Incus daemon (skipUnlessContextFileTestable, shared with
// context_file_integration_test.go).
func TestSetupCredentials_Integration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	tmpHost := t.TempDir()
	hostFile := filepath.Join(tmpHost, "id_ed25519")
	if err := os.WriteFile(hostFile, []byte("fake-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr := launchContextTestContainer(t, "coi-test-credentials")

	entries := []CredentialEntry{
		{HostPath: hostFile, ContainerPath: filepath.Join(".ollama", "id_ed25519"), Mode: "0600"},
	}
	var logs []string
	logger := func(msg string) { logs = append(logs, msg); t.Logf("[credentials] %s", msg) }

	homeDir := "/home/" + container.CodeUser
	if err := setupCredentials(mgr, homeDir, entries, logger); err != nil {
		t.Fatalf("setupCredentials: %v", err)
	}

	destPath := filepath.Join(homeDir, ".ollama", "id_ed25519")
	out, err := mgr.ExecCommand(fmt.Sprintf("cat %s", destPath), container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("reading pushed file: %v", err)
	}
	if out != "fake-key-material" {
		t.Errorf("pushed file content = %q, want %q", out, "fake-key-material")
	}

	perms, err := mgr.ExecCommand(fmt.Sprintf("stat -c %%a %s", destPath), container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perms != "600" {
		t.Errorf("mode = %q, want %q", perms, "600")
	}

	owner, err := mgr.ExecCommand(fmt.Sprintf("stat -c %%u %s", destPath), container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("stat owner: %v", err)
	}
	wantUID := fmt.Sprintf("%d", container.CodeUID)
	if owner != wantUID {
		t.Errorf("owner uid = %q, want %q", owner, wantUID)
	}
}
