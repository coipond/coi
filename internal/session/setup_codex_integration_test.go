//go:build integration

package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/tool"
)

// TestSetupCLIConfig_Codex_Integration runs the real codex config seeding
// against a live container: host ~/.codex files land in the container
// byte-identical (config.toml is TOML and must NEVER pass through the JSON
// settings merge — #698), owned by the code user, with no sibling state file
// synthesized. Skipped without a local Incus daemon + coi-default image
// (skipUnlessContextFileTestable, shared with context_file_integration_test.go).
func TestSetupCLIConfig_Codex_Integration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	// Fake host ~/.codex. The TOML deliberately includes formatting a JSON
	// (re)serialization could never reproduce: comments, table headers, and
	// key order — byte equality proves the file was copied, not parsed.
	hostCodex := t.TempDir()
	const configTOML = "# user config — must survive seeding byte-for-byte\n" +
		"model = \"gpt-5-codex\"\n\n[sandbox_workspace_write]\nnetwork_access = true\n"
	const authJSON = `{"tokens": {"access_token": "fake-token"}}`
	const agentsMD = "# My global codex instructions\nUSER-AGENTS-CONTENT\n"
	for name, content := range map[string]string{
		"config.toml": configTOML,
		"auth.json":   authJSON,
		"AGENTS.md":   agentsMD,
	} {
		if err := os.WriteFile(filepath.Join(hostCodex, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	mgr := launchContextTestContainer(t, "coi-test-codex-seed")

	codex, err := tool.Get("codex")
	if err != nil {
		t.Fatalf("Get(codex): %v", err)
	}
	tcf, ok := codex.(tool.ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("CodexTool must implement ToolWithConfigDirFiles")
	}

	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[codex] %s", msg) }

	if err := setupCLIConfig(mgr, hostCodex, homeDir, tcf, logger); err != nil {
		t.Fatalf("setupCLIConfig: %v", err)
	}

	for name, want := range map[string]string{
		"config.toml": configTOML,
		"auth.json":   authJSON,
		"AGENTS.md":   agentsMD,
	} {
		destPath := filepath.Join(homeDir, ".codex", name)
		got, err := mgr.ExecCommand(fmt.Sprintf("cat %s", destPath), container.ExecCommandOptions{Capture: true})
		if err != nil {
			t.Fatalf("reading %s: %v", destPath, err)
		}
		if got != want {
			t.Errorf("%s content changed during seeding:\n got: %q\nwant: %q", name, got, want)
		}

		owner, err := mgr.ExecCommand(fmt.Sprintf("stat -c %%u %s", destPath), container.ExecCommandOptions{Capture: true})
		if err != nil {
			t.Fatalf("stat %s: %v", destPath, err)
		}
		if wantUID := fmt.Sprintf("%d", container.CodeUID); owner != wantUID {
			t.Errorf("%s owner uid = %q, want %q", name, owner, wantUID)
		}
	}

	// Codex has no sibling state file (unlike ~/.claude.json) — nothing may be
	// synthesized next to the config dir.
	out, err := mgr.ExecCommand(
		fmt.Sprintf("test -e %s && echo exists || echo missing", filepath.Join(homeDir, ".codex.json")),
		container.ExecCommandOptions{Capture: true})
	if err == nil && out == "exists" {
		t.Error("a ~/.codex.json state file was synthesized; codex must not have one")
	}
}

// TestInjectAutoContext_Codex_Integration verifies the auto-context chain in a
// real container: the Coi-managed sandbox block is written into
// ~/.codex/AGENTS.md, coexists with host-seeded content, and stays a single
// copy across repeated sessions (the #674 accumulation guard, for codex).
func TestInjectAutoContext_Codex_Integration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	mgr := launchContextTestContainer(t, "coi-test-codex-autoctx")

	codex, err := tool.Get("codex")
	if err != nil {
		t.Fatalf("Get(codex): %v", err)
	}
	acf, ok := codex.(tool.ToolWithAutoContextFile)
	if !ok {
		t.Fatal("CodexTool must implement ToolWithAutoContextFile")
	}

	homeDir := "/home/" + container.CodeUser
	destPath := filepath.Join(homeDir, ".codex", "AGENTS.md")
	logger := func(msg string) { t.Logf("[autoctx] %s", msg) }

	// Simulate a host-seeded AGENTS.md already in place.
	const userMarker = "USER-CODEX-RULES-KEEP-ME"
	if _, err := mgr.ExecCommand(fmt.Sprintf("mkdir -p %s", filepath.Dir(destPath)), container.ExecCommandOptions{Capture: true}); err != nil {
		t.Fatal(err)
	}
	if err := mgr.CreateFile(destPath, "# my rules\n"+userMarker+"\n"); err != nil {
		t.Fatal(err)
	}

	content := tool.RenderContextFileContent(tool.ContextInfo{
		WorkspacePath: "/workspace",
		HomeDir:       homeDir,
		NetworkMode:   "restricted",
	})

	for i := 0; i < 2; i++ {
		if err := injectAutoContextFile(mgr, acf, content, homeDir, logger); err != nil {
			t.Fatalf("session %d: injectAutoContextFile: %v", i+1, err)
		}
	}

	got, err := mgr.ExecCommand(fmt.Sprintf("cat %s", destPath), container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("reading %s: %v", destPath, err)
	}
	if n := strings.Count(got, userMarker); n != 1 {
		t.Errorf("host content must survive exactly once, found %d occurrences", n)
	}
	if n := strings.Count(got, "# COI Sandbox Environment"); n != 1 {
		t.Errorf("expected exactly one Coi sandbox block after repeated sessions, found %d", n)
	}
}
