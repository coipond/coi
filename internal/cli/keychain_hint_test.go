package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
	"github.com/coipond/coi/internal/vmhost"
)

func TestFormatMacKeychainHint(t *testing.T) {
	got := formatMacKeychainHint("claude", ".claude", "Claude Code-credentials", ".credentials.json")

	// The exact command the user must run on the Mac, including the service name
	// and the destination path, must appear verbatim.
	wantCmd := `security find-generic-password -s "Claude Code-credentials" -w > ~/.claude/.credentials.json`
	if !strings.Contains(got, wantCmd) {
		t.Errorf("hint missing the materialize command.\n got:\n%s\n want substring:\n%s", got, wantCmd)
	}
	for _, want := range []string{"claude", "Keychain", "ON YOUR MAC"} {
		if !strings.Contains(got, want) {
			t.Errorf("hint missing %q; got:\n%s", want, got)
		}
	}
}

// The hint is driven by the tool's KeychainCredential(); make sure Claude
// actually advertises the Keychain service + credential filename, or the whole
// hint silently no-ops.
func TestClaudeExposesKeychainCredential(t *testing.T) {
	c, err := tool.Get("claude")
	if err != nil {
		t.Fatalf("tool.Get(claude): %v", err)
	}
	kc, ok := c.(tool.ToolWithKeychainCredential)
	if !ok {
		t.Fatal("ClaudeTool must implement ToolWithKeychainCredential")
	}
	service, filename := kc.KeychainCredential()
	if service != "Claude Code-credentials" {
		t.Errorf("keychain service = %q, want %q", service, "Claude Code-credentials")
	}
	if filename != ".credentials.json" {
		t.Errorf("keychain file = %q, want %q", filename, ".credentials.json")
	}
}

// The hint's gating: it must fire for a keychain-backed tool inside a Mac VM
// with no cred file, and stay quiet in every false-positive case (Linux,
// API-key auth, resume, cred file already present).
func TestMacKeychainHint_Gating(t *testing.T) {
	claude, err := tool.Get("claude")
	if err != nil {
		t.Fatalf("tool.Get(claude): %v", err)
	}
	dir := t.TempDir() // resolved config dir with NO .credentials.json

	// Baseline: Mac VM, no cred file, no API key, not resuming -> hint present.
	if macKeychainHint(claude, dir, vmhost.KindLimaLike, false, false) == "" {
		t.Fatal("expected a hint in a Mac VM with no credential file")
	}

	// Suppressed on Linux (KindUnknown).
	if got := macKeychainHint(claude, dir, vmhost.KindUnknown, false, false); got != "" {
		t.Errorf("no hint expected on Linux, got:\n%s", got)
	}
	// Suppressed when an API key is configured.
	if got := macKeychainHint(claude, dir, vmhost.KindLimaLike, true, false); got != "" {
		t.Errorf("no hint expected when API-key auth is configured, got:\n%s", got)
	}
	// Suppressed on a resumed session.
	if got := macKeychainHint(claude, dir, vmhost.KindLimaLike, false, true); got != "" {
		t.Errorf("no hint expected on resume, got:\n%s", got)
	}
	// Suppressed when the credential file is already present at the config dir.
	if err := os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := macKeychainHint(claude, dir, vmhost.KindLimaLike, false, false); got != "" {
		t.Errorf("no hint expected when the credential file already exists, got:\n%s", got)
	}
}

func TestAPIKeyAuthConfigured(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "") // ensure a clean baseline

	if apiKeyAuthConfigured(nil) {
		t.Error("no API key set or forwarded -> should be false")
	}
	if !apiKeyAuthConfigured([]string{"GITHUB_TOKEN", "ANTHROPIC_API_KEY"}) {
		t.Error("ANTHROPIC_API_KEY in forward list -> should be true")
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
	if !apiKeyAuthConfigured(nil) {
		t.Error("ANTHROPIC_API_KEY set in env -> should be true")
	}
}

// A tool without a Keychain credential (codex uses a file-based auth.json) must
// not implement the interface, so the hint never fires for it.
func TestCodexHasNoKeychainCredential(t *testing.T) {
	c, err := tool.Get("codex")
	if err != nil {
		t.Fatalf("tool.Get(codex): %v", err)
	}
	if kc, ok := c.(tool.ToolWithKeychainCredential); ok {
		if s, f := kc.KeychainCredential(); s != "" || f != "" {
			t.Errorf("codex should not advertise a keychain credential, got (%q, %q)", s, f)
		}
	}
}
