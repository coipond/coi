package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/tool"
	"github.com/coipond/coi/internal/vmhost"
)

// macKeychainHint returns a user-facing hint (or "") advising how to bring a
// tool's macOS-Keychain-stored login into the container. On macOS coi runs in
// the Linux guest VM and cannot read the Mac login Keychain (#818), so when a
// tool keeps its credential there — and no credential file exists at the
// resolved host config dir for coi to seed — it tells the user the exact
// command to materialize it on the Mac.
//
// It stays quiet when the hint would be a false positive: on Linux
// (KindUnknown), for tools without a Keychain credential, when the credential
// file is already present (it will be seeded), when the user authenticates via
// an API key (no Keychain needed), or when resuming a session that may already
// be logged in inside the container.
func macKeychainHint(t tool.Tool, cliConfigPath string, kind vmhost.Kind, apiKeyConfigured, resuming bool) string {
	if apiKeyConfigured || resuming {
		return ""
	}
	if cliConfigPath == "" || kind == vmhost.KindUnknown {
		return ""
	}
	kc, ok := t.(tool.ToolWithKeychainCredential)
	if !ok {
		return ""
	}
	service, credFile := kc.KeychainCredential()
	if service == "" || credFile == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(cliConfigPath, credFile)); err == nil {
		return "" // credential file present -> it will be seeded, no hint needed
	}
	return formatMacKeychainHint(t.Name(), t.ConfigDirName(), service, credFile)
}

// formatMacKeychainHint builds the hint message. Pure, so the wording is
// unit-testable without a VM.
func formatMacKeychainHint(toolName, configDirName, service, credFile string) string {
	return fmt.Sprintf(`Note: %s stores its login in the macOS Keychain, which coi (running inside the Linux VM) cannot read — this session may start logged out.
To bring your login across, run this ON YOUR MAC, then start coi again:

  security find-generic-password -s %q -w > ~/%s/%s

The token refreshes periodically; re-run if you get logged out again. See the macOS Setup Guide ("Claude auth on macOS").`,
		toolName, service, configDirName, credFile)
}

// printMacKeychainHint writes the hint (if any) to stderr. Called from the
// interactive shell seeding path once cliConfigPath has been VM-resolved. Not
// called from the headless `coi run` path, whose output an orchestrator
// consumes.
func printMacKeychainHint(t tool.Tool, cliConfigPath string, kind vmhost.Kind, apiKeyConfigured, resuming bool) {
	if hint := macKeychainHint(t, cliConfigPath, kind, apiKeyConfigured, resuming); hint != "" {
		fmt.Fprintln(os.Stderr, "\n"+hint)
	}
}

// anthropicAPIKeyEnv is the env var whose presence means Claude Code will
// authenticate with an API key and needs no Keychain-stored OAuth token.
const anthropicAPIKeyEnv = "ANTHROPIC_API_KEY" //nolint:gosec // G101 false positive: this is an env var NAME, not a credential value

// apiKeyAuthConfigured reports whether an API-key auth path is set up, so the
// Keychain hint should stay quiet. True when ANTHROPIC_API_KEY is set in the
// current environment or is listed for forwarding into the container.
func apiKeyAuthConfigured(forwardEnv []string) bool {
	if os.Getenv(anthropicAPIKeyEnv) != "" {
		return true
	}
	for _, name := range forwardEnv {
		if name == anthropicAPIKeyEnv {
			return true
		}
	}
	return false
}
