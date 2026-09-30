package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mensfeld/coi/internal/tool"
	"github.com/mensfeld/coi/internal/vmhost"
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

// Env vars whose presence means Claude Code authenticates without a
// Keychain-stored OAuth token: an API key, or a long-lived token from
// `claude setup-token` (set e.g. via [defaults.environment]).
var claudeAuthEnvVars = []string{
	"ANTHROPIC_API_KEY",       //nolint:gosec // G101 false positive: env var NAME, not a credential value
	"CLAUDE_CODE_OAUTH_TOKEN", //nolint:gosec // G101 false positive: env var NAME, not a credential value
}

// envAuthConfigured reports whether env-based auth is set up, so the Keychain
// hint should stay quiet. True when an auth env var is set in the current
// environment, listed for forwarding into the container, or set in
// [defaults.environment].
func envAuthConfigured(forwardEnv []string, environment map[string]string) bool {
	for _, name := range claudeAuthEnvVars {
		if os.Getenv(name) != "" {
			return true
		}
		if v, ok := environment[name]; ok && v != "" {
			return true
		}
		for _, f := range forwardEnv {
			if f == name {
				return true
			}
		}
	}
	return false
}
