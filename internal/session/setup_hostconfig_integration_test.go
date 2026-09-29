//go:build integration

package session

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/tool"
	"github.com/mensfeld/coi/internal/vmhost"
)

// TestMacHomeConfigSeeding_Integration reproduces the macOS/Colima credential
// gap and its Fix A resolution end-to-end: on a Mac VM the guest home (e.g.
// /home/lima) has no ~/.claude, while the Mac user's real config is visible
// under a shared /Users mount. vmhost.ResolveHostConfigDir must pick the shared
// path, and seeding from it must land the credentials inside a real container —
// so `coi shell` boots an authenticated tool instead of a fresh auth flow.
//
// The VM-detection + /proc/mounts scan of HostToolConfigDir can't be driven
// from a test (the temp "Mac home" isn't a real virtiofs mount under /Users),
// so we exercise the pure resolver against a real filesystem and then feed its
// choice through the same setupCLIConfig path production uses.
func TestMacHomeConfigSeeding_Integration(t *testing.T) {
	skipUnlessContextFileTestable(t)

	// Guest home: has a .claude that holds only a stray, non-config file — this
	// must NOT count as "real config" and must NOT shadow the shared Mac home.
	guestHome := t.TempDir()
	guestClaude := filepath.Join(guestHome, ".claude")
	if err := os.MkdirAll(guestClaude, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guestClaude, ".DS_Store"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Shared Mac home, KEYCHAIN-ONLY: the config dir has NO .credentials.json
	// (the OAuth token lives in the macOS Keychain) and none of the other marker
	// files — only non-config state, so it is merely non-empty. It is still the
	// user's real home and must be chosen so the sibling onboarding state seeds.
	// This is exactly the case the strict marker-only check regressed (#1).
	macHome := t.TempDir()
	macClaude := filepath.Join(macHome, ".claude")
	if err := os.MkdirAll(macClaude, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macClaude, "history.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A sibling ~/.claude.json (onboarding state) lives next to the dir; seeding
	// resolves it relative to the chosen config dir's parent.
	const stateJSON = `{"hasCompletedOnboarding":true}`
	if err := os.WriteFile(filepath.Join(macHome, ".claude.json"), []byte(stateJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Asymmetric selection: the guest (stray file only) must lose because it
	// holds no real config file; the keychain-only Mac home must win because it
	// merely exists and is non-empty — even though it too has no marker file.
	markers := []string{".credentials.json", "config.yml", "settings.json", "CLAUDE.md"}
	guestHasConfig := func(p string) bool {
		for _, f := range markers {
			if _, err := os.Stat(filepath.Join(p, f)); err == nil {
				return true
			}
		}
		return false
	}
	candidateUsable := func(p string) bool {
		entries, err := os.ReadDir(p)
		return err == nil && len(entries) > 0
	}
	resolved := vmhost.ResolveHostConfigDir(guestClaude, []string{macClaude}, guestHasConfig, candidateUsable)
	if resolved != macClaude {
		t.Fatalf("ResolveHostConfigDir picked %q, want keychain-only Mac home %q", resolved, macClaude)
	}

	// Seed from the resolved path into a real container, exactly as the shell/run
	// pipelines do once cliConfigPath has been VM-resolved.
	claude, err := tool.Get("claude")
	if err != nil {
		t.Fatalf("Get(claude): %v", err)
	}
	tcf, ok := claude.(tool.ToolWithConfigDirFiles)
	if !ok {
		t.Fatal("ClaudeTool must implement ToolWithConfigDirFiles")
	}

	mgr := launchContextTestContainer(t, "coi-test-machome-seed")
	homeDir := "/home/" + container.CodeUser
	logger := func(msg string) { t.Logf("[machome] %s", msg) }

	if err := setupCLIConfig(mgr, resolved, homeDir, tcf, logger); err != nil {
		t.Fatalf("setupCLIConfig: %v", err)
	}

	// The sibling state file (~/.claude.json) was seeded from the keychain-only
	// Mac home — this is what suppresses the theme/onboarding prompt, and is
	// precisely what the strict marker-only check would have skipped by falling
	// back to the (config-less) guest path.
	statePath := filepath.Join(homeDir, ".claude.json")
	gotState, err := mgr.ExecCommand(fmt.Sprintf("cat %s 2>/dev/null || true", statePath), container.ExecCommandOptions{Capture: true})
	if err != nil {
		t.Fatalf("reading seeded state file: %v", err)
	}
	if gotState != stateJSON {
		t.Errorf("seeded state file = %q, want %q (onboarding state must come from the Mac home)", gotState, stateJSON)
	}
}
