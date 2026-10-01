package network

import (
	"testing"

	"github.com/coipond/coi/internal/config"
)

// When use_sudo=false, NftUsable must return false WITHOUT invoking sudo, so Coi
// behaves as if passwordless sudo were unavailable regardless of the real env
// (this is what makes the no-sudoers path testable on CI runners that do have
// blanket sudo).
func TestNftUsable_FalseWhenSudoDisabled(t *testing.T) {
	no := false
	cfg := &config.NetworkConfig{UseSudo: &no}
	if NftUsable(cfg) {
		t.Error("NftUsable should be false when use_sudo=false")
	}
}

// The process-wide gate makes every network sudo entry point behave as if
// passwordless sudo were unavailable, without invoking sudo.
func TestSudoGate_DisablesNftEntryPoints(t *testing.T) {
	t.Cleanup(func() { SetSudoAllowed(true) }) // restore default for other tests
	SetSudoAllowed(false)

	if SudoEnabled() {
		t.Fatal("SudoEnabled() should be false after SetSudoAllowed(false)")
	}
	if NftAvailable() {
		t.Error("NftAvailable() must return false (no sudo probe) when sudo disabled")
	}
	if NeedsIptablesFallback() {
		t.Error("NeedsIptablesFallback() must return false when sudo disabled")
	}
	if ForwardPolicyIsDrop() {
		t.Error("ForwardPolicyIsDrop() must return false (no sudo probe) when sudo disabled")
	}
	if err := ApplyBootBlockRule("coi-test"); err != nil {
		t.Errorf("ApplyBootBlockRule should no-op (nil) when sudo disabled, got %v", err)
	}
	if _, err := runNFTCommand("list", "tables"); err == nil {
		t.Error("runNFTCommand should refuse (error) when sudo disabled")
	}
}
