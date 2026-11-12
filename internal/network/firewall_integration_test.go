//go:build integration

package network

import (
	"os/exec"
	"testing"
)

// NftAvailable should return true when nft is installed and passwordless sudo works.
func TestNftAvailable_Integration(t *testing.T) {
	_, lookPathErr := exec.LookPath("nft")
	installed := lookPathErr == nil

	if !installed {
		t.Log("nft not installed — expecting NftAvailable() == false")
		if NftAvailable() {
			t.Error("NftAvailable() returned true but nft is not installed")
		}
		return
	}

	// nft is installed; check if passwordless sudo works
	cmd := exec.Command("sudo", "-n", "nft", "list", "tables")
	sudoOK := cmd.Run() == nil

	result := NftAvailable()
	if result != sudoOK {
		t.Errorf("NftAvailable() = %v, but sudo nft list tables returned %v", result, sudoOK)
	}

	t.Logf("NftAvailable: installed=%v sudoOK=%v result=%v", installed, sudoOK, result)
}

// NftInstalled should return true when the nft binary exists on PATH.
func TestNftInstalled_Integration(t *testing.T) {
	_, lookPathErr := exec.LookPath("nft")
	expected := lookPathErr == nil

	result := NftInstalled()
	if result != expected {
		t.Errorf("NftInstalled() = %v, but exec.LookPath(\"nft\") says %v", result, expected)
	}

	t.Logf("NftInstalled: %v", result)
}

// MasqueradeEnabled should return true when the Incus bridge has ipv4.nat=true.
func TestMasqueradeEnabled_Integration(t *testing.T) {
	bridgeName, err := GetIncusBridgeName()
	if err != nil || bridgeName == "" {
		t.Skip("Incus bridge not available — skipping MasqueradeEnabled test")
	}

	// Query Incus directly to compare
	cmd := exec.Command("incus", "network", "get", bridgeName, "ipv4.nat")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("could not query incus bridge nat setting: %v", err)
	}

	natEnabled := string(out) == "true\n" || string(out) == "true"
	result := MasqueradeEnabled()
	if result != natEnabled {
		t.Errorf("MasqueradeEnabled() = %v, but incus bridge ipv4.nat = %v", result, natEnabled)
	}

	t.Logf("MasqueradeEnabled: %v", result)
}

// EnsureBridgeInTrustedZone manages iptables FORWARD ACCEPT rules for the Incus bridge.
// The test verifies the function works correctly and cleans up after itself.
func TestEnsureBridgeInTrustedZone_Integration(t *testing.T) {
	bridgeName, err := GetIncusBridgeName()
	if err != nil || bridgeName == "" {
		t.Skip("Incus bridge not available — skipping EnsureBridgeInTrustedZone test")
	}
	t.Logf("bridge: %s", bridgeName)

	initiallyHasRules := IptablesBridgeRulesExist(bridgeName)
	t.Logf("initial state: hasRules=%v", initiallyHasRules)

	// Restore initial state on exit.
	t.Cleanup(func() {
		if initiallyHasRules {
			_ = EnsureIptablesBridgeRules(bridgeName)
		} else {
			_ = RemoveIptablesBridgeRules(bridgeName)
		}
	})

	// Remove rules so we can exercise the "missing → add it" path.
	if initiallyHasRules {
		if err := RemoveIptablesBridgeRules(bridgeName); err != nil {
			t.Skipf("could not remove bridge rules (sudoers?): %v", err)
		}
	}

	if IptablesBridgeRulesExist(bridgeName) {
		t.Skip("bridge rules still present after removal — skipping")
	}

	// First call: should add the missing rules and report changed=true.
	ResetBridgeForwardMemo()
	changed, name, err := EnsureBridgeInTrustedZone()
	if err != nil {
		t.Fatalf("EnsureBridgeInTrustedZone() first call: %v", err)
	}
	if !changed {
		t.Errorf("EnsureBridgeInTrustedZone() first call: expected changed=true, got false (bridge=%q)", name)
	}
	if name != bridgeName {
		t.Errorf("EnsureBridgeInTrustedZone() first call: bridge name = %q, want %q", name, bridgeName)
	}

	// Verify rules are now in place.
	if !IptablesBridgeRulesExist(bridgeName) {
		t.Errorf("bridge rules not present after successful EnsureBridgeInTrustedZone")
	}

	// Second call: it acts once per process, so it reports changed=false.
	changed, name, err = EnsureBridgeInTrustedZone()
	if err != nil {
		t.Fatalf("EnsureBridgeInTrustedZone() second call: %v", err)
	}
	if changed {
		t.Errorf("EnsureBridgeInTrustedZone() second call: expected changed=false (once per process), got true")
	}
	if name != bridgeName {
		t.Errorf("EnsureBridgeInTrustedZone() second call: bridge name = %q, want %q", name, bridgeName)
	}
}
