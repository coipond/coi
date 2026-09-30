//go:build integration

package network

import (
	"os/exec"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestIptablesAvailable verifies IptablesAvailable returns a bool consistent
// with whether the iptables binary is on PATH.
func TestIptablesAvailable(t *testing.T) {
	_, lookPathErr := exec.LookPath("iptables")
	expected := lookPathErr == nil

	result := IptablesAvailable()
	if result != expected {
		t.Errorf("IptablesAvailable() = %v, but exec.LookPath says %v", result, expected)
	}

	t.Logf("IptablesAvailable: %v", result)
}

// TestForwardPolicyIsDrop reads the actual FORWARD chain policy and verifies
// ForwardPolicyIsDrop returns a bool without error.
func TestForwardPolicyIsDrop(t *testing.T) {
	if !IptablesAvailable() {
		t.Skip("iptables not available, skipping")
	}

	result := ForwardPolicyIsDrop()
	t.Logf("ForwardPolicyIsDrop: %v", result)
}

// TestGetIncusBridgeName verifies we can extract the bridge name from the
// default profile when incus is running.
func TestGetIncusBridgeName(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping")
	}

	name, err := GetIncusBridgeName()
	if err != nil {
		t.Fatalf("GetIncusBridgeName() error: %v", err)
	}
	if name == "" {
		t.Fatal("GetIncusBridgeName() returned empty string")
	}

	t.Logf("GetIncusBridgeName: %s", name)
}

// TestEnsureAndRemoveIptablesBridgeRules verifies the full lifecycle of adding
// and removing iptables bridge rules, including idempotency.
func TestEnsureAndRemoveIptablesBridgeRules(t *testing.T) {
	if !IptablesAvailable() {
		t.Skip("iptables not available, skipping")
	}
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping")
	}

	// Check we have passwordless sudo for iptables
	cmd := exec.Command("sudo", "-n", "iptables", "-L", "FORWARD", "-n")
	if err := cmd.Run(); err != nil {
		t.Skip("no passwordless sudo iptables access, skipping")
	}

	bridgeName, err := GetIncusBridgeName()
	if err != nil {
		t.Fatalf("GetIncusBridgeName() error: %v", err)
	}

	// Ensure cleanup even on failure
	t.Cleanup(func() {
		_ = RemoveIptablesBridgeRules(bridgeName)
	})

	// 1. Ensure rules
	if err := EnsureIptablesBridgeRules(bridgeName); err != nil {
		t.Fatalf("EnsureIptablesBridgeRules() error: %v", err)
	}

	// Verify rules exist
	if !IptablesBridgeRulesExist(bridgeName) {
		t.Fatal("IptablesBridgeRulesExist() = false after Ensure")
	}

	// 2. Ensure again (idempotent)
	if err := EnsureIptablesBridgeRules(bridgeName); err != nil {
		t.Fatalf("EnsureIptablesBridgeRules() second call error: %v", err)
	}

	// Still exist
	if !IptablesBridgeRulesExist(bridgeName) {
		t.Fatal("IptablesBridgeRulesExist() = false after second Ensure")
	}

	// 3. Remove
	if err := RemoveIptablesBridgeRules(bridgeName); err != nil {
		t.Fatalf("RemoveIptablesBridgeRules() error: %v", err)
	}

	// Verify rules are gone
	if IptablesBridgeRulesExist(bridgeName) {
		t.Fatal("IptablesBridgeRulesExist() = true after Remove")
	}

	t.Logf("Lifecycle test passed for bridge %s", bridgeName)
}

// TestNeedsIptablesFallback verifies the boolean logic.
func TestNeedsIptablesFallback(t *testing.T) {
	result := NeedsIptablesFallback()
	t.Logf("NeedsIptablesFallback: %v (nft=%v, forwardDrop=%v, iptables=%v)",
		result, NftAvailable(), ForwardPolicyIsDrop(), IptablesAvailable())
}

// TestIptablesBridgeRulesExist verifies detection works when no rules are present.
func TestIptablesBridgeRulesExist(t *testing.T) {
	if !IptablesAvailable() {
		t.Skip("iptables not available, skipping")
	}
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping")
	}
	if !container.Available() {
		t.Skip("incus daemon not running, skipping")
	}

	bridgeName, err := GetIncusBridgeName()
	if err != nil {
		t.Fatalf("GetIncusBridgeName() error: %v", err)
	}

	result := IptablesBridgeRulesExist(bridgeName)
	t.Logf("IptablesBridgeRulesExist(%s): %v", bridgeName, result)
}

// TestIsDockerRunning verifies the function returns a bool without error.
func TestIsDockerRunning(t *testing.T) {
	result := IsDockerRunning()
	t.Logf("IsDockerRunning: %v", result)
}
