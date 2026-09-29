//go:build integration

package nftmonitor

import (
	"os/exec"
	"testing"
)

// Coi should be able to parse the real nftables version from `nft --version` output
// and the parsed major version should fall within a reasonable range (0-99).
func TestNFTVersionIntegration(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not found, skipping integration test")
	}

	cmd := exec.Command("nft", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft --version failed: %v", err)
	}

	versionStr, err := ExtractNFTVersion(string(output))
	if err != nil {
		t.Fatalf("ExtractNFTVersion failed on real output %q: %v", string(output), err)
	}

	v, err := ParseNFTVersion(versionStr)
	if err != nil {
		t.Fatalf("ParseNFTVersion failed on %q: %v", versionStr, err)
	}

	t.Logf("Parsed nft version: major=%d minor=%d patch=%d raw=%q", v.Major, v.Minor, v.Patch, v.Raw)

	if v.Major < 0 || v.Major > 99 {
		t.Errorf("major version %d outside reasonable range [0, 99]", v.Major)
	}
}
