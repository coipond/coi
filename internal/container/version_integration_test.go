//go:build integration

package container

import (
	"os/exec"
	"testing"
)

// Coi should be able to parse the real Incus server version from `incus version` output
// and the parsed major version should fall within a reasonable range (5-99).
func TestIncusVersionIntegration(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	output, err := IncusOutput("version")
	if err != nil {
		t.Fatalf("incus version failed: %v", err)
	}

	versionStr, err := ExtractServerVersion(output)
	if err != nil {
		t.Fatalf("ExtractServerVersion failed on real output %q: %v", output, err)
	}

	v, err := ParseIncusVersion(versionStr)
	if err != nil {
		t.Fatalf("ParseIncusVersion failed on %q: %v", versionStr, err)
	}

	t.Logf("Parsed Incus version: major=%d minor=%d raw=%q", v.Major, v.Minor, v.Raw)

	if v.Major < 5 || v.Major > 99 {
		t.Errorf("major version %d outside reasonable range [5, 99]", v.Major)
	}
}

// CheckMinimumVersion should return nil (no error) when the running Incus daemon meets the
// minimum version requirement, or a non-nil error containing "zabbly" when it does not.
// On a system with Incus >= 6.1 this test expects nil; on older Incus it expects an error.
func TestCheckMinimumVersionIntegration(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}
	if !Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	err := CheckMinimumVersion()

	// Get the actual version so we can verify the result makes sense
	output, verr := IncusOutput("version")
	if verr != nil {
		t.Logf("Could not get version for verification: %v", verr)
		return
	}
	versionStr, verr := ExtractServerVersion(output)
	if verr != nil {
		t.Logf("Could not extract version for verification: %v", verr)
		return
	}
	v, verr := ParseIncusVersion(versionStr)
	if verr != nil {
		t.Logf("Could not parse version for verification: %v", verr)
		return
	}

	if MeetsMinimumVersion(v) {
		if err != nil {
			t.Errorf("Version %s meets minimum but CheckMinimumVersion returned error: %v", versionStr, err)
		}
	} else {
		if err == nil {
			t.Errorf("Version %s is below minimum but CheckMinimumVersion returned nil", versionStr)
		}
	}

	t.Logf("CheckMinimumVersion: version=%s err=%v", versionStr, err)
}
