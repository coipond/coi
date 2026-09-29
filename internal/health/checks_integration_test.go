//go:build integration

package health

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/network"
	"github.com/mensfeld/coi/internal/nftmonitor"
)

// CheckIncus should return a parseable version string in its details and the status should
// match the version: StatusOK when >= 6.1 (with version in message), StatusFailed when below
// (with zabbly upgrade link in message).
func TestCheckIncus_VersionCheck(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	result := CheckIncus()

	if result.Name != "incus" {
		t.Errorf("Expected check name 'incus', got '%s'", result.Name)
	}

	// Should be OK or Warning (version too old)
	if result.Status != StatusOK && result.Status != StatusWarning {
		t.Errorf("Expected StatusOK or StatusWarning, got %s: %s", result.Status, result.Message)
	}

	// Details should contain a version
	if result.Details == nil || result.Details["version"] == nil {
		t.Error("Expected 'version' in details")
	}

	versionStr, ok := result.Details["version"].(string)
	if !ok || versionStr == "" {
		t.Errorf("Expected non-empty version string in details, got %v", result.Details["version"])
	}

	// Verify the version is parseable
	v, err := container.ParseIncusVersion(versionStr)
	if err != nil {
		t.Fatalf("Version from CheckIncus (%q) should be parseable: %v", versionStr, err)
	}

	if container.MeetsMinimumVersion(v) {
		// At or above the hard minimum the check is StatusOK — including the
		// [6.1, recommended) band, which only adds an advisory note so `coi
		// health` exit 0 is preserved on supported hosts.
		if result.Status != StatusOK {
			t.Errorf("Version %s meets the minimum but status is %s: %s", versionStr, result.Status, result.Message)
		}
		if !strings.Contains(result.Message, versionStr) {
			t.Errorf("Message should contain version %q, got %q", versionStr, result.Message)
		}
	} else {
		if result.Status != StatusWarning {
			t.Errorf("Version %s is below minimum but status is %s", versionStr, result.Status)
		}
		if !strings.Contains(result.Message, "zabbly") {
			t.Errorf("Warning message should mention zabbly, got %q", result.Message)
		}
	}

	t.Logf("CheckIncus: status=%s version=%s message=%s", result.Status, versionStr, result.Message)
}

// evaluateIncusVersion should return StatusWarning with zabbly upgrade instructions for old versions
// (6.0.x, 5.x), StatusWarning with "recommended" advice for versions between the hard minimum and
// the recommended floor, StatusOK for recommended-or-newer versions, and degrade gracefully
// (StatusOK) when the version output is unparseable or empty.
func TestEvaluateIncusVersion_OldVersion(t *testing.T) {
	tests := []struct {
		name           string
		versionOutput  string
		expectStatus   CheckStatus
		expectContains string
	}{
		{
			"Ubuntu 6.0.x warns",
			"Client version: 6.0.3\nServer version: 6.0.3",
			StatusWarning,
			"zabbly",
		},
		{
			"6.0.0 warns",
			"Client version: 6.0.0\nServer version: 6.0.0",
			StatusWarning,
			"6.1",
		},
		{
			"5.x warns",
			"Server version: 5.21",
			StatusWarning,
			"zabbly",
		},
		{
			"6.1 meets the minimum; recommended-floor note stays StatusOK (must not flip exit code)",
			"Client version: 6.1\nServer version: 6.1",
			StatusOK,
			"recommended",
		},
		{
			"6.20 passes",
			"Client version: 6.20\nServer version: 6.20",
			StatusOK,
			"6.20",
		},
		{
			"7.0 passes",
			"Server version: 7.0",
			StatusOK,
			"7.0",
		},
		{
			"single line fallback",
			"6.0.1",
			StatusWarning,
			"zabbly",
		},
		{
			"unparseable degrades gracefully",
			"Server version: unknown-dev",
			StatusOK,
			"unknown-dev",
		},
		{
			"empty output degrades gracefully",
			"",
			StatusOK,
			"version unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateIncusVersion(tt.versionOutput)

			if result.Name != "incus" {
				t.Errorf("Expected check name 'incus', got %q", result.Name)
			}
			if result.Status != tt.expectStatus {
				t.Errorf("Expected status %s, got %s: %s", tt.expectStatus, result.Status, result.Message)
			}
			if !strings.Contains(result.Message, tt.expectContains) {
				t.Errorf("Expected message to contain %q, got %q", tt.expectContains, result.Message)
			}
		})
	}
}

// CheckNFTables should return a parseable version string in its details and the status should
// match the version: StatusOK when >= 0.9.0 (with version in message), StatusFailed when below.
// If sudo access is not configured, StatusWarning is acceptable even when the version is fine.
func TestCheckNFTables_VersionCheck(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not found, skipping integration test")
	}

	result := CheckNFTables()

	if result.Name != "nftables" {
		t.Errorf("Expected check name 'nftables', got '%s'", result.Name)
	}

	// Details should contain a version
	if result.Details == nil || result.Details["version"] == nil {
		t.Skipf("No version in details (nft --version may have failed): %s", result.Message)
	}

	versionStr, ok := result.Details["version"].(string)
	if !ok || versionStr == "" {
		t.Errorf("Expected non-empty version string in details, got %v", result.Details["version"])
	}

	// Verify the version is parseable
	v, err := nftmonitor.ParseNFTVersion(versionStr)
	if err != nil {
		t.Fatalf("Version from CheckNFTables (%q) should be parseable: %v", versionStr, err)
	}

	if nftmonitor.MeetsMinimumNFTVersion(v) {
		// Version meets minimum — status should be OK (if sudo works) or Warning (sudo issue)
		if result.Status == StatusFailed {
			t.Errorf("Version %s meets minimum but status is Failed: %s", versionStr, result.Message)
		}
		if result.Status == StatusOK && !strings.Contains(result.Message, versionStr) {
			t.Errorf("OK message should contain version %q, got %q", versionStr, result.Message)
		}
	} else {
		if result.Status != StatusWarning {
			t.Errorf("Version %s is below minimum but status is %s", versionStr, result.Status)
		}
	}

	t.Logf("CheckNFTables: status=%s version=%s message=%s", result.Status, versionStr, result.Message)
}

// evaluateNFTVersion should return a StatusWarning HealthCheck for old versions (0.8.x, 0.7.x),
// nil for versions meeting minimum (0.9.0+, 1.x), and nil when the version output is
// unparseable or empty (graceful degradation, version check is skipped).
func TestEvaluateNFTVersion_OldVersion(t *testing.T) {
	tests := []struct {
		name           string
		versionOutput  string
		expectFailed   bool
		expectContains string
	}{
		{
			"0.8.3 fails",
			"nftables v0.8.3 (Topsy)",
			true,
			"0.9.0",
		},
		{
			"0.7.0 fails",
			"nftables v0.7.0 (Scruffy)",
			true,
			"nftables",
		},
		{
			"0.9.0 passes",
			"nftables v0.9.0 (Fearless Fosdick)",
			false,
			"",
		},
		{
			"1.0.9 passes",
			"nftables v1.0.9 (Old Doc Yak #3)",
			false,
			"",
		},
		{
			"unparseable returns nil",
			"some garbage output",
			false,
			"",
		},
		{
			"empty returns nil",
			"",
			false,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateNFTVersion("/usr/sbin/nft", tt.versionOutput)

			if tt.expectFailed {
				if result == nil {
					t.Fatal("Expected a failed HealthCheck, got nil")
				}
				if result.Status != StatusWarning {
					t.Errorf("Expected StatusWarning, got %s: %s", result.Status, result.Message)
				}
				if !strings.Contains(result.Message, tt.expectContains) {
					t.Errorf("Expected message to contain %q, got %q", tt.expectContains, result.Message)
				}
			} else {
				if result != nil {
					t.Errorf("Expected nil (version OK or unparseable), got status=%s: %s", result.Status, result.Message)
				}
			}
		})
	}
}

// CheckContainerConnectivity should return StatusWarning with "Skipped" and "image not available"
// when the specified image does not exist, rather than attempting to launch a container.
func TestCheckContainerConnectivity_NoImage(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Use a non-existent image name
	result := CheckContainerConnectivity("non-existent-image-12345", container.DefaultHardeningPolicy())

	if result.Name != "container_connectivity" {
		t.Errorf("Expected check name 'container_connectivity', got '%s'", result.Name)
	}

	if result.Status != StatusWarning {
		t.Errorf("Expected StatusWarning when image doesn't exist, got %s", result.Status)
	}

	if !strings.Contains(result.Message, "Skipped") || !strings.Contains(result.Message, "image not available") {
		t.Errorf("Expected message about skipped/image not available, got '%s'", result.Message)
	}

	t.Logf("Correctly skipped check for non-existent image: %s", result.Message)
}

// CheckContainerConnectivity should complete without hanging when a valid image exists,
// return a definitive status (OK/Warning/Failed), and leave no leftover health-check containers.
func TestCheckContainerConnectivity_WithImage(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Run the actual connectivity check
	result := CheckContainerConnectivity("coi-default", container.DefaultHardeningPolicy())

	if result.Name != "container_connectivity" {
		t.Errorf("Expected check name 'container_connectivity', got '%s'", result.Name)
	}

	// The check should complete (not hang) and return a definitive status
	switch result.Status {
	case StatusOK:
		t.Logf("Container connectivity check passed: %s", result.Message)
		if result.Details != nil {
			t.Logf("Details: dns_test=%v, http_test=%v", result.Details["dns_test"], result.Details["http_test"])
		}
	case StatusWarning:
		t.Logf("Container connectivity check warning: %s", result.Message)
	case StatusFailed:
		t.Logf("Container connectivity check failed (expected if network is misconfigured): %s", result.Message)
	default:
		t.Errorf("Unexpected status: %s", result.Status)
	}

	// Verify no leftover containers
	containers, err := container.ListContainers("^coi-health-check-")
	if err != nil {
		t.Errorf("Failed to list containers: %v", err)
	}
	if len(containers) > 0 {
		t.Errorf("Found leftover health check containers: %v", containers)
	}
}

// CheckContainerConnectivity should default to the "coi-default" image when called with an empty
// image name, skipping with StatusWarning if the default image doesn't exist or running
// the full check if it does.
func TestCheckContainerConnectivity_EmptyImageName(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil {
		t.Skip("could not check for coi image, skipping integration test")
	}

	// Run with empty image name
	result := CheckContainerConnectivity("", container.DefaultHardeningPolicy())

	if result.Name != "container_connectivity" {
		t.Errorf("Expected check name 'container_connectivity', got '%s'", result.Name)
	}

	if !exists {
		// Should be skipped if image doesn't exist
		if result.Status != StatusWarning {
			t.Errorf("Expected StatusWarning when default image doesn't exist, got %s", result.Status)
		}
		t.Logf("Correctly handled missing default image: %s", result.Message)
	} else {
		// Should run the check if image exists
		if result.Status == StatusWarning && strings.Contains(result.Message, "Skipped") {
			t.Errorf("Should not skip when default coi image exists, got: %s", result.Message)
		}
		t.Logf("Check ran with default image: status=%s, message=%s", result.Status, result.Message)
	}
}

// CheckContainerConnectivity should not leak containers even after multiple consecutive runs;
// the number of coi-health-check-* containers after 3 checks should not exceed the count before.
func TestCheckContainerConnectivity_Cleanup(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test")
	}

	// Count containers before
	containersBefore, _ := container.ListContainers("^coi-health-check-")

	// Run multiple checks to ensure cleanup works
	for i := 0; i < 3; i++ {
		_ = CheckContainerConnectivity("coi-default", container.DefaultHardeningPolicy())
	}

	// Count containers after
	containersAfter, err := container.ListContainers("^coi-health-check-")
	if err != nil {
		t.Errorf("Failed to list containers: %v", err)
	}

	if len(containersAfter) > len(containersBefore) {
		t.Errorf("Found %d new leftover containers after running checks: %v",
			len(containersAfter)-len(containersBefore), containersAfter)
	} else {
		t.Logf("Cleanup verified: no leftover containers after %d checks", 3)
	}
}

// CheckNft should return a details map containing nft_installed, nft_available, and masquerade
// booleans, and the status should reflect the actual nft state.
func TestCheckNft_DetailedStatus(t *testing.T) {
	installed := network.NftInstalled()
	available := network.NftAvailable()
	masquerade := network.MasqueradeEnabled()

	modes := []config.NetworkMode{
		config.NetworkModeOpen,
		config.NetworkModeRestricted,
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			result := CheckNft(config.NetworkConfig{Mode: mode})

			if result.Name != "nft" {
				t.Errorf("Expected check name 'nft', got %q", result.Name)
			}

			// Verify details map has the expected keys
			if result.Details == nil {
				t.Fatal("Expected non-nil Details map")
			}

			for _, key := range []string{"nft_installed", "nft_available", "masquerade"} {
				val, ok := result.Details[key]
				if !ok {
					t.Errorf("Expected %q key in details", key)
					continue
				}
				if _, isBool := val.(bool); !isBool {
					t.Errorf("Expected %q to be bool, got %T", key, val)
				}
			}

			// Verify detail values match actual system state
			if result.Details["nft_installed"] != installed {
				t.Errorf("details[nft_installed] = %v, want %v", result.Details["nft_installed"], installed)
			}
			if result.Details["nft_available"] != available {
				t.Errorf("details[nft_available] = %v, want %v", result.Details["nft_available"], available)
			}
			if result.Details["masquerade"] != masquerade {
				t.Errorf("details[masquerade] = %v, want %v", result.Details["masquerade"], masquerade)
			}

			// Verify status logic
			if mode == config.NetworkModeOpen {
				if result.Status != StatusOK {
					t.Errorf("Open mode should always be StatusOK, got %s: %s", result.Status, result.Message)
				}
			} else {
				// restricted/allowlist mode
				switch {
				case !installed || !available:
					if result.Status != StatusFailed {
						t.Errorf("Expected StatusFailed when nft not available, got %s: %s", result.Status, result.Message)
					}
				case !masquerade:
					if result.Status != StatusWarning {
						t.Errorf("Expected StatusWarning when masquerade disabled, got %s: %s", result.Status, result.Message)
					}
				default:
					if result.Status != StatusOK {
						t.Errorf("Expected StatusOK when fully configured, got %s: %s", result.Status, result.Message)
					}
				}
			}

			t.Logf("CheckNft(%s): status=%s installed=%v available=%v masquerade=%v message=%s",
				mode, result.Status, installed, available, masquerade, result.Message)
		})
	}
}

// CheckNetworkRestriction should return StatusWarning with "nft not available" when
// nft is not installed or passwordless sudo is not configured.
func TestCheckNetworkRestriction_NoFirewall(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// This test only makes sense if firewall is NOT available
	if network.NftAvailable() {
		t.Skip("nft is available, cannot test no-firewall scenario")
	}

	result := CheckNetworkRestriction("coi-default", container.DefaultHardeningPolicy())

	if result.Name != "network_restriction" {
		t.Errorf("Expected check name 'network_restriction', got '%s'", result.Name)
	}

	if result.Status != StatusWarning {
		t.Errorf("Expected StatusWarning when firewall not available, got %s", result.Status)
	}

	if !strings.Contains(result.Message, "nft not available") {
		t.Errorf("Expected message about nft not available, got '%s'", result.Message)
	}

	t.Logf("Correctly skipped check when firewall unavailable: %s", result.Message)
}

// CheckNetworkRestriction should return StatusWarning with "image not available" when the
// specified image does not exist, rather than attempting to launch a container.
func TestCheckNetworkRestriction_NoImage(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Use a non-existent image name
	result := CheckNetworkRestriction("non-existent-image-12345", container.DefaultHardeningPolicy())

	if result.Name != "network_restriction" {
		t.Errorf("Expected check name 'network_restriction', got '%s'", result.Name)
	}

	if result.Status != StatusWarning {
		t.Errorf("Expected StatusWarning when image doesn't exist, got %s", result.Status)
	}

	if !strings.Contains(result.Message, "image not available") {
		t.Errorf("Expected message about image not available, got '%s'", result.Message)
	}

	t.Logf("Correctly skipped check for non-existent image: %s", result.Message)
}

// CheckNetworkRestriction should complete and return a definitive status (OK/Warning/Failed)
// when both nft and the Coi image are available, and leave no leftover restriction-check
// containers afterwards.
func TestCheckNetworkRestriction_WithImage(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test (run 'coi build' first)")
	}

	// Run the network restriction check
	result := CheckNetworkRestriction("coi-default", container.DefaultHardeningPolicy())

	if result.Name != "network_restriction" {
		t.Errorf("Expected check name 'network_restriction', got '%s'", result.Name)
	}

	// The check should complete and return a definitive status
	switch result.Status {
	case StatusOK:
		t.Logf("Network restriction check passed: %s", result.Message)
		if result.Details != nil {
			t.Logf("Details: external_access=%v, private_blocked=%v",
				result.Details["external_access"], result.Details["private_blocked"])
		}
	case StatusWarning:
		t.Logf("Network restriction check warning: %s", result.Message)
	case StatusFailed:
		t.Logf("Network restriction check failed: %s", result.Message)
		if result.Details != nil {
			t.Logf("Details: %v", result.Details)
		}
	default:
		t.Errorf("Unexpected status: %s", result.Status)
	}

	// Verify no leftover containers
	containers, err := container.ListContainers("^coi-restriction-check-")
	if err != nil {
		t.Errorf("Failed to list containers: %v", err)
	}
	if len(containers) > 0 {
		t.Errorf("Found leftover restriction check containers: %v", containers)
	}
}

// CheckNetworkRestriction should not leak containers; the number of coi-restriction-check-*
// containers after the check should not exceed the count before.
func TestCheckNetworkRestriction_Cleanup(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Skip if firewall is not available
	if !network.NftAvailable() {
		t.Skip("nft not available, skipping integration test")
	}

	// Check if the default 'coi' image exists
	exists, err := container.ImageExists("coi-default")
	if err != nil || !exists {
		t.Skip("coi image not found, skipping integration test")
	}

	// Count containers before
	containersBefore, _ := container.ListContainers("^coi-restriction-check-")

	// Run the check
	_ = CheckNetworkRestriction("coi-default", container.DefaultHardeningPolicy())

	// Count containers after
	containersAfter, err := container.ListContainers("^coi-restriction-check-")
	if err != nil {
		t.Errorf("Failed to list containers: %v", err)
	}

	if len(containersAfter) > len(containersBefore) {
		t.Errorf("Found %d new leftover containers after check: %v",
			len(containersAfter)-len(containersBefore), containersAfter)
	} else {
		t.Logf("Cleanup verified: no leftover containers after restriction check")
	}
}

// CheckAuditLogDirectory should return StatusOK with a non-empty path in details, confirming
// the audit log directory is accessible.
func TestCheckAuditLogDirectory(t *testing.T) {
	result := CheckAuditLogDirectory()

	if result.Name != "audit_log_directory" {
		t.Errorf("Expected check name 'audit_log_directory', got '%s'", result.Name)
	}

	if result.Status != StatusOK {
		t.Errorf("Expected StatusOK for audit log directory, got %s: %s",
			result.Status, result.Message)
	}

	if result.Details["path"] == nil {
		t.Error("Expected 'path' in details")
	}

	t.Logf("Audit log directory check passed: %s", result.Message)
}

// CheckCgroupAvailability should return StatusOK (cgroups v2) or StatusWarning (cgroups v1)
// with a non-empty path in details, confirming the cgroup filesystem is mounted.
func TestCheckCgroupAvailability(t *testing.T) {
	result := CheckCgroupAvailability()

	if result.Name != "cgroup_availability" {
		t.Errorf("Expected check name 'cgroup_availability', got '%s'", result.Name)
	}

	// Should be OK or Warning (v1 vs v2)
	if result.Status != StatusOK && result.Status != StatusWarning {
		t.Errorf("Expected StatusOK or StatusWarning for cgroups, got %s: %s",
			result.Status, result.Message)
	}

	if result.Details["path"] == nil {
		t.Error("Expected 'path' in details")
	}

	t.Logf("Cgroup availability check: %s (status: %s)", result.Message, result.Status)
}

// CheckMonitoringConfiguration should return StatusOK or StatusWarning with an "enabled"
// boolean in details, depending on whether monitoring is configured in the default config.
func TestCheckMonitoringConfiguration(t *testing.T) {
	// Use default config
	cfg := config.GetDefaultConfig()

	result := CheckMonitoringConfiguration(cfg)

	if result.Name != "monitoring_configuration" {
		t.Errorf("Expected check name 'monitoring_configuration', got '%s'", result.Name)
	}

	// Should be OK or Warning depending on if monitoring is enabled
	if result.Status != StatusOK && result.Status != StatusWarning {
		t.Errorf("Expected StatusOK or StatusWarning for monitoring config, got %s: %s",
			result.Status, result.Message)
	}

	if result.Details["enabled"] == nil {
		t.Error("Expected 'enabled' in details")
	}

	t.Logf("Monitoring configuration check: %s (enabled: %v)",
		result.Message, result.Details["enabled"])
}

// CheckIncusStoragePools should return sane values for every inspected pool:
// non-negative free space, used percentage between 0 and 100, and positive
// total space. This guards against the unit-mismatch bug where Incus reports
// "space used" in MiB and "total space" in GiB on fresh pools, which previously
// caused negative free space and >100% usage.
func TestCheckIncusStoragePools_SaneValues(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Pass nil to exercise the default-pool fallback path.
	result := CheckIncusStoragePools(nil)

	if result.Name != "incus_storage_pools" {
		t.Errorf("Expected check name 'incus_storage_pools', got %q", result.Name)
	}

	// The check must return a valid status
	if result.Status != StatusOK && result.Status != StatusWarning && result.Status != StatusFailed {
		t.Errorf("Unexpected status: %s", result.Status)
	}

	if len(result.Details) == 0 {
		t.Skipf("No per-pool details returned (no pools resolvable): %s", result.Message)
	}

	for poolName, raw := range result.Details {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			t.Errorf("Expected details[%q] to be map[string]interface{}, got %T", poolName, raw)
			continue
		}

		// Pools that failed to query won't have usage stats — skip them with a log.
		if statusStr, _ := entry["status"].(string); statusStr == string(StatusFailed) {
			t.Logf("Pool %q reported failed status: %v", poolName, entry)
			continue
		}

		for _, key := range []string{"driver", "used_gib", "total_gib", "free_gib", "used_pct"} {
			if _, ok := entry[key]; !ok {
				t.Errorf("Expected %q key in details[%q]", key, poolName)
			}
		}

		if driver, _ := entry["driver"].(string); driver == "" {
			t.Errorf("Expected non-empty driver in details[%q]", poolName)
		}

		totalGiB, ok := entry["total_gib"].(float64)
		if !ok {
			t.Fatalf("Expected details[%q][\"total_gib\"] to be float64, got %T", poolName, entry["total_gib"])
		}
		freeGiB, ok := entry["free_gib"].(float64)
		if !ok {
			t.Fatalf("Expected details[%q][\"free_gib\"] to be float64, got %T", poolName, entry["free_gib"])
		}
		usedPct, ok := entry["used_pct"].(float64)
		if !ok {
			t.Fatalf("Expected details[%q][\"used_pct\"] to be float64, got %T", poolName, entry["used_pct"])
		}

		// The core regression assertions: these failed before the unit-normalisation fix
		if totalGiB <= 0 {
			t.Errorf("pool %q total_gib should be positive, got %f", poolName, totalGiB)
		}
		if freeGiB < 0 {
			t.Errorf("pool %q free_gib should be non-negative, got %f (was negative before the MiB/GiB fix)", poolName, freeGiB)
		}
		if usedPct < 0 || usedPct > 100 {
			t.Errorf("pool %q used_pct should be 0-100, got %f (was >100%% before the MiB/GiB fix)", poolName, usedPct)
		}

		t.Logf("CheckIncusStoragePools[%s]: driver=%v total=%.2f GiB free=%.2f GiB used=%.0f%%",
			poolName, entry["driver"], totalGiB, freeGiB, usedPct)
	}
}

// CheckProcessMonitoringCapability should complete with a definitive status (OK/Warning/Failed)
// depending on whether the environment supports process monitoring (cgroups, image availability).
func TestCheckImmutableCapability(t *testing.T) {
	result := CheckImmutableCapability()

	if result.Name != "immutable_capability" {
		t.Errorf("Expected check name 'immutable_capability', got '%s'", result.Name)
	}

	// Must be OK (cap granted) or Warning (cap missing) — never Failed
	if result.Status != StatusOK && result.Status != StatusWarning {
		t.Errorf("Unexpected status: %s (message: %s)", result.Status, result.Message)
	}

	// When the capability is missing, the fix command must contain a resolved
	// binary path — never $(which coi) which breaks when coi is a symlink.
	if result.Status == StatusWarning {
		if strings.Contains(result.Message, "$(which") {
			t.Error("Fix command must not contain $(which ...) — setcap requires a resolved path, not a symlink")
		}
		mitigation, ok := result.Details["mitigation"].(string)
		if !ok {
			t.Error("Warning result should include a 'mitigation' detail")
		} else if strings.Contains(mitigation, "$(which") {
			t.Error("Mitigation must not contain $(which ...) — setcap requires a resolved path")
		}
	}

	t.Logf("Immutable capability check: status=%s message=%s", result.Status, result.Message)
}

func TestCheckProcessMonitoringCapability(t *testing.T) {
	// Skip if incus is not available
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping integration test")
	}

	// Skip if incus daemon is not running
	if !container.Available() {
		t.Skip("incus daemon not running, skipping integration test")
	}

	// Get default image
	cfg := config.GetDefaultConfig()

	result := CheckProcessMonitoringCapability(cfg.Container.Image)

	if result.Name != "process_monitoring" {
		t.Errorf("Expected check name 'process_monitoring', got '%s'", result.Name)
	}

	// Could be OK, Warning, or Failed depending on environment
	if result.Status != StatusOK && result.Status != StatusWarning && result.Status != StatusFailed {
		t.Errorf("Unexpected status: %s", result.Status)
	}

	t.Logf("Process monitoring capability check: %s (status: %s)",
		result.Message, result.Status)
}

func TestCheckIptablesSudo(t *testing.T) {
	result := CheckIptablesSudo()

	if result.Name != "iptables_sudo" {
		t.Errorf("Expected check name 'iptables_sudo', got %q", result.Name)
	}

	// Never fails — only OK or Warning
	if result.Status != StatusOK && result.Status != StatusWarning {
		t.Errorf("Expected StatusOK or StatusWarning, got %s: %s", result.Status, result.Message)
	}

	// On macOS the check always returns OK
	if runtime.GOOS == "darwin" {
		if result.Status != StatusOK {
			t.Errorf("macOS: expected StatusOK, got %s", result.Status)
		}
		return
	}

	// If iptables is not installed we expect OK with a clear message
	if _, err := exec.LookPath("iptables"); err != nil {
		if result.Status != StatusOK {
			t.Errorf("iptables not installed: expected StatusOK, got %s", result.Status)
		}
		return
	}

	// iptables is installed — status depends on whether sudo is configured
	sudoWorks := exec.Command("sudo", "-n", "iptables", "-L", "FORWARD", "-n").Run() == nil
	if sudoWorks {
		if result.Status != StatusOK {
			t.Errorf("sudo iptables works: expected StatusOK, got %s: %s", result.Status, result.Message)
		}
		if !strings.Contains(result.Message, "configured") {
			t.Errorf("OK message should mention 'configured', got: %q", result.Message)
		}
	} else {
		if result.Status != StatusWarning {
			t.Errorf("sudo iptables fails: expected StatusWarning, got %s: %s", result.Status, result.Message)
		}
		// Warning message must include the fix command
		if !strings.Contains(result.Message, "sudoers.d") {
			t.Errorf("Warning message should include sudoers.d fix path, got: %q", result.Message)
		}
		if !strings.Contains(result.Message, "iptables") {
			t.Errorf("Warning message should reference iptables, got: %q", result.Message)
		}
	}

	t.Logf("CheckIptablesSudo: status=%s message=%s", result.Status, result.Message)
}

func TestCheckIptablesSudo_InRunAllChecks(t *testing.T) {
	cfg := config.GetDefaultConfig()
	result := RunAllChecks(cfg, false)

	if _, ok := result.Checks["iptables_sudo"]; !ok {
		t.Error("RunAllChecks should include 'iptables_sudo' check")
	}
}

func TestCheckBridgeForwardRules_NoFalsePositiveWhenForwardNotDrop(t *testing.T) {
	// If FORWARD policy is not DROP, missing bridge rules are harmless —
	// the check must not warn in that case.
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping bridge check test")
	}
	if network.ForwardPolicyIsDrop() {
		t.Skip("FORWARD policy is DROP on this host; skipping false-positive test")
	}

	result := CheckBridgeForwardRules()

	if result.Name != "bridge_forward_rules" {
		t.Errorf("Expected check name 'bridge_forward_rules', got %q", result.Name)
	}

	if result.Status != StatusOK {
		t.Errorf("FORWARD policy is not DROP: expected StatusOK regardless of rule presence, got %s: %s",
			result.Status, result.Message)
	}

	t.Logf("CheckBridgeForwardRules (FORWARD not DROP): status=%s message=%s", result.Status, result.Message)
}
