package health

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/nftmonitor"
)

// CheckNFTables checks if nftables is available and properly configured
func CheckNFTables() HealthCheck {
	// Check if nftables binary exists
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return HealthCheck{
			Name:    "nftables",
			Status:  StatusWarning,
			Message: "nftables not found (required for NFT monitoring)",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check nft version
	versionCmd := exec.Command("nft", "--version")
	versionOutput, vErr := versionCmd.CombinedOutput()

	var nftVersion string
	if vErr == nil {
		if result := evaluateNFTVersion(nftPath, string(versionOutput)); result != nil {
			return *result
		}
		// Version OK — extract for display
		if vs, err := nftmonitor.ExtractNFTVersion(string(versionOutput)); err == nil {
			nftVersion = vs
		}
	}

	// Check if we can run nft commands with sudo (NOPASSWD)
	cmd := exec.Command("sudo", "-n", "nft", "list", "ruleset")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return HealthCheck{
			Name:    "nftables",
			Status:  StatusWarning,
			Message: "nftables installed but sudo access not configured",
			Details: map[string]interface{}{
				"nft_path": nftPath,
				"version":  nftVersion,
				"error":    string(output),
				"hint":     "Run scripts/install-nft-deps.sh to configure passwordless sudo",
			},
		}
	}

	message := "nftables available with sudo access"
	if nftVersion != "" {
		message = fmt.Sprintf("nftables %s available with sudo access", nftVersion)
	}

	return HealthCheck{
		Name:    "nftables",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"nft_path": nftPath,
			"version":  nftVersion,
		},
	}
}

// evaluateNFTVersion evaluates the raw `nft --version` output and returns
// a failed health check if the version is below minimum. Returns nil if OK.
func evaluateNFTVersion(nftPath, versionOutput string) *HealthCheck {
	vs, err := nftmonitor.ExtractNFTVersion(versionOutput)
	if err != nil {
		return nil // Can't parse, skip version check
	}

	v, err := nftmonitor.ParseNFTVersion(vs)
	if err != nil {
		return nil // Can't parse, skip version check
	}

	if !nftmonitor.MeetsMinimumNFTVersion(v) {
		return &HealthCheck{
			Name:    "nftables",
			Status:  StatusWarning,
			Message: nftmonitor.FormatMinNFTVersionError(v),
			Details: map[string]interface{}{
				"nft_path": nftPath,
				"version":  vs,
			},
		}
	}

	return nil
}

// CheckSystemdJournal checks if systemd-journal access is available
func CheckSystemdJournal() HealthCheck {
	// Check if journalctl exists
	journalPath, err := exec.LookPath("journalctl")
	if err != nil {
		return HealthCheck{
			Name:    "systemd_journal",
			Status:  StatusWarning,
			Message: "journalctl not found (required for NFT monitoring)",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Check if user is in systemd-journal group
	currentUser, err := user.Current()
	if err != nil {
		return HealthCheck{
			Name:    "systemd_journal",
			Status:  StatusWarning,
			Message: "Failed to get current user",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Try to read kernel logs
	cmd := exec.Command("journalctl", "-k", "-n", "1")
	if err := cmd.Run(); err != nil {
		return HealthCheck{
			Name:    "systemd_journal",
			Status:  StatusWarning,
			Message: "No access to kernel logs (add user to systemd-journal group)",
			Details: map[string]interface{}{
				"journal_path": journalPath,
				"user":         currentUser.Username,
				"hint":         "Run scripts/install-nft-deps.sh to configure access",
			},
		}
	}

	return HealthCheck{
		Name:    "systemd_journal",
		Status:  StatusOK,
		Message: "systemd journal access available",
		Details: map[string]interface{}{
			"journal_path": journalPath,
			"user":         currentUser.Username,
		},
	}
}

// CheckLibsystemd checks if libsystemd development headers are installed
func CheckLibsystemd() HealthCheck {
	// Check if the header file exists
	headerPaths := []string{
		"/usr/include/systemd/sd-journal.h",
		"/usr/include/x86_64-linux-gnu/systemd/sd-journal.h",
		"/usr/include/aarch64-linux-gnu/systemd/sd-journal.h",
	}

	var foundPath string
	for _, path := range headerPaths {
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			break
		}
	}

	if foundPath == "" {
		return HealthCheck{
			Name:    "libsystemd",
			Status:  StatusWarning,
			Message: "libsystemd-dev not installed (required to build NFT monitoring)",
			Details: map[string]interface{}{
				"hint": "Run scripts/install-nft-deps.sh to install dependencies",
			},
		}
	}

	return HealthCheck{
		Name:    "libsystemd",
		Status:  StatusOK,
		Message: "libsystemd-dev installed",
		Details: map[string]interface{}{
			"header_path": foundPath,
		},
	}
}

// CheckAuditLogDirectory checks if the audit log directory exists and is writable
func CheckAuditLogDirectory() HealthCheck {
	auditDir := filepath.Join(os.Getenv("HOME"), ".coi", "audit")

	// Check if directory exists
	info, err := os.Stat(auditDir) //nolint:gosec // G703: path is derived from HOME env var + fixed ".coi/audit" suffix, not user-supplied
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create it
			if err := os.MkdirAll(auditDir, 0o755); err != nil { //nolint:gosec // G703: same path as above
				return HealthCheck{
					Name:    "audit_log_directory",
					Status:  StatusFailed,
					Message: "Failed to create audit log directory",
					Details: map[string]interface{}{
						"path":  auditDir,
						"error": err.Error(),
					},
				}
			}
			return HealthCheck{
				Name:    "audit_log_directory",
				Status:  StatusOK,
				Message: "Audit log directory created",
				Details: map[string]interface{}{
					"path": auditDir,
				},
			}
		}
		return HealthCheck{
			Name:    "audit_log_directory",
			Status:  StatusFailed,
			Message: "Failed to access audit log directory",
			Details: map[string]interface{}{
				"path":  auditDir,
				"error": err.Error(),
			},
		}
	}

	// Verify it's a directory
	if !info.IsDir() {
		return HealthCheck{
			Name:    "audit_log_directory",
			Status:  StatusFailed,
			Message: "Audit log path exists but is not a directory",
			Details: map[string]interface{}{
				"path": auditDir,
			},
		}
	}

	// Check if writable by creating a test file
	testFile := filepath.Join(auditDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil { //nolint:gosec // G703: testFile is derived from HOME env var + fixed path suffix, not user-supplied
		return HealthCheck{
			Name:    "audit_log_directory",
			Status:  StatusFailed,
			Message: "Audit log directory is not writable",
			Details: map[string]interface{}{
				"path":  auditDir,
				"error": err.Error(),
			},
		}
	}
	os.Remove(testFile) //nolint:gosec // G703: testFile is derived from HOME env var + fixed path suffix, not user-supplied

	return HealthCheck{
		Name:    "audit_log_directory",
		Status:  StatusOK,
		Message: "Audit log directory is ready",
		Details: map[string]interface{}{
			"path": auditDir,
		},
	}
}

// CheckCgroupAvailability checks if cgroup v2 is available for resource monitoring
func CheckCgroupAvailability() HealthCheck {
	cgroupPath := "/sys/fs/cgroup"

	// Check if cgroup filesystem exists
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return HealthCheck{
			Name:    "cgroup_availability",
			Status:  StatusFailed,
			Message: "Cgroup filesystem not found",
			Details: map[string]interface{}{
				"path":  cgroupPath,
				"error": err.Error(),
				"hint":  "Resource monitoring requires cgroup v2",
			},
		}
	}

	if !info.IsDir() {
		return HealthCheck{
			Name:    "cgroup_availability",
			Status:  StatusFailed,
			Message: "Cgroup path is not a directory",
			Details: map[string]interface{}{
				"path": cgroupPath,
			},
		}
	}

	// Check if it's cgroup v2 by looking for cgroup.controllers
	controllersPath := filepath.Join(cgroupPath, "cgroup.controllers")
	if _, err := os.Stat(controllersPath); err != nil {
		return HealthCheck{
			Name:    "cgroup_availability",
			Status:  StatusWarning,
			Message: "Cgroup v1 detected (v2 recommended for monitoring)",
			Details: map[string]interface{}{
				"path": cgroupPath,
				"hint": "Resource monitoring works best with cgroup v2",
			},
		}
	}

	// Read available controllers
	controllers, err := os.ReadFile(controllersPath)
	if err != nil {
		return HealthCheck{
			Name:    "cgroup_availability",
			Status:  StatusOK,
			Message: "Cgroup v2 is available",
			Details: map[string]interface{}{
				"path": cgroupPath,
			},
		}
	}

	return HealthCheck{
		Name:    "cgroup_availability",
		Status:  StatusOK,
		Message: "Cgroup v2 is available with controllers",
		Details: map[string]interface{}{
			"path":        cgroupPath,
			"controllers": strings.TrimSpace(string(controllers)),
		},
	}
}

// CheckMonitoringConfiguration checks if monitoring is properly configured
func CheckMonitoringConfiguration(cfg *config.Config) HealthCheck {
	details := map[string]interface{}{
		"enabled":                config.BoolVal(cfg.Monitoring.Enabled),
		"auto_pause_on_high":     config.BoolVal(cfg.Monitoring.AutoPauseOnHigh),
		"auto_kill_on_critical":  config.BoolVal(cfg.Monitoring.AutoKillOnCritical),
		"poll_interval_sec":      cfg.Monitoring.PollIntervalSec,
		"file_read_threshold_mb": cfg.Monitoring.FileReadThresholdMB,
	}
	if p := config.StringVal(cfg.Monitoring.ReverseShellOneLiners); p != "" {
		details["reverse_shell_one_liners"] = p
	}

	if !config.BoolVal(cfg.Monitoring.Enabled) {
		return HealthCheck{
			Name:    "monitoring_configuration",
			Status:  StatusWarning,
			Message: "Security monitoring is disabled (set monitoring.enabled=true in [monitoring] section of config.toml)",
			Details: details,
		}
	}

	// Check for unreasonable values
	warnings := []string{}

	if cfg.Monitoring.PollIntervalSec < 1 {
		warnings = append(warnings, "poll_interval_sec too low (<1s)")
	}
	if cfg.Monitoring.PollIntervalSec > 60 {
		warnings = append(warnings, "poll_interval_sec very high (>60s)")
	}
	if cfg.Monitoring.FileReadThresholdMB < 1 {
		warnings = append(warnings, "file_read_threshold_mb too low (<1MB)")
	}
	if cfg.Monitoring.FileReadThresholdMB > 10000 {
		warnings = append(warnings, "file_read_threshold_mb very high (>10GB)")
	}

	if len(warnings) > 0 {
		details["warnings"] = warnings
		return HealthCheck{
			Name:    "monitoring_configuration",
			Status:  StatusWarning,
			Message: "Monitoring configuration has unusual values",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "monitoring_configuration",
		Status:  StatusOK,
		Message: "Monitoring is properly configured",
		Details: details,
	}
}
