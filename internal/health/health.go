// Package health implements `coi health`: system, Incus, network, storage
// and container probes, their aggregation into an overall status, and
// optional remediation of failed checks.
package health

import (
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// CheckStatus represents the status of a health check
type CheckStatus string

// Possible CheckStatus values.
const (
	StatusOK      CheckStatus = "ok"
	StatusWarning CheckStatus = "warning"
	StatusFailed  CheckStatus = "failed"
)

// OverallStatus represents the overall health status
type OverallStatus string

// Possible OverallStatus values.
const (
	OverallHealthy   OverallStatus = "healthy"
	OverallDegraded  OverallStatus = "degraded"
	OverallUnhealthy OverallStatus = "unhealthy"
)

// HealthCheck represents the result of a single health check
type HealthCheck struct {
	Name    string                 `json:"name"`
	Status  CheckStatus            `json:"status"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// HealthResult represents the overall health check result
type HealthResult struct {
	Status    OverallStatus          `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Checks    map[string]HealthCheck `json:"checks"`
	Summary   HealthSummary          `json:"summary"`
}

// HealthSummary provides a summary of health check results
type HealthSummary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
}

// RunAllChecks runs all health checks and returns the result
func RunAllChecks(cfg *config.Config, verbose bool) *HealthResult {
	checks := make(map[string]HealthCheck)

	// System checks
	checks["os"] = CheckOS()
	checks["kernel_version"] = CheckKernelVersionHealth()
	checks["kernel_build_age"] = CheckKernelBuildAge()
	checks["kernel_mitigations"] = CheckKernelMitigations()
	checks["distro_eol"] = CheckDistroEOL()
	checks["timezone"] = CheckTimezone()

	// Critical checks
	checks["incus"] = CheckIncus()
	checks["permissions"] = CheckPermissions()
	checks["image"] = CheckImage(cfg.Container.Image)
	checks["image_age"] = CheckImageAge(cfg.Container.Image)
	checks["privileged_profile"] = CheckPrivilegedProfile()
	checks["security_posture"] = CheckSecurityPosture()
	checks["immutable_capability"] = CheckImmutableCapability()

	// Networking checks
	checks["network_bridge"] = CheckNetworkBridge()
	checks["ip_forwarding"] = CheckIPForwarding()
	checks["nft"] = CheckNft(cfg.Network)
	checks["bridge_forward_rules"] = CheckBridgeForwardRules()
	checks["iptables_sudo"] = CheckIptablesSudo()
	checks["docker_forward_policy"] = CheckDockerForwardPolicy()
	checks["ufw_conflict"] = CheckUFWConflict()

	// Storage checks
	checks["coi_directory"] = CheckCOIDirectory()
	checks["sessions_directory"] = CheckSessionsDirectory(cfg)
	checks["disk_space"] = CheckDiskSpace()
	checks["incus_storage_pools"] = CheckIncusStoragePools(collectReferencedPools(cfg))

	// Configuration checks
	checks["config"] = CheckConfiguration(cfg)
	checks["network_mode"] = CheckNetworkMode(cfg.Network.Mode)
	checks["tool"] = CheckTool(cfg.Tool.Name)
	checks["git_branch_guard"] = CheckGitBranchGuard(cfg)

	// Status checks
	checks["active_containers"] = CheckActiveContainers()
	checks["saved_sessions"] = CheckSavedSessions(cfg)
	checks["orphaned_resources"] = CheckOrphanedResources()
	checks["firewalld_veth_bloat"] = CheckFirewalldVethBloat()

	// Container networking checks (critical for detecting real networking issues).
	// Probe containers honor the user's kernel-surface policy: under
	// [security] reduce_kernel_surface / [container] docker = false a probe
	// must not silently boot with the full docker/nesting surface — the exact
	// class of widening the policy exists to prevent.
	probePolicy := container.HardeningPolicy{
		Docker:                    cfg.Container.IsDockerEnabled(),
		ReduceKernelSurface:       cfg.Security.IsReduceKernelSurfaceEnabled(),
		ReduceKernelSurfaceStrict: cfg.Security.IsReduceKernelSurfaceStrictEnabled(),
	}
	checks["container_connectivity"] = CheckContainerConnectivity(cfg.Container.Image, probePolicy)
	checks["network_restriction"] = CheckNetworkRestriction(cfg.Container.Image, probePolicy)

	// Runtime isolation proof: verify secret_paths masking actually hides a
	// planted decoy secret from inside a container (not just that config parses).
	checks["secret_masking"] = CheckSecretMasking(cfg.Container.Image, probePolicy)

	// Runtime isolation proof: verify host home/credentials are not reachable
	// inside the container (Coi's "credentials never exposed" guarantee).
	checks["host_credential_isolation"] = CheckHostCredentialIsolation(cfg.Container.Image, probePolicy)

	// NFT monitoring checks (only if enabled in config)
	if config.BoolVal(cfg.Monitoring.NFT.Enabled) {
		checks["nftables"] = CheckNFTables()
		checks["systemd_journal"] = CheckSystemdJournal()
		checks["libsystemd"] = CheckLibsystemd()
	}

	// Process/Filesystem monitoring checks (always run)
	checks["monitoring_configuration"] = CheckMonitoringConfiguration(cfg)
	if config.BoolVal(cfg.Monitoring.Enabled) {
		checks["sensitive_file_monitoring"] = CheckSensitiveFileMonitoring()
	}
	checks["audit_log_directory"] = CheckAuditLogDirectory()
	checks["cgroup_availability"] = CheckCgroupAvailability()

	// Optional checks (only if verbose)
	if verbose {
		checks["dns_resolution"] = CheckDNS()
		checks["process_monitoring"] = CheckProcessMonitoringCapability(cfg.Container.Image)
	}

	// Calculate summary
	summary := calculateSummary(checks)

	// Determine overall status
	status := determineStatus(checks)

	return &HealthResult{
		Status:    status,
		Timestamp: time.Now(),
		Checks:    checks,
		Summary:   summary,
	}
}

// calculateSummary calculates the summary from checks
func calculateSummary(checks map[string]HealthCheck) HealthSummary {
	summary := HealthSummary{
		Total: len(checks),
	}

	for _, check := range checks {
		switch check.Status {
		case StatusOK:
			summary.Passed++
		case StatusWarning:
			summary.Warnings++
		case StatusFailed:
			summary.Failed++
		}
	}

	return summary
}

// determineStatus determines the overall status from checks
func determineStatus(checks map[string]HealthCheck) OverallStatus {
	hasFailed := false
	hasWarning := false

	for _, check := range checks {
		switch check.Status {
		case StatusFailed:
			hasFailed = true
		case StatusWarning:
			hasWarning = true
		}
	}

	if hasFailed {
		return OverallUnhealthy
	}
	if hasWarning {
		return OverallDegraded
	}
	return OverallHealthy
}

// collectReferencedPools returns the de-duped list of storage pools that the
// loaded configuration cares about, so the storage-pool health check can
// inspect every pool any profile (or the global config) might actually use.
//
// Rules:
//   - The global [container] storage_pool is always included. If it is empty,
//     CheckIncusStoragePools resolves it to the Incus default pool name, so
//     a default-configured system still produces one meaningful entry.
//   - Every loaded profile contributes its effective Container.StoragePool.
//     Profile-to-profile inheritance is already flattened by
//     ResolveProfileInheritance at load time, so a child profile that only
//     inherits a pool (without overriding it) still shows up here.
//   - A profile whose effective storage_pool is "" falls back to the global
//     pool at ApplyProfile time, so we do not add "" again for it — the
//     global entry already covers that case.
func collectReferencedPools(cfg *config.Config) []string {
	seen := map[string]bool{}
	var pools []string
	add := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		pools = append(pools, p)
	}

	add(cfg.Container.StoragePool)
	for _, profile := range cfg.Profiles {
		if profile.Container.StoragePool != "" {
			add(profile.Container.StoragePool)
		}
	}

	return pools
}

// ExitCode returns the appropriate exit code for the health result
func (r *HealthResult) ExitCode() int {
	switch r.Status {
	case OverallHealthy:
		return 0
	case OverallDegraded:
		return 1
	case OverallUnhealthy:
		return 2
	default:
		return 2
	}
}
