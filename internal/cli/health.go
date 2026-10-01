package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/health"
	"github.com/spf13/cobra"
)

var (
	healthFormat  string
	healthVerbose bool
	healthFix     bool
	healthDryRun  bool
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check system health and dependencies",
	Long: `Check all system dependencies and report their status.

This helps diagnose setup issues and verify your environment is correctly configured.

Examples:
  coi health                  # Basic health check (text output)
  coi health --format json    # JSON output for scripting
  coi health --verbose        # Include additional checks
  coi health --fix            # Apply safe remediations for failing checks, then re-check
  coi health --fix --dry-run  # Show what --fix would do, without changing anything

Exit codes:
  0 = healthy (all checks pass)
  1 = degraded (warnings but functional)
  2 = unhealthy (critical failures)
`,
	RunE: healthCommand,
}

func init() {
	healthCmd.Flags().StringVar(&healthFormat, "format", "text", "Output format: text or json")
	healthCmd.Flags().Bool("json", false, "Alias for --format json")
	healthCmd.Flags().BoolVarP(&healthVerbose, "verbose", "v", false, "Include additional verbose checks")
	healthCmd.Flags().BoolVar(&healthFix, "fix", false, "Apply safe remediations for failing checks, then re-check")
	healthCmd.Flags().BoolVar(&healthDryRun, "dry-run", false, "With --fix, show the remediation plan without changing anything")
}

func healthCommand(cmd *cobra.Command, args []string) error {
	// Validate format
	applyJSONFormatAlias(cmd, &healthFormat)
	if err := validateTextOrJSON(healthFormat); err != nil {
		return err
	}

	if healthDryRun && !healthFix {
		return fmt.Errorf("--dry-run only applies together with --fix")
	}
	if healthFix && healthFormat == "json" {
		return fmt.Errorf("--fix is not supported with --format json; run it in text mode")
	}

	// Use package-level cfg from PersistentPreRunE, fall back to defaults
	healthCfg := app.cfg
	if healthCfg == nil {
		healthCfg = config.GetDefaultConfig()
	}

	// Run all health checks
	result := health.RunAllChecks(healthCfg, healthVerbose)

	// Apply remediations before reporting so the printed table and exit code
	// reflect the post-fix state. RunFixes updates result in place.
	if healthFix {
		outcomes := health.RunFixes(result, health.FixOptions{DryRun: healthDryRun})
		printFixReport(outcomes, healthDryRun)
	}

	// Output based on format
	if healthFormat == "json" {
		return outputHealthJSON(result)
	}

	return outputHealthText(result)
}

// printFixReport prints the outcome of `coi health --fix` above the health
// table. Each line states what was (or would be) done and, where relevant, the
// exact command and any follow-up the user must perform themselves.
func printFixReport(outcomes []health.FixOutcome, dryRun bool) {
	if dryRun {
		fmt.Println("Remediation plan (--dry-run — nothing was changed):")
	} else {
		fmt.Println("Applying remediations:")
	}

	if len(outcomes) == 0 {
		fmt.Println("  Nothing to do — no failing check has an applicable automatic remediation.")
		fmt.Println()
		return
	}

	for _, o := range outcomes {
		var icon, verb string
		switch o.Status {
		case health.FixPlanned:
			icon, verb = "[PLAN]", "would run"
		case health.FixApplied:
			icon, verb = "[DONE]", "fixed"
		case health.FixReloginRequired:
			icon, verb = "[DONE]", "applied (action still needed)"
		case health.FixManualRequired:
			icon, verb = "[MANUAL]", "run this yourself"
		case health.FixFailed:
			icon, verb = "[FAIL]", "failed"
		}

		fmt.Printf("  %-8s %s: %s\n", icon, formatCheckName(o.Check), o.Summary)
		if len(o.Command) > 0 && (o.Status == health.FixPlanned || o.Status == health.FixManualRequired) {
			fmt.Printf("           %s: %s\n", verb, shellQuoteArgs(o.Command))
		}
		if o.Err != nil {
			fmt.Printf("           error: %v\n", o.Err)
		}
		if o.Note != "" {
			fmt.Printf("           note: %s\n", o.Note)
		}
	}
	fmt.Println()
}

// outputHealthJSON outputs health check results as JSON
func outputHealthJSON(result *health.HealthResult) error {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))

	if result.ExitCode() != 0 {
		return &ExitCodeError{Code: result.ExitCode()}
	}
	return nil
}

// outputHealthText outputs health check results as human-readable text
func outputHealthText(result *health.HealthResult) error {
	fmt.Println("Coi Health Check")
	fmt.Println("==========================")
	fmt.Println()

	// Group checks by category
	categories := map[string][]string{
		"SYSTEM":        {"os", "kernel_version", "kernel_build_age", "kernel_mitigations", "distro_eol", "timezone"},
		"CRITICAL":      {"incus", "permissions", "image", "image_age", "privileged_profile", "security_posture", "immutable_capability", "secret_masking", "host_credential_isolation"},
		"NETWORKING":    {"network_bridge", "ip_forwarding", "nft", "bridge_forward_rules", "iptables_sudo", "docker_forward_policy", "ufw_conflict", "container_connectivity", "network_restriction", "firewalld_veth_bloat"},
		"MONITORING":    {"nftables", "systemd_journal", "libsystemd", "monitoring_configuration", "audit_log_directory", "cgroup_availability"},
		"STORAGE":       {"coi_directory", "sessions_directory", "disk_space", "incus_storage_pools"},
		"CONFIGURATION": {"config", "network_mode", "tool", "git_branch_guard"},
		"STATUS":        {"active_containers", "saved_sessions", "orphaned_resources"},
		"OPTIONAL":      {"dns_resolution", "process_monitoring"},
	}

	// Category order
	categoryOrder := []string{"SYSTEM", "CRITICAL", "NETWORKING", "MONITORING", "STORAGE", "CONFIGURATION", "STATUS", "OPTIONAL"}

	for _, category := range categoryOrder {
		checkNames := categories[category]
		hasChecks := false

		// Check if any checks in this category exist
		for _, name := range checkNames {
			if _, ok := result.Checks[name]; ok {
				hasChecks = true
				break
			}
		}

		if !hasChecks {
			continue
		}

		fmt.Printf("%s:\n", category)

		for _, name := range checkNames {
			check, ok := result.Checks[name]
			if !ok {
				continue
			}

			// Format status indicator
			var statusIcon string
			switch check.Status {
			case health.StatusOK:
				statusIcon = "[OK]"
			case health.StatusWarning:
				statusIcon = "[WARN]"
			case health.StatusFailed:
				statusIcon = "[FAIL]"
			}

			// Format the check name for display
			displayName := formatCheckName(name)

			fmt.Printf("  %-6s %-18s: %s\n", statusIcon, displayName, check.Message)
		}
		fmt.Println()
	}

	// Print any checks that weren't in a category
	printedNames := make(map[string]bool)
	for _, names := range categories {
		for _, name := range names {
			printedNames[name] = true
		}
	}

	var uncategorized []string
	for name := range result.Checks {
		if !printedNames[name] {
			uncategorized = append(uncategorized, name)
		}
	}

	if len(uncategorized) > 0 {
		sort.Strings(uncategorized)
		fmt.Println("OTHER:")
		for _, name := range uncategorized {
			check := result.Checks[name]
			var statusIcon string
			switch check.Status {
			case health.StatusOK:
				statusIcon = "[OK]"
			case health.StatusWarning:
				statusIcon = "[WARN]"
			case health.StatusFailed:
				statusIcon = "[FAIL]"
			}
			displayName := formatCheckName(name)
			fmt.Printf("  %-6s %-18s: %s\n", statusIcon, displayName, check.Message)
		}
		fmt.Println()
	}

	// Print summary
	fmt.Printf("STATUS: %s\n", strings.ToUpper(string(result.Status)))

	if result.Summary.Failed > 0 {
		fmt.Printf("%d of %d checks failed", result.Summary.Failed, result.Summary.Total)
		if result.Summary.Warnings > 0 {
			fmt.Printf(", %d warnings", result.Summary.Warnings)
		}
		fmt.Println()
	} else if result.Summary.Warnings > 0 {
		fmt.Printf("%d checks passed with %d warnings\n", result.Summary.Passed, result.Summary.Warnings)
	} else {
		fmt.Printf("All %d checks passed\n", result.Summary.Total)
	}

	if result.ExitCode() != 0 {
		return &ExitCodeError{Code: result.ExitCode()}
	}
	return nil
}

// formatCheckName converts snake_case check names to Title Case for display
func formatCheckName(name string) string {
	// Special cases for better display
	specialCases := map[string]string{ //nolint:gosec // G101 false positive: map of UI display labels (e.g. "host_credential_isolation"), not credentials
		"os":                        "Operating system",
		"kernel_version":            "Kernel version",
		"kernel_build_age":          "Kernel build age",
		"kernel_mitigations":        "Kernel mitigations",
		"distro_eol":                "Distro support",
		"timezone":                  "Timezone",
		"incus":                     "Incus",
		"permissions":               "Permissions",
		"image":                     "Default image",
		"image_age":                 "Image age",
		"privileged_profile":        "Privileged check",
		"network_bridge":            "Network bridge",
		"ip_forwarding":             "IP forwarding",
		"nft":                       "nft firewall",
		"bridge_forward_rules":      "Bridge forward",
		"iptables_sudo":             "iptables sudo",
		"docker_forward_policy":     "Docker FORWARD",
		"nftables":                  "nftables",
		"systemd_journal":           "systemd journal",
		"libsystemd":                "libsystemd-dev",
		"coi_directory":             "Coi directory",
		"sessions_directory":        "Sessions dir",
		"disk_space":                "Disk space",
		"incus_storage_pools":       "Incus storage pools",
		"config":                    "Config loaded",
		"network_mode":              "Network mode",
		"tool":                      "Tool",
		"git_branch_guard":          "Git branch guard",
		"active_containers":         "Containers",
		"saved_sessions":            "Saved sessions",
		"dns_resolution":            "DNS resolution",
		"orphaned_resources":        "Orphaned resources",
		"security_posture":          "Security posture",
		"immutable_capability":      "Immutable cap",
		"ufw_conflict":              "UFW conflict",
		"container_connectivity":    "Container connect",
		"network_restriction":       "Network restriction",
		"secret_masking":            "Secret masking",
		"host_credential_isolation": "Host cred isolation",
		"monitoring_configuration":  "Monitoring config",
		"audit_log_directory":       "Audit log dir",
		"cgroup_availability":       "cgroup v2",
		"process_monitoring":        "Process monitoring",
	}

	if displayName, ok := specialCases[name]; ok {
		return displayName
	}

	// Default: convert snake_case to Title Case
	words := strings.Split(name, "_")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

// shellQuoteArgs renders argv as one copy-pasteable shell command: arguments
// made only of safe characters are left bare, anything else is single-quoted
// (a fix can carry a multi-line sh -c script, which a plain space-join mangles).
func shellQuoteArgs(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		// A leading '=' stays quoted: zsh expands =cmd to the path of cmd.
		if a != "" && a[0] != '=' && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
			quoted[i] = a
			continue
		}
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}
