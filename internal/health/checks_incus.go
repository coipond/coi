package health

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mensfeld/code-on-incus/internal/config"
	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/tool"
)

// CheckIncus verifies that Incus is available and running
func CheckIncus() HealthCheck {
	// Check if incus binary exists
	if _, err := exec.LookPath("incus"); err != nil {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusFailed,
			Message: "Incus binary not found",
		}
	}

	// Check if Incus is available (daemon running and accessible)
	if !container.Available() {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusFailed,
			Message: "Incus daemon not running or not accessible",
		}
	}

	// Get Incus version
	versionOutput, err := container.IncusOutput("version")
	if err != nil {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusOK,
			Message: "Running (version unknown)",
		}
	}

	return evaluateIncusVersion(versionOutput)
}

// evaluateIncusVersion evaluates the raw `incus version` output and returns
// the appropriate health check result, including minimum version validation.
func evaluateIncusVersion(versionOutput string) HealthCheck {
	versionStr, err := container.ExtractServerVersion(versionOutput)
	if err != nil {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusOK,
			Message: "Running (version unknown)",
		}
	}

	v, err := container.ParseIncusVersion(versionStr)
	if err != nil {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusOK,
			Message: fmt.Sprintf("Running (version %s)", versionStr),
			Details: map[string]interface{}{
				"version": versionStr,
			},
		}
	}

	if !container.MeetsMinimumVersion(v) {
		return HealthCheck{
			Name:    "incus",
			Status:  StatusWarning,
			Message: container.FormatMinVersionError(v),
			Details: map[string]interface{}{
				"version": versionStr,
			},
		}
	}

	if !container.MeetsRecommendedVersion(v) {
		// Advisory only — NOT a warning. The version meets COI's hard minimum
		// (6.1) and works, so this must not flip the overall status to degraded
		// or the exit code to 1: scripts that gate on `coi health` exit 0 run on
		// supported hosts and would break. The recommendation rides along in the
		// message/details for anyone reading the report.
		return HealthCheck{
			Name:   "incus",
			Status: StatusOK,
			Message: fmt.Sprintf("Running (version %s) — works, but %d.%d+ is recommended; distribution lag means older Incus may miss container-isolation fixes (https://github.com/zabbly/incus)",
				versionStr, container.RecommendedIncusVersionMajor, container.RecommendedIncusVersionMinor),
			Details: map[string]interface{}{
				"version":     versionStr,
				"recommended": fmt.Sprintf("%d.%d", container.RecommendedIncusVersionMajor, container.RecommendedIncusVersionMinor),
			},
		}
	}

	return HealthCheck{
		Name:    "incus",
		Status:  StatusOK,
		Message: fmt.Sprintf("Running (version %s)", versionStr),
		Details: map[string]interface{}{
			"version": versionStr,
		},
	}
}

// CheckImage verifies that the default image exists
func CheckImage(imageName string) HealthCheck {
	if imageName == "" {
		imageName = "coi-default"
	}

	exists, err := container.ImageExists(imageName)
	if err != nil {
		return HealthCheck{
			Name:    "image",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not check image: %v", err),
		}
	}

	if !exists {
		return HealthCheck{
			Name:    "image",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Image '%s' not found (run 'coi build')", imageName),
			Details: map[string]interface{}{
				"expected": imageName,
			},
		}
	}

	// Get image fingerprint
	output, err := container.IncusOutput("image", "list", imageName, "--format=csv", "-c", "f")
	fingerprint := ""
	if err == nil && output != "" {
		lines := strings.Split(output, "\n")
		if len(lines) > 0 {
			fingerprint = strings.TrimSpace(lines[0])
			if len(fingerprint) > 12 {
				fingerprint = fingerprint[:12] + "..."
			}
		}
	}

	message := imageName
	if fingerprint != "" {
		message = fmt.Sprintf("%s (fingerprint: %s)", imageName, fingerprint)
	}

	return HealthCheck{
		Name:    "image",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"alias":       imageName,
			"fingerprint": fingerprint,
		},
	}
}

// CheckConfiguration verifies the configuration is loaded correctly
func CheckConfiguration(cfg *config.Config) HealthCheck {
	if cfg == nil {
		return HealthCheck{
			Name:    "config",
			Status:  StatusFailed,
			Message: "Configuration not loaded",
		}
	}

	// Find which config files exist
	configPaths := config.GetConfigPaths()
	var loadedFrom []string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			loadedFrom = append(loadedFrom, path)
		}
	}

	message := "Defaults only (no config files)"
	if len(loadedFrom) > 0 {
		message = loadedFrom[len(loadedFrom)-1] // Show highest priority
	}

	return HealthCheck{
		Name:    "config",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"loaded_from": loadedFrom,
		},
	}
}

// CheckGitBranchGuard reports whether the [git] protected_branches guard is
// active and which branches it covers. Purely config-driven — no remediation
// (there is no host state to fix; the guard is installed per-session).
func CheckGitBranchGuard(cfg *config.Config) HealthCheck {
	var branches []string
	if cfg != nil {
		branches = cfg.Git.EffectiveProtectedBranches()
	}
	if len(branches) == 0 {
		return HealthCheck{
			Name:    "git_branch_guard",
			Status:  StatusWarning,
			Message: "Disabled (protected_branches = []) — commits/pushes to any branch are allowed",
			Details: map[string]interface{}{"protected_branches": []string{}},
		}
	}
	return HealthCheck{
		Name:    "git_branch_guard",
		Status:  StatusOK,
		Message: "Protecting " + strings.Join(branches, ", ") + " (no direct commits/pushes)",
		Details: map[string]interface{}{"protected_branches": branches},
	}
}

// CheckNetworkMode reports the configured network mode
func CheckNetworkMode(mode config.NetworkMode) HealthCheck {
	if mode == "" {
		mode = config.NetworkModeRestricted
	}

	return HealthCheck{
		Name:    "network_mode",
		Status:  StatusOK,
		Message: string(mode),
		Details: map[string]interface{}{
			"mode": string(mode),
		},
	}
}

// CheckTool reports the configured tool
func CheckTool(toolName string) HealthCheck {
	if toolName == "" {
		toolName = "claude"
	}

	_, err := tool.Get(toolName)
	if err != nil {
		return HealthCheck{
			Name:    "tool",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Unknown tool: %s", toolName),
		}
	}

	return HealthCheck{
		Name:    "tool",
		Status:  StatusOK,
		Message: toolName,
		Details: map[string]interface{}{
			"name": toolName,
		},
	}
}

// CheckImageAge checks if the COI image is outdated
func CheckImageAge(imageName string) HealthCheck {
	if imageName == "" {
		imageName = "coi-default"
	}

	// Get image info
	output, err := container.IncusOutput("image", "list", imageName, "--format=json")
	if err != nil {
		return HealthCheck{
			Name:    "image_age",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not get image info: %v", err),
		}
	}

	var images []struct {
		CreatedAt time.Time `json:"created_at"`
		Aliases   []struct {
			Name string `json:"name"`
		} `json:"aliases"`
	}

	if err := json.Unmarshal([]byte(output), &images); err != nil {
		return HealthCheck{
			Name:    "image_age",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not parse image info: %v", err),
		}
	}

	// Find the image
	for _, img := range images {
		for _, alias := range img.Aliases {
			if alias.Name == imageName {
				age := time.Since(img.CreatedAt)
				days := int(age.Hours() / 24)

				// Warn if older than 30 days
				if days > 30 {
					return HealthCheck{
						Name:    "image_age",
						Status:  StatusWarning,
						Message: fmt.Sprintf("%d days old (consider rebuilding with 'coi build --force')", days),
						Details: map[string]interface{}{
							"created_at": img.CreatedAt.Format("2006-01-02"),
							"age_days":   days,
						},
					}
				}

				return HealthCheck{
					Name:    "image_age",
					Status:  StatusOK,
					Message: fmt.Sprintf("%d days old", days),
					Details: map[string]interface{}{
						"created_at": img.CreatedAt.Format("2006-01-02"),
						"age_days":   days,
					},
				}
			}
		}
	}

	return HealthCheck{
		Name:    "image_age",
		Status:  StatusWarning,
		Message: fmt.Sprintf("Image '%s' not found", imageName),
	}
}

// CheckPrivilegedProfile checks if the default Incus profile has security.privileged=true
func CheckPrivilegedProfile() HealthCheck {
	if !container.Available() {
		return HealthCheck{
			Name:    "privileged_profile",
			Status:  StatusOK,
			Message: "Skipped (Incus not available)",
		}
	}

	output, err := container.IncusOutput("profile", "get", "default", "security.privileged")
	if err != nil {
		return HealthCheck{
			Name:    "privileged_profile",
			Status:  StatusWarning,
			Message: "Could not check default profile — unable to verify container security",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	if strings.TrimSpace(output) == "true" {
		return HealthCheck{
			Name:   "privileged_profile",
			Status: StatusFailed,
			Message: "Default profile has security.privileged=true — this defeats all container isolation. " +
				"Remove with: incus profile unset default security.privileged",
			Details: map[string]interface{}{
				"security.privileged": "true",
			},
		}
	}

	return HealthCheck{
		Name:    "privileged_profile",
		Status:  StatusOK,
		Message: "Default profile uses unprivileged containers",
	}
}

// CheckSecurityPosture checks the overall container security posture by inspecting
// seccomp, AppArmor, and privilege settings on the default Incus profile.
func CheckSecurityPosture() HealthCheck {
	if !container.Available() {
		return HealthCheck{
			Name:    "security_posture",
			Status:  StatusOK,
			Message: "Skipped (Incus not available)",
		}
	}

	details := map[string]interface{}{}

	// Check security.privileged
	privOutput, err := container.IncusOutput("profile", "get", "default", "security.privileged")
	if err != nil {
		return HealthCheck{
			Name:    "security_posture",
			Status:  StatusWarning,
			Message: "Could not check default profile — unable to verify security posture",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	privileged := strings.TrimSpace(privOutput) == "true"
	details["privileged"] = privileged

	if privileged {
		details["seccomp"] = "disabled (privileged)"
		details["apparmor"] = "disabled (privileged)"
		details["raw_seccomp_override"] = false
		details["raw_apparmor_override"] = false

		return HealthCheck{
			Name:   "security_posture",
			Status: StatusFailed,
			Message: "Privileged containers — seccomp and AppArmor are disabled. " +
				"Remove with: incus profile unset default security.privileged",
			Details: details,
		}
	}

	// Check raw.seccomp override
	rawSeccomp, _ := container.IncusOutput("profile", "get", "default", "raw.seccomp")
	rawSeccompOverride := strings.TrimSpace(rawSeccomp) != ""
	details["raw_seccomp_override"] = rawSeccompOverride

	if rawSeccompOverride {
		details["seccomp"] = "custom override"
	} else {
		details["seccomp"] = "enabled (default)"
	}

	// Check raw.apparmor override
	rawApparmor, _ := container.IncusOutput("profile", "get", "default", "raw.apparmor")
	rawApparmorOverride := strings.TrimSpace(rawApparmor) != ""
	details["raw_apparmor_override"] = rawApparmorOverride

	// Check host AppArmor availability
	apparmorAvailable := false

	if runtime.GOOS == "linux" {
		if content, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
			apparmorAvailable = strings.TrimSpace(string(content)) == "Y"
		}
	}

	if rawApparmorOverride {
		details["apparmor"] = "custom override"
	} else if apparmorAvailable {
		details["apparmor"] = "enabled (default)"
	} else {
		details["apparmor"] = "not available"
	}

	// Determine status
	if rawSeccompOverride || rawApparmorOverride {
		msg := "Custom security profile overrides detected — verify your raw.seccomp/raw.apparmor settings"
		return HealthCheck{
			Name:    "security_posture",
			Status:  StatusWarning,
			Message: msg,
			Details: details,
		}
	}

	if !apparmorAvailable {
		return HealthCheck{
			Name:    "security_posture",
			Status:  StatusOK,
			Message: "Seccomp enabled, AppArmor not available (seccomp-only isolation)",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "security_posture",
		Status:  StatusOK,
		Message: "Full isolation — unprivileged containers with seccomp and AppArmor",
		Details: details,
	}
}
