package health

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/vmhost"
)

// CheckOS reports the operating system information
func CheckOS() HealthCheck {
	// Get OS and architecture
	osName := runtime.GOOS
	arch := runtime.GOARCH

	// Try to get more detailed OS info on Linux
	var details string
	var environment string

	if osName == "linux" {
		// Try to read /etc/os-release for distribution info
		if content, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(content), "\n")
			var prettyName string
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
					break
				}
			}
			if prettyName != "" {
				details = prettyName
			}
		}

		// Detect if running in Colima/Lima VM
		if vmhost.Detect() == vmhost.KindLimaLike {
			environment = "colima"
		}
	} else if osName == "darwin" {
		// Get macOS version
		cmd := exec.Command("sw_vers", "-productVersion")
		if output, err := cmd.Output(); err == nil {
			details = "macOS " + strings.TrimSpace(string(output))
		}
	}

	message := fmt.Sprintf("%s/%s", osName, arch)
	if details != "" {
		message = fmt.Sprintf("%s (%s)", details, arch)
	}
	if environment != "" {
		message += fmt.Sprintf(" [%s]", environment)
	}

	return HealthCheck{
		Name:    "os",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"os":          osName,
			"arch":        arch,
			"details":     details,
			"environment": environment,
		},
	}
}

// CheckPermissions verifies user has correct group membership
func CheckPermissions() HealthCheck {
	// On macOS, no group check needed
	if runtime.GOOS == "darwin" {
		return HealthCheck{
			Name:    "permissions",
			Status:  StatusOK,
			Message: "macOS - no group required",
		}
	}

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return HealthCheck{
			Name:    "permissions",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not determine current user: %v", err),
		}
	}

	// Use os.Getgroups() (getgroups(2)) to get the actual supplementary GIDs
	// of the current process — not the group database. This correctly reflects
	// whether the running session has picked up a recent usermod change.
	activeGIDs, err := os.Getgroups()
	if err != nil {
		return HealthCheck{
			Name:    "permissions",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not determine active session groups: %v", err),
		}
	}

	// Look for incus-admin group
	incusGroup, err := user.LookupGroup("incus-admin")
	if err != nil {
		return HealthCheck{
			Name:    "permissions",
			Status:  StatusFailed,
			Message: "incus-admin group not found",
		}
	}

	// Check if the group is active in the current session.
	incusGID, _ := strconv.Atoi(incusGroup.Gid)
	for _, gid := range activeGIDs {
		if gid == incusGID {
			return HealthCheck{
				Name:    "permissions",
				Status:  StatusOK,
				Message: "User in incus-admin group",
				Details: map[string]interface{}{
					"user":  currentUser.Username,
					"group": "incus-admin",
				},
			}
		}
	}

	// Not active in session — check if they were added but haven't re-logged in.
	if container.UserInGroupFile(currentUser.Username, "incus-admin") {
		return HealthCheck{
			Name:    "permissions",
			Status:  StatusWarning,
			Message: fmt.Sprintf("User '%s' is in incus-admin group but session not reloaded — log out and back in, or run: newgrp incus-admin", currentUser.Username),
		}
	}

	return HealthCheck{
		Name:    "permissions",
		Status:  StatusFailed,
		Message: fmt.Sprintf("User '%s' not in incus-admin group — run: sudo usermod -aG incus-admin $USER", currentUser.Username),
	}
}

// CheckKernelVersionHealth checks the running kernel version and warns if too old
func CheckKernelVersionHealth() HealthCheck {
	if runtime.GOOS != "linux" {
		return HealthCheck{
			Name:    "kernel_version",
			Status:  StatusOK,
			Message: fmt.Sprintf("Not applicable (%s)", runtime.GOOS),
		}
	}

	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return HealthCheck{
			Name:    "kernel_version",
			Status:  StatusOK,
			Message: "Could not determine kernel version",
		}
	}

	v, err := container.ParseKernelVersion(string(out))
	if err != nil {
		return HealthCheck{
			Name:    "kernel_version",
			Status:  StatusOK,
			Message: fmt.Sprintf("Could not parse kernel version: %s", strings.TrimSpace(string(out))),
		}
	}

	if !container.MeetsMinimumKernelVersion(v) {
		return HealthCheck{
			Name:   "kernel_version",
			Status: StatusWarning,
			Message: fmt.Sprintf("Kernel %s is below recommended minimum %d.%d — older kernels may lack security features for safe container isolation",
				v.Raw, container.MinKernelVersionMajor, container.MinKernelVersionMinor),
			Details: map[string]interface{}{
				"kernel":        v.Raw,
				"minimum":       fmt.Sprintf("%d.%d", container.MinKernelVersionMajor, container.MinKernelVersionMinor),
				"major":         v.Major,
				"minor":         v.Minor,
				"patch":         v.Patch,
				"meets_minimum": false,
			},
		}
	}

	return HealthCheck{
		Name:    "kernel_version",
		Status:  StatusOK,
		Message: fmt.Sprintf("Kernel %s (>= %d.%d)", v.Raw, container.MinKernelVersionMajor, container.MinKernelVersionMinor),
		Details: map[string]interface{}{
			"kernel":        v.Raw,
			"minimum":       fmt.Sprintf("%d.%d", container.MinKernelVersionMajor, container.MinKernelVersionMinor),
			"major":         v.Major,
			"minor":         v.Minor,
			"patch":         v.Patch,
			"meets_minimum": true,
		},
	}
}

// CheckImmutableCapability checks whether the Coi binary has CAP_LINUX_IMMUTABLE,
// which is needed to apply chattr +i on protected paths as defense-in-depth against
// the unshare+umount bypass of read-only bind mounts.
func CheckImmutableCapability() HealthCheck {
	if runtime.GOOS != "linux" {
		return HealthCheck{
			Name:    "immutable_capability",
			Status:  StatusOK,
			Message: "Skipped (not applicable on " + runtime.GOOS + ")",
		}
	}

	// Read effective capabilities from /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return HealthCheck{
			Name:    "immutable_capability",
			Status:  StatusWarning,
			Message: "Cannot read process capabilities",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	// Parse CapEff line
	var capEff uint64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexVal := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			_, err := fmt.Sscanf(hexVal, "%x", &capEff)
			if err != nil {
				return HealthCheck{
					Name:    "immutable_capability",
					Status:  StatusWarning,
					Message: "Cannot parse effective capabilities",
					Details: map[string]interface{}{
						"raw": hexVal,
					},
				}
			}
			break
		}
	}

	// CAP_LINUX_IMMUTABLE is bit 9
	const capLinuxImmutable = uint64(1) << 9

	if capEff&capLinuxImmutable != 0 {
		return HealthCheck{
			Name:    "immutable_capability",
			Status:  StatusOK,
			Message: "Host-side immutable protection available (CAP_LINUX_IMMUTABLE present)",
			Details: map[string]interface{}{
				"category": "SECURITY",
			},
		}
	}

	// Resolve the real binary path (setcap doesn't work on symlinks)
	fixCmd := "sudo setcap cap_linux_immutable=ep /path/to/coi"
	if exe, err := os.Executable(); err == nil {
		if resolved, linkErr := filepath.EvalSymlinks(exe); linkErr == nil {
			exe = resolved
		}
		fixCmd = fmt.Sprintf("sudo setcap cap_linux_immutable=ep %s", exe)
	}

	return HealthCheck{
		Name:   "immutable_capability",
		Status: StatusWarning,
		Message: "Host-side immutable protection unavailable — protected paths rely on bind-mount " +
			"read-only only (bypassable with root in container). Fix: " + fixCmd,
		Details: map[string]interface{}{
			"category":   "SECURITY",
			"mitigation": fixCmd,
		},
	}
}

// CheckTimezone reports whether the host timezone can be detected
func CheckTimezone() HealthCheck {
	tz, err := container.DetectHostTimezone()
	if err != nil || tz == "" {
		return HealthCheck{
			Name:    "timezone",
			Status:  StatusWarning,
			Message: "Could not detect host timezone — containers will use UTC",
			Details: map[string]interface{}{
				"detected": false,
			},
		}
	}

	return HealthCheck{
		Name:    "timezone",
		Status:  StatusOK,
		Message: fmt.Sprintf("Host timezone: %s", tz),
		Details: map[string]interface{}{
			"detected": true,
			"timezone": tz,
		},
	}
}
