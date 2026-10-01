package container

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MinIncusVersionMajor is the minimum required Incus major version
	MinIncusVersionMajor = 6
	// MinIncusVersionMinor is the minimum required Incus minor version
	MinIncusVersionMinor = 1

	// RecommendedIncusVersionMajor and RecommendedIncusVersionMinor give the
	// version below which `coi health` warns (but nothing refuses to run): Incus releases carry
	// container-manager and isolation fixes that stable distributions
	// backport late or never, so running far behind the current release
	// means known-fixed issues stay live. Bump this occasionally alongside
	// dependency updates.
	RecommendedIncusVersionMajor = 6
	// RecommendedIncusVersionMinor is the recommended Incus minor version.
	RecommendedIncusVersionMinor = 7
)

// IncusVersion represents a parsed Incus version
type IncusVersion struct {
	Major int
	Minor int
	Raw   string
}

// ParseIncusVersion parses a version string like "6.20", "6.1", "6.0.3", "7.0"
func ParseIncusVersion(str string) (*IncusVersion, error) {
	str = strings.TrimSpace(str)
	if str == "" {
		return nil, fmt.Errorf("empty version string")
	}

	parts := strings.SplitN(str, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid version format: %q (expected major.minor)", str)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid major version in %q: %w", str, err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid minor version in %q: %w", str, err)
	}

	return &IncusVersion{
		Major: major,
		Minor: minor,
		Raw:   str,
	}, nil
}

// ExtractServerVersion extracts the server version string from `incus version` output.
// It looks for a "Server version:" line first, then falls back to the raw trimmed string.
func ExtractServerVersion(output string) (string, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return "", fmt.Errorf("empty version output")
	}

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Server version:") {
			version := strings.TrimSpace(strings.TrimPrefix(line, "Server version:"))
			if version == "" {
				return "", fmt.Errorf("empty server version in output")
			}
			return version, nil
		}
	}

	// Fallback: single-line output (older Incus versions)
	return strings.TrimSpace(strings.Split(output, "\n")[0]), nil
}

// MeetsMinimumVersion checks if the given version meets the minimum requirement (>= 6.1)
func MeetsMinimumVersion(v *IncusVersion) bool {
	if v.Major > MinIncusVersionMajor {
		return true
	}
	if v.Major == MinIncusVersionMajor {
		return v.Minor >= MinIncusVersionMinor
	}
	return false
}

// MeetsRecommendedVersion checks if the given version meets the recommended
// version (see RecommendedIncusVersionMajor/Minor).
func MeetsRecommendedVersion(v *IncusVersion) bool {
	if v.Major > RecommendedIncusVersionMajor {
		return true
	}
	if v.Major == RecommendedIncusVersionMajor {
		return v.Minor >= RecommendedIncusVersionMinor
	}
	return false
}

// CheckMinimumVersion checks the running Incus server version and returns an error
// if it is below the minimum required version. Returns nil if the version is OK or
// cannot be determined (graceful degradation).
func CheckMinimumVersion() error {
	output, err := IncusOutput("version")
	if err != nil {
		return nil // Can't get version, don't block
	}

	versionStr, err := ExtractServerVersion(output)
	if err != nil {
		return nil
	}

	v, err := ParseIncusVersion(versionStr)
	if err != nil {
		return nil
	}

	if !MeetsMinimumVersion(v) {
		return fmt.Errorf("%s", FormatMinVersionError(v))
	}

	return nil
}

// FormatMinVersionError returns an actionable error message for users with old Incus versions
func FormatMinVersionError(v *IncusVersion) string {
	return fmt.Sprintf(
		"Incus version %s is below the minimum required %d.%d. "+
			"Ubuntu ships Incus 6.0.x which lacks required idmapping support. "+
			"Please install Incus >= %d.%d from the Zabbly repository: "+
			"https://github.com/zabbly/incus",
		v.Raw, MinIncusVersionMajor, MinIncusVersionMinor,
		MinIncusVersionMajor, MinIncusVersionMinor,
	)
}
