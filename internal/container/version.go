package container

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	// MinIncusVersionMajor is the minimum required Incus major version
	MinIncusVersionMajor = 7
	// MinIncusVersionMinor is the minimum required Incus minor version
	MinIncusVersionMinor = 0

	// RecommendedIncusVersionMajor and RecommendedIncusVersionMinor give the
	// version below which `coi health` adds a recommendation note to the
	// incus check, which stays OK-status (exit code unchanged; nothing
	// refuses to run): Incus releases carry container-manager and isolation
	// fixes that stable distributions backport late or never, so running far
	// behind the current release means known-fixed issues stay live. Bump
	// this occasionally alongside dependency updates.
	RecommendedIncusVersionMajor = 7
	// RecommendedIncusVersionMinor is the recommended Incus minor version.
	RecommendedIncusVersionMinor = 5
)

// IncusVersion represents a parsed Incus version
type IncusVersion struct {
	Major int
	Minor int
	Raw   string
}

// ParseIncusVersion parses a version string like "6.20", "6.0.3", "7.0", "7.5"
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

// ExtractClientVersion extracts the client version string from the
// "Client version:" line of `incus version` output.
func ExtractClientVersion(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Client version:") {
			version := strings.TrimSpace(strings.TrimPrefix(line, "Client version:"))
			if version == "" {
				return "", fmt.Errorf("empty client version in output")
			}
			return version, nil
		}
	}
	return "", fmt.Errorf("no client version in output")
}

// MeetsMinimumVersion checks if the given version meets the minimum requirement
// (see MinIncusVersionMajor/Minor).
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

// CheckMinimumVersion checks the Incus server and client versions and returns
// an error if either is below the minimum required version. Returns nil if both
// are OK or cannot be determined (graceful degradation).
func CheckMinimumVersion() error {
	output, err := IncusOutput("version")
	if err != nil {
		return nil // Can't get version, don't block
	}
	return checkMinimumVersionOutput(output)
}

// checkMinimumVersionOutput checks the server and client versions in raw
// `incus version` output. A version that cannot be parsed is not checked.
func checkMinimumVersionOutput(output string) error {
	if versionStr, err := ExtractServerVersion(output); err == nil {
		if v, err := ParseIncusVersion(versionStr); err == nil && !MeetsMinimumVersion(v) {
			return fmt.Errorf("%s", FormatMinVersionError(v))
		}
	}

	if versionStr, err := ExtractClientVersion(output); err == nil {
		if v, err := ParseIncusVersion(versionStr); err == nil && !MeetsMinimumVersion(v) {
			return fmt.Errorf("%s", FormatMinClientVersionError(v))
		}
	}

	return nil
}

// FormatMinVersionError returns an actionable error message for users with an
// old Incus server.
func FormatMinVersionError(v *IncusVersion) string {
	return formatMinVersionError("server", v)
}

// FormatMinClientVersionError returns an actionable error message for users
// with an old incus client.
func FormatMinClientVersionError(v *IncusVersion) string {
	return formatMinVersionError("client", v)
}

// formatMinVersionError builds the below-minimum message for the given part
// ("server" or "client") of the Incus install.
func formatMinVersionError(part string, v *IncusVersion) string {
	return fmt.Sprintf(
		"Incus %s version %s is below the minimum required %d.%d. "+
			"Distribution packages are often older (Ubuntu 24.04 ships Incus 6.0.x). "+
			"Please install Incus >= %d.%d from the Zabbly repository: "+
			"https://github.com/zabbly/incus",
		part, v.Raw, MinIncusVersionMajor, MinIncusVersionMinor,
		MinIncusVersionMajor, MinIncusVersionMinor,
	)
}

// pushArchiveSupported reports, once per process, whether the incus client
// has `file push --archive`. It is a client flag, so the client's own help
// decides: 7.5 added it, and LTS releases such as 7.0.2 backported it along
// with 7.5's root-owned default, so a version number would miss them. A
// failed probe reports false, which keeps the push every client has.
//
// pushFollowSupported reports, from the same help, whether the client has
// `file push -H` (--follow), added in 7.0.
var pushArchiveSupported, pushFollowSupported = newPushFlagChecks()

func newPushFlagChecks() (archive, follow func() bool) {
	help := sync.OnceValue(func() string {
		out, err := IncusOutput("file", "push", "--help")
		if err != nil {
			return ""
		}
		return out
	})
	return func() bool { return strings.Contains(help(), "--archive") },
		func() bool { return strings.Contains(help(), "--follow") }
}

// pullNoDereferenceSupported reports, once per process, whether the incus
// client has `file pull -P` (6.23+). Without -P, a 6.23+ client follows a
// symlink source; older clients copy the link itself.
var pullNoDereferenceSupported = newPullNoDereferenceCheck()

func newPullNoDereferenceCheck() func() bool {
	return newClientVersionCheck(6, 23)
}

// newClientVersionCheck returns a check, probed on first use, of whether the
// incus client is at least major.minor. A failed probe reports false, which
// keeps the flags every client has.
func newClientVersionCheck(major, minor int) func() bool {
	return sync.OnceValue(func() bool {
		out, err := IncusOutput("--version")
		if err != nil {
			return false
		}
		v, err := ParseIncusVersion(out)
		if err != nil {
			return false
		}
		return v.Major > major || (v.Major == major && v.Minor >= minor)
	})
}
