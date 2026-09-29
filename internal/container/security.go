package container

import (
	"fmt"
	"strings"
)

// CheckNotPrivileged verifies that neither the container config nor the default profile
// has security.privileged=true. Running privileged containers defeats all container
// isolation and is incompatible with Coi's security model.
// Returns nil on any incus command failure (graceful degradation).
func CheckNotPrivileged(containerName string) error {
	// Check container-level config
	output, err := IncusOutput("config", "get", containerName, "security.privileged")
	if err == nil && containsPrivilegedValue(output) {
		return fmt.Errorf(
			"container %q has security.privileged=true which defeats all container isolation. "+
				"Coi requires unprivileged containers for security. "+
				"Remove it with: incus config unset %s security.privileged",
			containerName, containerName,
		)
	}

	// Check default profile
	output, err = IncusOutput("profile", "get", "default", "security.privileged")
	if err == nil && containsPrivilegedValue(output) {
		return fmt.Errorf(
			"the default Incus profile has security.privileged=true which defeats all container isolation. " +
				"Coi requires unprivileged containers for security. " +
				"Remove it with: incus profile unset default security.privileged",
		)
	}

	return nil
}

// containsPrivilegedValue checks if the output from `incus config get` or
// `incus profile get` indicates security.privileged is true.
func containsPrivilegedValue(output string) bool {
	return strings.TrimSpace(output) == "true"
}
