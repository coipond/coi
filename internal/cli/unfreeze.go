package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/mensfeld/coi/internal/alias"
	"github.com/mensfeld/coi/internal/container"
	"github.com/spf13/cobra"
)

var unfreezeCmd = &cobra.Command{
	Use:   "unfreeze [container-name]",
	Short: "Unfreeze a frozen (paused) container",
	Long: `Unfreeze a container that was paused/frozen by the security monitoring system.

When the security monitor detects a threat, it may pause (freeze) the container.
Use this command to unfreeze the container after investigating the threat.

Examples:
  coi unfreeze coi-abc123-1    # Unfreeze a specific frozen container
  coi unfreeze                  # Unfreeze all frozen Coi containers`,
	Args: cobra.MaximumNArgs(1),
	RunE: runUnfreeze,
}

func runUnfreeze(cmd *cobra.Command, args []string) error {
	if len(args) == 1 {
		// Unfreeze specific container (with alias resolution)
		containerName := args[0]
		if resolved, err := alias.ResolveAliasForRunning(containerName); err == nil {
			containerName = resolved
		} else if !alias.IsContainerName(containerName) {
			return err
		}
		return unfreezeContainer(containerName)
	}

	// Unfreeze all frozen Coi containers
	return unfreezeAllFrozen()
}

func unfreezeContainer(name string) error {
	// Check if container exists and is frozen
	status, err := getContainerStatus(name)
	if err != nil {
		return fmt.Errorf("container %s not found: %w", name, err)
	}

	if !container.StatusIsFrozen(status) {
		return fmt.Errorf("container %s is not frozen (status: %s)", name, status)
	}

	// Unfreeze the container
	_, err = container.IncusOutput("start", name)
	if err != nil {
		return fmt.Errorf("failed to unfreeze container: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Unfroze container: %s\n", name)
	return nil
}

func unfreezeAllFrozen() error {
	// List all Coi containers
	output, err := container.IncusOutput("list", "--format", "csv", "-c", "ns")
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	unfrozeCount := 0

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		name := parts[0]
		status := parts[1]

		// Only unfreeze frozen Coi containers
		if !strings.HasPrefix(name, "coi-") {
			continue
		}

		if container.StatusIsFrozen(status) {
			if err := unfreezeContainer(name); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to unfreeze %s: %v\n", name, err)
			} else {
				unfrozeCount++
			}
		}
	}

	if unfrozeCount == 0 {
		fmt.Fprintln(os.Stderr, "No frozen Coi containers found")
	} else {
		fmt.Fprintf(os.Stderr, "Unfroze %d container(s)\n", unfrozeCount)
	}

	return nil
}

func getContainerStatus(name string) (string, error) {
	output, err := container.IncusOutput("list", name, "--format", "csv", "-c", "s")
	if err != nil {
		return "", err
	}

	status := strings.TrimSpace(output)
	if status == "" {
		return "", fmt.Errorf("container not found")
	}
	// Normalize status
	if container.StatusIsFrozen(status) {
		return "Frozen", nil
	}
	return status, nil
}
