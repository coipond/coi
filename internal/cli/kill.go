package cli

import (
	"fmt"
	"os"

	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/network"
	"github.com/spf13/cobra"
)

var (
	killForce bool
	killAll   bool
)

var killCmd = &cobra.Command{
	Use:   "kill [container-name...]",
	Short: "Force stop and delete containers immediately",
	Long: `Force stop and delete one or more containers by name.

This immediately force-kills containers without waiting for graceful shutdown.
For graceful shutdown, use 'coi shutdown' instead.

Use 'coi list' to see active containers.

Examples:
  coi kill claude-abc12345-1           # Force kill specific container
  coi kill claude-abc12345-1 claude-xyz78901-2  # Force kill multiple containers
  coi kill --all                       # Force kill all containers (with confirmation)
  coi kill --all --force               # Force kill all without confirmation
`,
	RunE: killCommand,
}

func init() {
	killCmd.Flags().BoolVarP(&killForce, "force", "f", false, "Skip confirmation prompts")
	killCmd.Flags().BoolVarP(&killAll, "all", "a", false, "Kill all containers")
}

// resolveContainerArgs resolves container names from args (with alias support) or --all flag.
// Returns the resolved container names, or nil if the user cancelled or there are no containers.
// The action parameter is used in prompts (e.g., "Kill", "Shutdown").
func resolveContainerArgs(args []string, all bool, force bool, action string) ([]string, error) {
	var containerNames []string

	if all {
		containers, err := listActiveContainers()
		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %w", err)
		}

		if len(containers) == 0 {
			fmt.Printf("No containers to %s\n", action)
			return nil, nil
		}

		for _, c := range containers {
			containerNames = append(containerNames, c.Name)
		}

		fmt.Printf("Found %d container(s):\n", len(containerNames))
		for _, name := range containerNames {
			fmt.Printf("  - %s\n", name)
		}

		if !force {
			if !confirmYN(fmt.Sprintf("\n%s all these containers? [y/N]: ", action)) {
				fmt.Println("Cancelled.")
				return nil, nil
			}
		}
	} else {
		if len(args) == 0 {
			return nil, fmt.Errorf("no container names provided - use 'coi list' to see active containers")
		}
		containerNames = make([]string, 0, len(args))
		for _, arg := range args {
			name, err := resolveNameOrAlias(arg)
			if err != nil {
				return nil, err
			}
			containerNames = append(containerNames, name)
		}

		if !force && len(containerNames) > 1 {
			if !confirmYN(fmt.Sprintf("%s %d container(s)? [y/N]: ", action, len(containerNames))) {
				fmt.Println("Cancelled.")
				return nil, nil
			}
		}
	}

	return containerNames, nil
}

func killCommand(cmd *cobra.Command, args []string) error {
	containerNames, err := resolveContainerArgs(args, killAll, killForce, "Kill")
	if err != nil {
		return err
	}
	if containerNames == nil {
		return nil
	}

	// Kill each container
	killed := 0
	for _, name := range containerNames {
		fmt.Printf("Killing container %s...\n", name)
		mgr := container.NewManager(name)

		// Check if container exists first
		exists, err := mgr.Exists()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to check if %s exists: %v\n", name, err)
			continue
		}
		if !exists {
			fmt.Fprintf(os.Stderr, "  Warning: Container %s does not exist\n", name)
			continue
		}

		// Get container IP BEFORE stopping/deleting (needed for firewall cleanup)
		var containerIP string
		if network.NftAvailable() {
			containerIP, _ = network.GetContainerIPFast(name)
		}

		// Stop container (only if running - skip if already stopped)
		running, err := mgr.Running()
		if err == nil && running {
			if err := mgr.Stop(true); err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: Failed to stop %s: %v\n", name, err)
			}
		}

		// Clean up nft rules BEFORE deleting container
		// This ensures we remove any rules that were created for this container
		cleanupContainerFirewall(name, containerIP)

		// Delete container.
		//
		// An instance that is already gone counts as killed. Stopping a container
		// ends the coi session that owns it, and that session deletes its own
		// ephemeral container — so the delete below routinely races that cleanup and
		// finds the instance already removed. Reporting that as a failure meant
		// `coi kill` printed "No containers were killed" and exited non-zero about a
		// container it had, in fact, just killed.
		err = mgr.Delete(true)
		switch {
		case err == nil, container.IsNotFoundErr(err):
			killed++
			fmt.Printf("  ✓ Killed %s\n", name)
		default:
			// A delete can also lose a race to a concurrent delete of the SAME
			// instance (the session's own ephemeral cleanup, or another `coi kill`).
			// Incus reports the loser with messages like "A matching non-reusable
			// operation has now succeeded" — the instance is gone, but the error
			// text varies by race window and incus version. Rather than pattern-
			// match every phrasing, re-check the actual end state: if the instance
			// is no longer there, the delete effectively succeeded and it counts as
			// killed. Only a delete error that leaves the instance PRESENT is a real
			// failure.
			if exists, chkErr := mgr.Exists(); chkErr == nil && !exists {
				killed++
				fmt.Printf("  ✓ Killed %s\n", name)
			} else {
				fmt.Fprintf(os.Stderr, "  Warning: Failed to delete %s: %v\n", name, err)
			}
		}
	}

	if killed > 0 {
		fmt.Printf("\nKilled %d container(s)\n", killed)
	} else {
		fmt.Println("\nNo containers were killed")
		if len(containerNames) > 0 {
			// User specified containers but none were killed - this is an error
			return fmt.Errorf("failed to kill specified containers")
		}
	}

	return nil
}

// cleanupNftRulesForIP removes any nft rules associated with a container IP
func cleanupNftRulesForIP(containerIP string) error {
	if containerIP == "" {
		return nil
	}

	// Create a temporary firewall manager to remove rules for this IP
	fm := network.NewNftManager(containerIP, "")
	return fm.RemoveRules()
}

// cleanupNftMonitoringRulesForIP removes any NFT monitoring rules for a container IP
func cleanupNftMonitoringRulesForIP(containerIP string) error {
	return network.CleanupNFTMonitoringRules(containerIP)
}
