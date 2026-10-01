package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/network"
	"github.com/spf13/cobra"
)

var (
	shutdownForce bool
	shutdownAll   bool
)

var shutdownCmd = &cobra.Command{
	Use: "shutdown [container-name...]",
	// 'close' echoes the verb users already type INSIDE a container, so it is
	// accepted here too. SuggestFor catches the near-miss typo, which cobra
	// would otherwise resolve against command names only (and point at 'logs').
	Aliases:    []string{"close"},
	SuggestFor: []string{"clos"},
	Short:      "Gracefully stop and delete containers",
	Long: `Gracefully stop and delete one or more containers by name.

This attempts a graceful shutdown first, waiting for the timeout before
force-killing if necessary. The container is then deleted — including a
PERSISTENT one, which this removes rather than keeping for reuse.

'coi close' is an accepted alias for this command. It matches the 'close'
wrapper used INSIDE a container for the usual (ephemeral) case — both end
with the container gone. They differ for a persistent container: powering it
off from inside keeps it (stopped) for the next session, whereas this deletes
it. To stop a persistent container without losing it, power it off from
inside, or use 'coi shell' and exit.

Use 'coi list' to see active containers.

Examples:
  coi shutdown coi-abc12345-1     # Graceful shutdown, then delete (60s grace window by default)
  coi close coi-abc12345-1        # Same thing, via the alias
  coi shutdown --all              # Shutdown all containers
  coi shutdown --all --force      # Shutdown all without confirmation

The grace window is configurable via [container] shutdown_timeout (seconds).
`,
	RunE: shutdownCommand,
}

func init() {
	shutdownCmd.Flags().BoolVarP(&shutdownForce, "force", "f", false, "Skip confirmation prompts")
	shutdownCmd.Flags().BoolVarP(&shutdownAll, "all", "a", false, "Shutdown all containers")
}

func shutdownCommand(cmd *cobra.Command, args []string) error {
	containerNames, err := resolveContainerArgs(args, shutdownAll, shutdownForce, "Shutdown")
	if err != nil {
		return err
	}
	if containerNames == nil {
		return nil
	}

	// Graceful-shutdown window is config-driven: [container] shutdown_timeout
	// (settable globally, per project, or per profile).
	shutdownTimeout := app.cfg.Container.ShutdownTimeoutSeconds()

	// Shutdown each container
	shutdown := 0
	for _, name := range containerNames {
		fmt.Printf("Shutting down container %s (timeout: %ds)...\n", name, shutdownTimeout)
		mgr := container.NewManager(name)

		// Check if container exists at all before attempting anything
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

		// Check if container is running
		running, err := mgr.Running()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to check status of %s: %v\n", name, err)
			continue
		}

		if running {
			// First attempt graceful stop
			fmt.Printf("  Attempting graceful shutdown...\n")
			gracefulDone := make(chan error, 1)
			go func() {
				gracefulDone <- mgr.Stop(false) // graceful stop
			}()

			// Wait for graceful stop or timeout
			select {
			case err := <-gracefulDone:
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Warning: Graceful stop failed: %v\n", err)
				} else {
					fmt.Printf("  Graceful shutdown successful\n")
				}
			case <-time.After(time.Duration(shutdownTimeout) * time.Second):
				// Check if container stopped during timeout (avoids spurious errors)
				if stillRunning, _ := mgr.Running(); stillRunning {
					fmt.Printf("  Timeout reached, force-killing...\n")
					if err := mgr.Stop(true); err != nil {
						fmt.Fprintf(os.Stderr, "  Warning: Force stop failed: %v\n", err)
					}
				} else {
					fmt.Printf("  Container stopped during timeout\n")
				}
			}
		}

		// Clean up nft rules BEFORE deleting container
		cleanupContainerFirewall(name, containerIP)

		// Delete container (may already be gone if ephemeral or cleaned by shell process)
		if err := mgr.Delete(true); err != nil {
			// Check if container is already gone — that counts as success
			if exists, existsErr := mgr.Exists(); existsErr == nil && !exists {
				shutdown++
				fmt.Printf("  ✓ Shutdown %s (already removed)\n", name)
			} else {
				fmt.Fprintf(os.Stderr, "  Warning: Failed to delete %s: %v\n", name, err)
			}
		} else {
			shutdown++
			fmt.Printf("  ✓ Shutdown %s\n", name)
		}
	}

	if shutdown > 0 {
		fmt.Printf("\nShutdown %d container(s)\n", shutdown)
	} else {
		fmt.Println("\nNo containers were shutdown")
		if len(containerNames) > 0 {
			// User specified containers but none were shutdown - this is an error
			return fmt.Errorf("failed to shutdown specified containers")
		}
	}

	return nil
}
