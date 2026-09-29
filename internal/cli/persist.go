package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/session"
	"github.com/spf13/cobra"
)

var (
	persistForce bool
	persistAll   bool
)

var persistCmd = &cobra.Command{
	Use:   "persist [container-name...]",
	Short: "Convert ephemeral sessions to persistent",
	Long: `Convert one or more ephemeral containers to persistent mode.

Persistent containers are not automatically deleted when stopped, allowing you
to preserve installed tools and configurations across sessions.

Use 'coi list' to see active containers and their persistence mode.

Examples:
  coi persist coi-abc12345-1              # Persist specific container
  coi persist coi-abc12345-1 coi-xyz78901-2  # Persist multiple containers
  coi persist --all                       # Persist all containers (with confirmation)
  coi persist --all --force               # Persist all without confirmation
`,
	RunE: persistCommand,
}

func init() {
	persistCmd.Flags().BoolVarP(&persistForce, "force", "f", false, "Skip confirmation prompts")
	persistCmd.Flags().BoolVarP(&persistAll, "all", "a", false, "Persist all containers")
}

func persistCommand(cmd *cobra.Command, args []string) error {
	// Get container names to persist
	var containerNames []string

	if persistAll {
		// Get all containers
		containers, err := listActiveContainers()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		if len(containers) == 0 {
			fmt.Println("No containers to persist")
			return nil
		}

		for _, c := range containers {
			containerNames = append(containerNames, c.Name)
		}

		// Show what will be persisted
		fmt.Printf("Found %d container(s):\n", len(containerNames))
		for _, name := range containerNames {
			fmt.Printf("  - %s\n", name)
		}

		// Confirm unless --force
		if !persistForce {
			if !confirmYN("\nPersist all these containers? [y/N]: ") {
				fmt.Println("Cancelled.")
				return nil
			}
		}
	} else {
		// Use containers from args
		if len(args) == 0 {
			return fmt.Errorf("no container names provided - use 'coi list' to see active containers")
		}
		containerNames = args

		// Confirm unless --force or single container
		if !persistForce && len(containerNames) > 1 {
			if !confirmYN(fmt.Sprintf("Persist %d container(s)? [y/N]: ", len(containerNames))) {
				fmt.Println("Cancelled.")
				return nil
			}
		}
	}

	// Get tool instance to determine sessions directory
	toolInstance, err := getConfiguredTool(app.cfg)
	if err != nil {
		return err
	}

	// Get sessions directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	baseDir := filepath.Join(homeDir, ".coi")
	sessionsDir := session.GetSessionsDir(baseDir, toolInstance)

	// Persist each container
	persisted := 0
	for _, name := range containerNames {
		fmt.Printf("Persisting container %s...\n", name)
		mgr := container.NewManager(name)

		// Check if container exists
		exists, err := mgr.Exists()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to check if %s exists: %v\n", name, err)
			continue
		}
		if !exists {
			fmt.Fprintf(os.Stderr, "  Warning: Container %s does not exist\n", name)
			continue
		}

		// Find session metadata for this container
		metadataPath, err := findSessionMetadata(sessionsDir, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: %v\n", err)
			continue
		}

		// Update persistent flag in metadata
		if err := updatePersistentFlag(metadataPath, true); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Failed to update metadata: %v\n", err)
			continue
		}

		persisted++
		fmt.Printf("  ✓ Persisted %s\n", name)
	}

	if persisted > 0 {
		fmt.Printf("\nPersisted %d container(s)\n", persisted)
	} else {
		fmt.Println("\nNo containers were persisted")
		if len(containerNames) > 0 {
			// User specified containers but none were persisted - this is an error
			return fmt.Errorf("failed to persist specified containers")
		}
	}

	return nil
}

// findSessionMetadata finds the metadata.json file for a given container name
func findSessionMetadata(sessionsDir, containerName string) (string, error) {
	// Check if sessions directory exists
	if _, err := os.Stat(sessionsDir); os.IsNotExist(err) {
		return "", fmt.Errorf("sessions directory not found: %s", sessionsDir)
	}

	// Scan all session directories
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return "", fmt.Errorf("failed to read sessions directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		metadataPath := filepath.Join(sessionsDir, entry.Name(), "metadata.json")
		metadata, err := session.LoadSessionMetadata(metadataPath)
		if err != nil {
			// Skip invalid metadata files
			continue
		}

		if metadata.ContainerName == containerName {
			return metadataPath, nil
		}
	}

	return "", fmt.Errorf("no session metadata found for container %s", containerName)
}

// updatePersistentFlag updates the persistent field in a metadata file
func updatePersistentFlag(metadataPath string, persistent bool) error {
	// Load existing metadata
	metadata, err := session.LoadSessionMetadata(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Check if already persistent
	if metadata.Persistent == persistent {
		return nil // No change needed
	}

	// Update persistent field and marshal the WHOLE struct — the previous
	// hand-written JSON silently dropped fields it didn't format
	// (profile_name), so persisting a session lost profile inheritance on
	// the next resume.
	metadata.Persistent = persistent

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return os.WriteFile(metadataPath, append(data, '\n'), 0o644)
}
