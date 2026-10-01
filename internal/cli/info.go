package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info [session-id]",
	Short: "Show detailed information about a session",
	Long: `Show detailed information about a saved session.

Examples:
  coi info abc123
  coi info
`,
	Args: cobra.MaximumNArgs(1),
	RunE: infoCommand,
}

func infoCommand(cmd *cobra.Command, args []string) error {
	// Get configured tool to determine tool-specific sessions directory
	toolInstance, err := getConfiguredTool(app.cfg)
	if err != nil {
		return err
	}

	// Get tool-specific sessions directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}
	baseDir := filepath.Join(homeDir, ".coi")
	sessionsDir := session.GetSessionsDir(baseDir, toolInstance)

	// Get session ID
	var sessionID string
	if len(args) > 0 {
		sessionID = args[0]
	} else {
		// Get latest session
		sessionID, err = session.GetLatestSession(sessionsDir)
		if err != nil {
			return fmt.Errorf("no sessions found (specify session ID or use 'coi list --all')")
		}
	}

	// Check if session exists
	sessionDir := filepath.Join(sessionsDir, sessionID)
	if _, err := os.Stat(sessionDir); os.IsNotExist(err) {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Read metadata
	metadataPath := filepath.Join(sessionDir, "metadata.json")
	var metadata session.SessionMetadata

	if data, err := os.ReadFile(metadataPath); err == nil {
		if err := json.Unmarshal(data, &metadata); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not parse metadata: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Warning: No metadata found\n")
	}

	// Check if .claude directory exists
	statePath := filepath.Join(sessionDir, ".claude")
	claudeExists := false
	if info, err := os.Stat(statePath); err == nil && info.IsDir() {
		claudeExists = true
	}

	// Display information
	fmt.Printf("Session Information\n")
	fmt.Printf("===================\n\n")
	fmt.Printf("Session ID:     %s\n", sessionID)

	if metadata.ContainerName != "" {
		fmt.Printf("Container:      %s\n", metadata.ContainerName)
	}

	if metadata.SavedAt != "" {
		fmt.Printf("Saved At:       %s\n", metadata.SavedAt)
	}

	fmt.Printf("Session Data:   ")
	if claudeExists {
		fmt.Printf("✓ Present (.claude directory)\n")
	} else {
		fmt.Printf("✗ Missing\n")
	}

	// Show directory size
	if claudeExists {
		size, err := getDirSize(statePath)
		if err == nil {
			fmt.Printf("Data Size:      %s\n", formatBytes(size))
		}
	}

	fmt.Printf("\nSession Path:   %s\n", sessionDir)

	// Show resumability
	fmt.Printf("\nResume:         coi shell --resume %s\n", sessionID)

	return nil
}

// getDirSize calculates the total size of a directory
func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// formatBytes formats bytes into human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
