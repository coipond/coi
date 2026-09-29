package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mensfeld/code-on-incus/internal/container"
	"github.com/mensfeld/code-on-incus/internal/image"
	"github.com/spf13/cobra"
)

var showAll bool

// imageCmd is the parent command for all image operations
var imageCmd = &cobra.Command{
	Use:   "image",
	Short: "Manage Incus images",
	Long:  `Operations for listing, publishing, deleting, and managing container images.`,
}

// imageListCmd lists available images
var imageListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available images",
	Long: `List available Incus images with optional filtering.

Examples:
  coi image list                           # List Coi images
  coi image list --all                     # List all local images
  coi image list --prefix claudeyard-      # List images starting with prefix
  coi image list --format json             # Output as JSON`,
	RunE: imageListCommand,
}

// imagePublishCmd publishes a container as an image
var imagePublishCmd = &cobra.Command{
	Use:   "publish <container> <alias>",
	Short: "Publish a stopped container as an image",
	Long: `Publish a container as an image with the given alias.

Examples:
  coi image publish my-container my-image --description "Custom build with Python 3.11"
  coi image publish my-container my-image --compression none`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		containerName := args[0]
		aliasName := args[1]

		description, _ := cmd.Flags().GetString("description")
		compression, _ := cmd.Flags().GetString("compression")

		// Publish container
		fingerprint, err := container.PublishContainer(containerName, aliasName, description, compression)
		if err != nil {
			return fmt.Errorf("failed to publish container: %v", err)
		}

		// Output as JSON
		result := map[string]string{
			"fingerprint": fingerprint,
			"alias":       aliasName,
		}
		jsonOutput, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonOutput))

		return nil
	},
}

// imageDeleteCmd deletes an image
var imageDeleteCmd = &cobra.Command{
	Use:   "delete <alias>",
	Short: "Delete an image by alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		aliasName := args[0]

		if err := container.DeleteImage(aliasName); err != nil {
			return fmt.Errorf("failed to delete image: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Image %s deleted\n", aliasName)
		return nil
	},
}

// imageExistsCmd checks if an image exists
var imageExistsCmd = &cobra.Command{
	Use:   "exists <alias>",
	Short: "Check if an image exists",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		aliasName := args[0]

		exists, err := container.ImageExists(aliasName)
		if err != nil {
			return fmt.Errorf("failed to check image: %v", err)
		}

		if !exists {
			return &ExitCodeError{Code: 1}
		}

		return nil
	},
}

// imageCleanupCmd cleans up old image versions
var imageCleanupCmd = &cobra.Command{
	Use:   "cleanup <prefix>",
	Short: "Delete old image versions, keeping only N most recent",
	Long: `Delete old versions of images matching a prefix, keeping only the N most recent.

Image aliases must follow format: prefix-YYYYMMDD-HHMMSS

Example:
  # Keep only the 3 most recent versions of node-42 images
  coi image cleanup claudeyard-node-42- --keep 3`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		prefix := args[0]
		keepCount, _ := cmd.Flags().GetInt("keep")

		if keepCount <= 0 {
			return &ExitCodeError{Code: 2, Message: "--keep must be > 0"}
		}

		deleted, kept, err := image.Cleanup(prefix, keepCount)
		if err != nil {
			return fmt.Errorf("cleanup failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Cleanup complete:\n")
		if len(deleted) > 0 {
			fmt.Fprintf(os.Stderr, "\nDeleted %d old version(s):\n", len(deleted))
			for _, alias := range deleted {
				fmt.Fprintf(os.Stderr, "  - %s\n", alias)
			}
		}
		if len(kept) > 0 {
			fmt.Fprintf(os.Stderr, "\nKept %d recent version(s):\n", len(kept))
			for _, alias := range kept {
				fmt.Fprintf(os.Stderr, "  - %s\n", alias)
			}
		}

		return nil
	},
}

// imageInfoCmd shows detailed information about an image
var imageInfoCmd = &cobra.Command{
	Use:   "info <alias>",
	Short: "Show detailed image information",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		alias := args[0]
		format, _ := cmd.Flags().GetString("format")
		applyJSONFormatAlias(cmd, &format)

		// Validate format
		if err := validateTextOrJSON(format); err != nil {
			return err
		}

		var output string
		var err error

		if format == "json" {
			output, err = container.IncusOutput("image", "info", alias, "--format=json")
		} else {
			output, err = container.IncusOutput("image", "info", alias)
		}

		if err != nil {
			return fmt.Errorf("failed to get image info: %v", err)
		}

		fmt.Print(output)
		return nil
	},
}

func init() {
	// Add flags to list command
	imageListCmd.Flags().BoolVarP(&showAll, "all", "a", false, "Show all local images, not just Coi images")
	imageListCmd.Flags().String("prefix", "", "Filter images by alias prefix")
	imageListCmd.Flags().String("format", "text", "Output format: text or json")
	imageListCmd.Flags().Bool("json", false, "Alias for --format json")

	// Add flags to publish command
	imagePublishCmd.Flags().String("description", "", "Image description")
	imagePublishCmd.Flags().String("compression", "", "Compression algorithm (e.g., none, gzip, xz; see Incus docs for all options)")

	// Add flags to cleanup command
	imageCleanupCmd.Flags().Int("keep", 0, "Number of versions to keep (required)")
	_ = imageCleanupCmd.MarkFlagRequired("keep") // Always succeeds for valid flag names.

	// Add flags to info command
	imageInfoCmd.Flags().String("format", "text", "Output format: text or json")
	imageInfoCmd.Flags().Bool("json", false, "Alias for --format json")

	// Add subcommands to image command
	imageCmd.AddCommand(imageListCmd)
	imageCmd.AddCommand(imagePublishCmd)
	imageCmd.AddCommand(imageDeleteCmd)
	imageCmd.AddCommand(imageExistsCmd)
	imageCmd.AddCommand(imageCleanupCmd)
	imageCmd.AddCommand(imageInfoCmd)
}

func imageListCommand(cmd *cobra.Command, args []string) error {
	// Check if Incus is available
	if !container.Available() {
		return container.IncusNotAvailableError()
	}

	format, _ := cmd.Flags().GetString("format")
	applyJSONFormatAlias(cmd, &format)
	prefix, _ := cmd.Flags().GetString("prefix")

	// Validate format value
	if err := validateTextOrJSON(format); err != nil {
		return err
	}

	// If format is JSON, output structured data
	if format == "json" {
		images, err := image.ListAllImages(prefix)
		if err != nil {
			return fmt.Errorf("failed to list images: %w", err)
		}

		jsonOutput, _ := json.MarshalIndent(images, "", "  ")
		fmt.Println(string(jsonOutput))
		return nil
	}

	// Table format (human-readable)
	if prefix != "" {
		// List with prefix filter
		images, err := image.ListAllImages(prefix)
		if err != nil {
			return fmt.Errorf("failed to list images: %w", err)
		}

		if len(images) == 0 {
			fmt.Printf("No images found with prefix '%s'\n", prefix)
			return nil
		}

		fmt.Printf("Images with prefix '%s':\n\n", prefix)
		tbl := NewTable("ALIAS", "SIZE", "CREATED")
		for _, img := range images {
			for _, alias := range img.Aliases {
				sizeFormatted := formatSize(fmt.Sprintf("%d", img.Size))
				createdFormatted := img.CreatedAt.Format("2006-01-02 15:04")
				tbl.AddRow(alias, sizeFormatted, createdFormatted)
			}
		}
		tbl.Render()
		return nil
	}

	// Default listing (Coi images + optional all)
	fmt.Println("Available Images:")
	fmt.Println()

	// Check Coi images
	coiImages := []struct {
		alias       string
		description string
		buildCmd    string
	}{
		{"coi-default", "coi image (Claude CLI, Node.js, Docker, GitHub CLI, tmux)", "coi build"},
	}

	fmt.Println("Coi Images:")
	for _, img := range coiImages {
		exists, err := container.ImageExists(img.alias)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s - error checking: %v\n", img.alias, err)
			continue
		}

		if exists {
			fmt.Printf("  ✓ %s\n", img.alias)
			fmt.Printf("    %s\n", img.description)
		} else {
			fmt.Printf("  ✗ %s (not built)\n", img.alias)
			fmt.Printf("    %s\n", img.description)
			fmt.Printf("    Build with: %s\n", img.buildCmd)
		}
		fmt.Println()
	}

	if showAll {
		fmt.Println("All Local Images:")
		if err := listAllImages(); err != nil {
			return err
		}
	} else {
		fmt.Println("Tip: Use --all to see all local images")
	}

	fmt.Println()
	fmt.Println("Remote Images:")
	fmt.Println("  You can use any image from images.linuxcontainers.org:")
	fmt.Println("  - ubuntu:22.04, ubuntu:24.04")
	fmt.Println("  - debian:12, debian:11")
	fmt.Println("  - alpine:3.19")
	fmt.Println()
	fmt.Println("  Example: set [container] image = \"ubuntu:24.04\" in config or a profile")
	fmt.Println()
	fmt.Println("Custom Images:")
	fmt.Println("  Build your own: coi build custom --script setup.sh my-image")
	fmt.Println()

	return nil
}

// listAllImages lists all local Incus images
func listAllImages() error {
	mgr := container.NewManager("temp")

	output, err := mgr.ExecHostCommand("incus image list --format=csv -c l,s,u", true)
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		fmt.Println("  No local images found")
		return nil
	}

	tbl := NewTable("ALIAS", "SIZE", "UPLOAD DATE")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		alias := parts[0]
		size := parts[1]
		uploadDate := parts[2]

		// Format size (convert bytes to human readable)
		sizeFormatted := formatSize(size)

		tbl.AddRow(alias, sizeFormatted, uploadDate)
	}
	tbl.Render()

	return nil
}

// formatSize converts byte string to human readable
func formatSize(sizeStr string) string {
	// Size is in bytes as string, convert to MB/GB
	var bytes int64
	_, _ = fmt.Sscanf(sizeStr, "%d", &bytes) // Ignore error, default to 0 if parse fails

	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1fGB", float64(bytes)/(1024*1024*1024))
}
