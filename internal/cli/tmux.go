package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

// tmuxExecUser resolves the UID whose per-user tmux socket
// (/tmp/tmux-<uid>/default) the tmux commands must target (#588); see
// session.ResolveCodeUID for why this is probed per container.
func tmuxExecUser(mgr container.ContainerManager) (*int, error) {
	uid, err := session.ResolveCodeUID(mgr, container.CodeUser)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container code user: %w", err)
	}
	return &uid, nil
}

var tmuxFormat string

var tmuxCmd = &cobra.Command{
	Use:   "tmux",
	Short: "Interact with tmux sessions in containers",
	Long: `Send commands to or capture output from AI coding sessions running in tmux.
This is primarily for automated workflows.`,
}

var tmuxSendCmd = &cobra.Command{
	Use:   "send <session-name> <command>",
	Short: "Send a command to a tmux session",
	Long: `Send a command to a running tmux session in a container.
The session name should be the container name (e.g., coi-abc123-1).`,
	Args: cobra.ExactArgs(2),
	RunE: tmuxSendCommand,
}

var tmuxCaptureCmd = &cobra.Command{
	Use:   "capture <session-name>",
	Short: "Capture output from a tmux session",
	Long: `Capture the current pane output from a tmux session.
The session name should be the container name (e.g., coi-abc123-1).`,
	Args: cobra.ExactArgs(1),
	RunE: tmuxCaptureCommand,
}

var tmuxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active tmux sessions",
	Long: `List all active tmux sessions across all containers.

Examples:
  coi tmux list
  coi tmux list --format json`,
	RunE: tmuxListCommand,
}

func init() {
	tmuxListCmd.Flags().StringVar(&tmuxFormat, "format", "text", "Output format: text or json")
	tmuxListCmd.Flags().Bool("json", false, "Alias for --format json")

	tmuxCmd.AddCommand(tmuxSendCmd)
	tmuxCmd.AddCommand(tmuxCaptureCmd)
	tmuxCmd.AddCommand(tmuxListCmd)
}

func tmuxSendCommand(cmd *cobra.Command, args []string) error {
	containerName := args[0]
	command := args[1]

	mgr := container.NewManager(containerName)

	// Check if container is running
	running, err := mgr.Running()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}
	if !running {
		return fmt.Errorf("container %s is not running", containerName)
	}

	user, err := tmuxExecUser(mgr)
	if err != nil {
		return err
	}

	// Send command to tmux session
	tmuxSession := fmt.Sprintf("coi-%s", containerName)
	tmuxCmd := fmt.Sprintf("tmux send-keys -t %s %q Enter", tmuxSession, command)

	opts := container.ExecCommandOptions{
		Interactive: false,
		Capture:     true,
		User:        user,
	}

	_, err = mgr.ExecCommand(tmuxCmd, opts)
	if err != nil {
		return fmt.Errorf("failed to send command to tmux session: %w", err)
	}

	fmt.Printf("Sent command to session %s\n", tmuxSession)
	return nil
}

func tmuxCaptureCommand(cmd *cobra.Command, args []string) error {
	containerName := args[0]

	mgr := container.NewManager(containerName)

	// Check if container is running
	running, err := mgr.Running()
	if err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	}
	if !running {
		return fmt.Errorf("container %s is not running", containerName)
	}

	user, err := tmuxExecUser(mgr)
	if err != nil {
		return err
	}

	// Capture tmux pane output
	tmuxSession := fmt.Sprintf("coi-%s", containerName)
	tmuxCmd := fmt.Sprintf("tmux capture-pane -t %s -p", tmuxSession)

	opts := container.ExecCommandOptions{
		Interactive: false,
		Capture:     true,
		User:        user,
	}

	output, err := mgr.ExecCommand(tmuxCmd, opts)
	if err != nil {
		return fmt.Errorf("failed to capture tmux output: %w", err)
	}

	fmt.Print(output)
	return nil
}

func tmuxListCommand(cmd *cobra.Command, args []string) error {
	applyJSONFormatAlias(cmd, &tmuxFormat)
	if err := validateTextOrJSON(tmuxFormat); err != nil {
		return err
	}

	// List all running containers with configured prefix
	containers, err := container.ListContainers("coi-.*")
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Collect sessions first
	type tmuxEntry struct {
		Container string `json:"container"`
		Session   string `json:"session"`
	}

	var sessions []tmuxEntry
	for _, c := range containers {
		mgr := container.NewManager(c)

		// Check if container is running
		running, err := mgr.Running()
		if err != nil || !running {
			continue
		}

		// Resolve the per-container code UID. Unlike a failed Running()
		// check (container is gone), a probe failure can hit a live
		// container with a live session — warn instead of silently
		// omitting it from the listing.
		user, err := tmuxExecUser(mgr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", c, err)
			continue
		}

		// Check if tmux session exists
		tmuxSession := fmt.Sprintf("coi-%s", c)
		checkCmd := fmt.Sprintf("tmux has-session -t %s 2>/dev/null", tmuxSession)

		opts := container.ExecCommandOptions{
			Interactive: false,
			Capture:     false,
			User:        user,
		}

		_, err = mgr.ExecCommand(checkCmd, opts)
		if err == nil {
			sessions = append(sessions, tmuxEntry{Container: c, Session: tmuxSession})
		}
	}

	if tmuxFormat == "json" {
		// Ensure [] not null for empty slice
		if sessions == nil {
			sessions = []tmuxEntry{}
		}
		jsonData, err := json.MarshalIndent(sessions, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	if len(sessions) == 0 {
		fmt.Println("No active sessions")
		return nil
	}

	tbl := NewTable("CONTAINER", "TMUX SESSION")
	for _, s := range sessions {
		tbl.AddRow(s.Container, s.Session)
	}
	tbl.Render()
	return nil
}
