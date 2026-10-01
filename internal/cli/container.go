package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

// containerCmd is the parent command for all container operations
var containerCmd = &cobra.Command{
	Use:   "container",
	Short: "Manage Incus containers",
	Long:  `Low-level container operations for launching, stopping, executing commands, and managing containers.`,
}

// containerLaunchCmd launches a new container from an image
var containerLaunchCmd = &cobra.Command{
	Use:   "launch <image> <name>",
	Short: "Launch a new container from an image",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		image := args[0]
		name := args[1]

		ephemeral, _ := cmd.Flags().GetBool("ephemeral")
		pool, _ := cmd.Flags().GetString("storage")

		if err := container.ValidateStoragePool(pool); err != nil {
			return err
		}

		// Honor [container] docker / [security] reduce_kernel_surface from the
		// loaded config (app.cfg is populated by PersistentPreRunE), so `coi
		// container launch` doesn't silently give a hardened setup the full
		// Docker/nesting surface.
		policy := app.hardeningPolicy()
		warnDockerHardeningConflict(app.cfg)
		mgr := container.NewManager(name)
		if err := mgr.LaunchWithPolicy(image, ephemeral, pool, policy); err != nil {
			return fmt.Errorf("failed to launch container: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Container %s launched from %s\n", name, image)
		return nil
	},
}

// containerStartCmd starts a stopped container
var containerStartCmd = &cobra.Command{
	Use:   "start <name>",
	Short: "Start a stopped container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// #691: proactively apply the #683 shift→raw.idmap decision before
		// starting, deriving the statfs-sweep sources from the container's own
		// disk devices (this command has no session context). On OrbStack ≥2.2.2
		// a shift=true mount succeeds-but-unwritable, so the reactive fallback
		// below never fires; this heals a pre-#689 container up front. No-op
		// unless the container still carries a shift=true disk device.
		disableShift := false
		if app.cfg != nil {
			disableShift = app.cfg.Incus.DisableShift
		}
		session.ResolveStartUIDMapping(name, disableShift, func(msg string) {
			fmt.Fprintln(os.Stderr, msg)
		})

		// Recover from the #678 idmapped-mount start failure here too, rather
		// than handing back a raw Incus error the user can't act on (#685). The
		// isolation fallback is deliberately not used: this command runs against
		// an arbitrary container, and it must not unset security.idmap.isolated
		// on someone's container as a side effect of a failed start.
		if err := container.StartWithIdmapFallback(name); err != nil {
			return fmt.Errorf("failed to start container: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Container %s started\n", name)
		return nil
	},
}

// containerStopCmd stops a running container
var containerStopCmd = &cobra.Command{
	Use:   "stop <name>",
	Short: "Stop a running container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		force, _ := cmd.Flags().GetBool("force")

		mgr := container.NewManager(name)
		if err := mgr.Stop(force); err != nil {
			return fmt.Errorf("failed to stop container: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Container %s stopped\n", name)
		return nil
	},
}

// containerDeleteCmd deletes a container
var containerDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a container",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		force, _ := cmd.Flags().GetBool("force")

		mgr := container.NewManager(name)

		// Get container IP BEFORE deleting (needed for nft cleanup)
		var containerIP string
		if network.NftAvailable() {
			containerIP, _ = network.GetContainerIPFast(name)
		}

		// Clean up ALL host-side firewall artefacts BEFORE deleting the
		// container: the IP-keyed rule bundle + sets, the monitoring LOG rules,
		// and the NAME-keyed coi6-<name> IPv6 block. Using the shared helper
		// (same one kill/shutdown use) closes #696 item 5 — the old inline
		// RemoveRules() left the LOG rules and the IPv6 block behind.
		cleanupContainerFirewall(name, containerIP)

		if err := mgr.Delete(force); err != nil {
			return fmt.Errorf("failed to delete container: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Container %s deleted\n", name)
		return nil
	},
}

// containerExecCmd executes a command in a container
var containerExecCmd = &cobra.Command{
	Use:   "exec <name> -- <command>",
	Short: "Execute a command in a container",
	Long: `Execute a command inside a container with full context control.

Examples:
  # Run as root
  coi container exec my-container -- ls -la /

  # Run as specific user with env vars
  coi container exec my-container --user 1000 --env FOO=bar --cwd /workspace -- npm test

  # Allocate a PTY for interactive sessions (required for tmux, shells, etc.)
  coi container exec my-container -t -- bash

  # Capture output as JSON
  coi container exec my-container --capture -- echo "hello world"`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		containerName := args[0]
		commandArgs := args[1:] // Keep as separate arguments

		if len(commandArgs) == 0 {
			return &ExitCodeError{Code: 2, Message: "no command specified (use -- before command)"}
		}

		capture, _ := cmd.Flags().GetBool("capture")
		format, _ := cmd.Flags().GetString("format")
		tty, _ := cmd.Flags().GetBool("tty")
		mgr := container.NewManager(containerName)

		// Validate that --format requires --capture
		if cmd.Flags().Changed("format") && !capture {
			return &ExitCodeError{Code: 2, Message: "--format flag requires --capture flag"}
		}

		// Validate format value
		if format != "json" && format != "raw" {
			return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid format '%s': must be 'json' or 'raw'", format)}
		}

		// Validate that --tty and --capture are mutually exclusive
		if tty && capture {
			return &ExitCodeError{Code: 2, Message: "--tty and --capture flags are mutually exclusive"}
		}

		if capture {
			// For capture mode, use ExecArgsCapture (no bash -c wrapping, preserves whitespace)
			// Parse flags
			userFlag, _ := cmd.Flags().GetInt("user")
			groupFlag, _ := cmd.Flags().GetInt("group")
			envVars, _ := cmd.Flags().GetStringArray("env")
			cwd, _ := cmd.Flags().GetString("cwd")

			// Auto-detect workspace path if --cwd not explicitly set
			if !cmd.Flags().Changed("cwd") {
				cwd = mgr.GetWorkspacePath()
			}

			// Parse env vars
			env := make(map[string]string)
			for _, e := range envVars {
				parts := strings.SplitN(e, "=", 2)
				if len(parts) == 2 {
					env[parts[0]] = parts[1]
				}
			}

			opts := container.ExecCommandOptions{
				Cwd: cwd,
				Env: env,
			}

			if cmd.Flags().Changed("user") {
				opts.User = &userFlag
			}
			if cmd.Flags().Changed("group") {
				opts.Group = &groupFlag
			}

			output, err := mgr.ExecArgsCapture(commandArgs, opts)

			// Handle raw format - output stdout and exit with proper code
			if format == "raw" {
				fmt.Print(output) // No newline, preserve exact output
				if err != nil {
					// Extract actual exit code if available, otherwise use 1
					exitCode := 1
					if exitErr, ok := err.(*container.ExitError); ok {
						exitCode = exitErr.ExitCode
					}
					return &ExitCodeError{Code: exitCode}
				}
				return nil
			}

			// Handle JSON format (default)
			exitCode := 0
			stderr := ""
			if err != nil {
				// Extract actual exit code if available, otherwise use 1
				exitCode = 1
				if exitErr, ok := err.(*container.ExitError); ok {
					exitCode = exitErr.ExitCode
				}
				stderr = err.Error()
			}

			result := map[string]interface{}{
				"stdout":    output,
				"stderr":    stderr,
				"exit_code": exitCode,
			}
			jsonOutput, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(jsonOutput))
			return nil
		}

		// For non-capture mode, use ExecArgs with options
		userFlag, _ := cmd.Flags().GetInt("user")
		groupFlag, _ := cmd.Flags().GetInt("group")
		envVars, _ := cmd.Flags().GetStringArray("env")
		cwd, _ := cmd.Flags().GetString("cwd")

		// Auto-detect workspace path if --cwd not explicitly set
		if !cmd.Flags().Changed("cwd") {
			cwd = mgr.GetWorkspacePath()
		}

		// Parse env vars
		env := make(map[string]string)
		for _, e := range envVars {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				env[parts[0]] = parts[1]
			}
		}

		opts := container.ExecCommandOptions{
			Cwd:         cwd,
			Env:         env,
			Interactive: tty,
		}

		if cmd.Flags().Changed("user") {
			opts.User = &userFlag
		}
		if cmd.Flags().Changed("group") {
			opts.Group = &groupFlag
		}

		err := mgr.ExecArgs(commandArgs, opts)
		if err != nil {
			return fmt.Errorf("command failed: %v", err)
		}

		return nil
	},
}

// containerExistsCmd checks if a container exists
var containerExistsCmd = &cobra.Command{
	Use:   "exists <name>",
	Short: "Check if a container exists",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		mgr := container.NewManager(name)
		exists, err := mgr.Exists()
		if err != nil {
			return fmt.Errorf("failed to check container: %v", err)
		}

		if !exists {
			return &ExitCodeError{Code: 1}
		}

		return nil
	},
}

// containerRunningCmd checks if a container is running
var containerRunningCmd = &cobra.Command{
	Use:   "running <name>",
	Short: "Check if a container is running",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		mgr := container.NewManager(name)
		running, err := mgr.Running()
		if err != nil {
			return fmt.Errorf("failed to check container: %v", err)
		}

		if !running {
			return &ExitCodeError{Code: 1}
		}

		return nil
	},
}

// containerMountCmd mounts a disk to a container
var containerMountCmd = &cobra.Command{
	Use:   "mount <name> <device-name> <source> <path>",
	Short: "Add a disk device to a container",
	Long: `Mount a host directory into a container.

Example:
  coi container mount my-container workspace /home/user/project /workspace --shift`,
	Args: cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		deviceName := args[1]
		source := args[2]
		path := args[3]

		shift, _ := cmd.Flags().GetBool("shift")
		readonly, _ := cmd.Flags().GetBool("readonly")

		mgr := container.NewManager(name)
		if err := mgr.MountDisk(deviceName, source, path, shift, readonly); err != nil {
			return fmt.Errorf("failed to mount disk: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Disk mounted: %s -> %s:%s\n", source, name, path)
		return nil
	},
}

// containerListCmd lists all containers
var containerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all containers",
	Long: `List all containers in JSON or text format.

This is a low-level command that provides raw container information,
similar to 'incus list'. For a higher-level view with session info,
use 'coi list' instead.

Examples:
  # List containers in text format (default)
  coi container list

  # List containers in JSON format
  coi container list --format=json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		format, _ := cmd.Flags().GetString("format")
		applyJSONFormatAlias(cmd, &format)

		// Validate format
		if format != "json" && format != "text" {
			return &ExitCodeError{Code: 2, Message: fmt.Sprintf("invalid format '%s': must be 'json' or 'text'", format)}
		}

		// Get raw incus list output
		var output string
		var err error

		if format == "json" {
			output, err = container.IncusOutput("list", "--format=json")
		} else {
			output, err = container.IncusOutput("list")
		}

		if err != nil {
			return fmt.Errorf("failed to list containers: %v", err)
		}

		fmt.Print(output)
		return nil
	},
}

// containerInfoCmd shows detailed information about a container
var containerInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show detailed container information",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		format, _ := cmd.Flags().GetString("format")
		applyJSONFormatAlias(cmd, &format)

		// Validate format
		if err := validateTextOrJSON(format); err != nil {
			return err
		}

		var output string
		var err error

		if format == "json" {
			output, err = container.IncusOutput("info", name, "--format=json")
		} else {
			output, err = container.IncusOutput("info", name)
		}

		if err != nil {
			return fmt.Errorf("failed to get container info: %v", err)
		}

		fmt.Print(output)
		return nil
	},
}

func init() {
	// Add flags to launch command
	containerLaunchCmd.Flags().Bool("ephemeral", false, "Create ephemeral container")
	containerLaunchCmd.Flags().StringP("storage", "s", "", "Incus storage pool name (empty = default pool)")

	// Add flags to stop command
	containerStopCmd.Flags().BoolP("force", "f", false, "Force stop")

	// Add flags to delete command
	containerDeleteCmd.Flags().BoolP("force", "f", false, "Force delete even if running")

	// Add flags to exec command
	containerExecCmd.Flags().Int("user", 0, "User ID to run as")
	containerExecCmd.Flags().Int("group", 0, "Group ID to run as")
	containerExecCmd.Flags().StringArray("env", []string{}, "Environment variable (KEY=VALUE)")
	containerExecCmd.Flags().String("cwd", "", "Working directory (auto-detects from container if not set)")
	containerExecCmd.Flags().Bool("capture", false, "Capture output as JSON")
	containerExecCmd.Flags().String("format", "json", "Output format when using --capture: json or raw")
	containerExecCmd.Flags().BoolP("tty", "t", false, "Allocate a pseudo-terminal (PTY)")

	// Add flags to mount command
	containerMountCmd.Flags().Bool("shift", true, "Enable UID/GID shifting")
	containerMountCmd.Flags().Bool("readonly", false, "Mount as read-only")

	// Add flags to info command
	containerInfoCmd.Flags().String("format", "text", "Output format: text or json")
	containerInfoCmd.Flags().Bool("json", false, "Alias for --format json")

	// Add flags to list command
	containerListCmd.Flags().String("format", "text", "Output format: text or json")
	containerListCmd.Flags().Bool("json", false, "Alias for --format json")

	// Add subcommands to container command
	containerCmd.AddCommand(containerLaunchCmd)
	containerCmd.AddCommand(containerStartCmd)
	containerCmd.AddCommand(containerStopCmd)
	containerCmd.AddCommand(containerDeleteCmd)
	containerCmd.AddCommand(containerExecCmd)
	containerCmd.AddCommand(containerExistsCmd)
	containerCmd.AddCommand(containerRunningCmd)
	containerCmd.AddCommand(containerMountCmd)
	containerCmd.AddCommand(containerListCmd)
	containerCmd.AddCommand(containerInfoCmd)
}
