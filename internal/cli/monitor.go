package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/session"
	"github.com/spf13/cobra"
)

var (
	monitorJSON   bool
	monitorFormat string
	monitorWatch  int
)

func init() {
	monitorCmd.Flags().StringVar(&monitorFormat, "format", "text", "Output format: text or json")
	monitorCmd.Flags().BoolVar(&monitorJSON, "json", false, "Output in JSON format (alias for --format json)")
	monitorCmd.Flags().IntVar(&monitorWatch, "watch", 0, "Watch mode: update every N seconds (0 = one-shot)")
}

var monitorCmd = &cobra.Command{
	Use:   "monitor [container]",
	Short: "Display real-time security monitoring for a container",
	Long: `Display real-time security monitoring for a container.

This command shows current container metrics including:
- Network connections (with suspicious connection detection)
- Running processes (with reverse shell detection)
- Filesystem activity (workspace read monitoring)
- Resource usage (CPU, memory, I/O)
- Security threats and alerts

If no container name is provided, it will attempt to detect the container
from the current workspace.

Examples:
  coi monitor                    # Auto-detect container, one-shot
  coi monitor coi-abc-1          # Monitor specific container
  coi monitor --format json      # JSON output
  coi monitor --json             # JSON output (backward-compatible alias)
  coi monitor --watch 2          # Update every 2 seconds`,
	RunE: app.monitorCommand,
}

func (a *App) monitorCommand(cmd *cobra.Command, args []string) error {
	// Resolve the same session identity the launch used (profile-carried
	// session_name), error-tolerantly per #607.
	a.applyDefaultProfileForOps(cmd)
	// Reconcile --json flag with --format flag (backward compatibility)
	if monitorJSON {
		monitorFormat = "json"
	}

	// Validate format value
	if err := validateTextOrJSON(monitorFormat); err != nil {
		return err
	}

	// Watch mode doesn't support JSON output
	if monitorFormat == "json" && monitorWatch > 0 {
		return &ExitCodeError{Code: 2, Message: "--format json is not supported with --watch"}
	}

	ctx := cmd.Context()

	// Determine container name using 3-tier resolution:
	// 1. Positional argument
	// 2. COI_CONTAINER environment variable
	// 3. Auto-detect from workspace
	containerName, err := a.resolveMonitorContainer(args)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Monitoring container: %s\n", containerName)

	// Get allowed CIDRs from network config
	allowedCIDRs := []string{}
	if a.cfg.Network.Mode == config.NetworkModeAllowlist {
		// Convert allowed domains to CIDRs (simplified - in full implementation would resolve)
		// For now, just pass empty list
		allowedCIDRs = []string{}
	}

	// Create collector
	collector := monitor.NewCollector(containerName, "", "", allowedCIDRs)
	detector := monitor.NewDetector(a.cfg.Monitoring.FileReadThresholdMB, a.cfg.Monitoring.FileReadRateMBPerSec).
		WithReverseShellOneLinerPolicy(config.StringVal(a.cfg.Monitoring.ReverseShellOneLiners))

	// Watch mode or one-shot
	if monitorWatch > 0 {
		return runMonitorWatch(ctx, collector, detector, monitorWatch)
	}

	// One-shot collection
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}

	// Detect threats
	snapshot.Threats = detector.Analyze(snapshot)

	// Output
	if monitorFormat == "json" {
		data, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(monitor.FormatSnapshot(snapshot))
	}

	return nil
}

// resolveMonitorContainer resolves the container name using the following strategy:
// 1. Use positional arg if provided
// 2. Check COI_CONTAINER environment variable
// 3. Find container for current workspace
func (a *App) resolveMonitorContainer(args []string) (string, error) {
	// 1. Use positional arg if provided (with alias resolution)
	if len(args) > 0 {
		name := args[0]
		if resolved, err := alias.ResolveAliasForRunning(name); err == nil {
			name = resolved
		} else if !alias.IsContainerName(name) {
			return "", err
		}
		mgr := container.NewManager(name)
		exists, err := mgr.Exists()
		if err != nil {
			return "", fmt.Errorf("failed to check container: %w", err)
		}
		if !exists {
			return "", fmt.Errorf("container '%s' not found", name)
		}
		return name, nil
	}

	// 2. Check COI_CONTAINER environment variable
	if envContainer := os.Getenv("COI_CONTAINER"); envContainer != "" {
		mgr := container.NewManager(envContainer)
		exists, err := mgr.Exists()
		if err != nil {
			return "", fmt.Errorf("failed to check container: %w", err)
		}
		if !exists {
			return "", fmt.Errorf("container '%s' from COI_CONTAINER not found", envContainer)
		}
		return envContainer, nil
	}

	// 3. Find container for current workspace
	absWorkspace, err := filepath.Abs(a.workspace)
	if err != nil {
		return "", fmt.Errorf("failed to resolve workspace path: %w", err)
	}

	sessions, err := session.ListWorkspaceSessions(absWorkspace, a.sessionName())
	if err != nil {
		return "", fmt.Errorf("failed to list workspace sessions: %w", err)
	}

	if len(sessions) == 0 {
		return "", fmt.Errorf("no Coi containers found for current workspace - pass container name as argument")
	}

	if len(sessions) > 1 {
		var names []string
		for _, name := range sessions {
			names = append(names, name)
		}
		return "", fmt.Errorf("multiple Coi containers found for workspace, pass container name as argument: %s", strings.Join(names, ", "))
	}

	// Exactly one container
	for _, name := range sessions {
		return name, nil
	}

	return "", fmt.Errorf("no Coi containers found for current workspace")
}

func runMonitorWatch(ctx context.Context, collector *monitor.Collector, detector *monitor.Detector, intervalSec int) error {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	// Initial collection
	snapshot, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect metrics: %w", err)
	}
	snapshot.Threats = detector.Analyze(snapshot)

	// Clear screen and display
	fmt.Print("\033[2J\033[H") // Clear screen, move cursor to top
	fmt.Print(monitor.FormatSnapshot(snapshot))
	fmt.Printf("\nLast Updated: %s | Press Ctrl+C to exit\n", time.Now().Format("2006-01-02 15:04:05"))

	// Watch loop
	for {
		select {
		case <-ticker.C:
			snapshot, err := collector.Collect(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}
			snapshot.Threats = detector.Analyze(snapshot)

			// Clear screen and display
			fmt.Print("\033[2J\033[H") // Clear screen, move cursor to top
			fmt.Print(monitor.FormatSnapshot(snapshot))
			fmt.Printf("\nLast Updated: %s | Press Ctrl+C to exit\n", time.Now().Format("2006-01-02 15:04:05"))

		case <-ctx.Done():
			return nil
		}
	}
}
