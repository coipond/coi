package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/session"
	"github.com/mensfeld/coi/internal/tool"
	"github.com/spf13/cobra"
)

var (
	listAll     bool
	listFormat  string
	listStatus  string
	listRunning bool
	listStopped bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List active containers and saved sessions",
	Long: `List active Coi containers and saved sessions.

By default, shows only active containers. Use --all to also show saved sessions.

Status filters (--running, --stopped, --status) narrow the active-containers
section only; saved sessions shown by --all have no container status and are
never filtered.

Examples:
  coi list
  coi list --all
  coi list --running
  coi list --stopped
  coi list --status frozen
`,
	RunE: listCommand,
}

func init() {
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "Show saved sessions in addition to active containers")
	listCmd.Flags().StringVar(&listFormat, "format", "text", "Output format: text or json")
	listCmd.Flags().Bool("json", false, "Alias for --format json")
	listCmd.Flags().StringVar(&listStatus, "status", "", "Show only containers with this status: "+strings.Join(validStatusFilters, ", "))
	listCmd.Flags().BoolVar(&listRunning, "running", false, "Show only running containers (alias for --status running)")
	listCmd.Flags().BoolVar(&listStopped, "stopped", false, "Show only stopped containers (alias for --status stopped)")
}

func listCommand(cmd *cobra.Command, args []string) error {
	// Validate format value
	applyJSONFormatAlias(cmd, &listFormat)
	if err := validateTextOrJSON(listFormat); err != nil {
		return err
	}

	// Resolve the status filter before touching Incus so flag misuse fails
	// fast. Changed() rather than a non-empty check so an explicitly passed
	// empty value (--status "") is rejected instead of silently unfiltered.
	statusFilter, err := resolveStatusFilter(cmd.Flags().Changed("status"), listStatus, listRunning, listStopped)
	if err != nil {
		return &ExitCodeError{Code: 2, Message: err.Error()}
	}

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

	// List active containers
	containers, err := listActiveContainers()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	// Status filters constrain only the active-containers section; saved
	// sessions have no container status and are left untouched
	if statusFilter != "" {
		containers = filterContainersByStatus(containers, statusFilter)
	}

	// Build maps of container name -> workspace and container name -> persistent from saved sessions
	// We search for metadata.json files directly (not using listSavedSessions which requires .claude dir)
	// because metadata is saved early at session start, before .claude directory exists
	containerWorkspaces := make(map[string]string)
	containerPersistent := make(map[string]bool)
	if entries, err := os.ReadDir(sessionsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			metadataPath := filepath.Join(sessionsDir, entry.Name(), "metadata.json")
			if data, err := os.ReadFile(metadataPath); err == nil {
				var metadata session.SessionMetadata
				if err := json.Unmarshal(data, &metadata); err == nil && metadata.ContainerName != "" {
					containerWorkspaces[metadata.ContainerName] = metadata.Workspace
					containerPersistent[metadata.ContainerName] = metadata.Persistent
				}
			}
		}
	}

	// Get saved sessions if --all
	var sessions []SessionInfo
	if listAll {
		sessions, err = listSavedSessions(sessionsDir, toolInstance)
		if err != nil {
			return fmt.Errorf("failed to list sessions: %w", err)
		}
	}

	// Route to formatter
	if listFormat == "json" {
		return outputJSON(containers, sessions, containerWorkspaces, containerPersistent)
	}

	return outputText(containers, sessions, containerWorkspaces, containerPersistent, statusFilter)
}

// ContainerInfo holds information about a container
type ContainerInfo struct {
	Name      string
	Status    string
	CreatedAt string
	Image     string
	IPv4      string
	// Pool is the storage pool the container's root device lives in.
	// Sourced from expanded_devices.root.pool in `incus list --format=json`,
	// which already reflects profile defaults — so this is the actual pool
	// being used, not the configured one.
	Pool  string
	Alias string
	// Ports are the container's published host ports (its coi-port-* proxy
	// devices), parsed from the same expanded_devices JSON — no extra Incus
	// calls. Identity-mapped pool ports render as the bare number ("23410"),
	// named entries as "<name>:<host>-><container>" (with the listen address
	// prefixed when it is not loopback). Bound on the host while the
	// container is Running; on a stopped persistent container they are the
	// last session's publications, re-resolved at the next start.
	Ports []string
}

// SessionInfo holds information about a saved session
type SessionInfo struct {
	ID        string
	SavedAt   string
	Workspace string
}

// listActiveContainers lists all active Coi containers
func listActiveContainers() ([]ContainerInfo, error) {
	// Use the configured container prefix (respects COI_CONTAINER_PREFIX env var)
	prefix := session.GetContainerPrefix()
	pattern := fmt.Sprintf("^%s", prefix)

	output, err := container.IncusOutput("list", pattern, "--format=json")
	if err != nil {
		return nil, err
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, err
	}

	var result []ContainerInfo
	for _, c := range containers {
		name, _ := c["name"].(string)            // Type assertion, default to "" if fails
		status, _ := c["status"].(string)        // Type assertion, default to "" if fails
		createdAt, _ := c["created_at"].(string) // Type assertion, default to "" if fails

		// Get image info and alias
		config, _ := c["config"].(map[string]interface{})      // Type assertion
		image, _ := config["image.description"].(string)       // Type assertion
		containerAlias, _ := config["user.coi.alias"].(string) // Alias metadata

		// Parse created_at time
		createdTime := ""
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			createdTime = t.Format("2006-01-02 15:04:05")
		}

		// Extract IPv4 address from eth0 interface
		ipv4 := extractEth0IPv4(c)

		// Extract storage pool from expanded_devices.root.pool — this is the
		// actual pool the container's root disk lives in, after profile
		// expansion. No extra Incus call needed.
		pool := extractRootPool(c)

		result = append(result, ContainerInfo{
			Name:      name,
			Status:    status,
			CreatedAt: createdTime,
			Image:     image,
			IPv4:      ipv4,
			Pool:      pool,
			Alias:     containerAlias,
			Ports:     extractPublishedPorts(c),
		})
	}

	return result, nil
}

// validStatusFilters is the single source of the --status vocabulary: it
// drives the validation, the error message, and the flag help. The values are
// every status Incus reports for an instance, lowercase — matching is
// case-insensitive (see filterContainersByStatus), so lowercase is the
// canonical form throughout the filter path.
var validStatusFilters = []string{
	"running", "stopped", "frozen",
	"error", "starting", "stopping", "freezing", "thawed", "aborting", "ready",
}

// resolveStatusFilter merges --status and the --running/--stopped shorthands
// into a single lowercase status, or "" when no filter was requested.
// statusSet reports whether --status was passed at all (flag.Changed), so an
// explicitly empty value is rejected like any other invalid one instead of
// silently disabling the filter. Combining any two of the flags is an error:
// even a consistent pair like --running --status running is rejected, so
// scripts don't grow invocations that look like they stack two filters.
func resolveStatusFilter(statusSet bool, status string, running, stopped bool) (string, error) {
	flagsSet := 0
	if statusSet {
		flagsSet++
	}
	if running {
		flagsSet++
	}
	if stopped {
		flagsSet++
	}
	if flagsSet > 1 {
		return "", fmt.Errorf("--running, --stopped, and --status are mutually exclusive: pass at most one")
	}

	switch {
	case running:
		return "running", nil
	case stopped:
		return "stopped", nil
	case !statusSet:
		return "", nil
	}

	lower := strings.ToLower(status)
	if slices.Contains(validStatusFilters, lower) {
		return lower, nil
	}
	return "", fmt.Errorf("invalid status '%s': must be one of %s", status, strings.Join(validStatusFilters, ", "))
}

// filterContainersByStatus returns only the containers matching the given
// status. Case-insensitive so a change in Incus status casing can't silently
// empty the filtered output.
func filterContainersByStatus(containers []ContainerInfo, status string) []ContainerInfo {
	filtered := make([]ContainerInfo, 0, len(containers))
	for _, c := range containers {
		if strings.EqualFold(c.Status, status) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// listSavedSessions lists all saved sessions
func listSavedSessions(sessionsDir string, toolInstance tool.Tool) ([]SessionInfo, error) {
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SessionInfo{}, nil
		}
		return nil, err
	}

	// Initialize as empty slice instead of nil so the section always appears with --all
	result := []SessionInfo{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sessionID := entry.Name()

		// Check if it has the tool's config directory (e.g., .claude, .aider, .cursor)
		// Skip if tool uses ENV-based auth (ConfigDirName returns "")
		configDirName := toolInstance.ConfigDirName()
		if configDirName == "" {
			// For ENV-based tools, only check if metadata.json exists
			metadataPath := filepath.Join(sessionsDir, sessionID, "metadata.json")
			if _, err := os.Stat(metadataPath); err != nil {
				continue
			}
		} else {
			// For config-based tools, check if config directory exists
			statePath := filepath.Join(sessionsDir, sessionID, configDirName)
			if info, err := os.Stat(statePath); err != nil || !info.IsDir() {
				continue
			}
		}

		// Try to read metadata
		metadataPath := filepath.Join(sessionsDir, sessionID, "metadata.json")
		savedAt := ""
		workspace := ""

		if data, err := os.ReadFile(metadataPath); err == nil {
			var metadata session.SessionMetadata
			if err := json.Unmarshal(data, &metadata); err == nil {
				savedAt = metadata.SavedAt
				workspace = metadata.Workspace
			}
		}

		// Get directory modification time as fallback
		if savedAt == "" {
			if info, err := entry.Info(); err == nil {
				savedAt = info.ModTime().Format("2006-01-02 15:04:05")
			}
		}

		result = append(result, SessionInfo{
			ID:        sessionID,
			SavedAt:   savedAt,
			Workspace: workspace,
		})
	}

	return result, nil
}

// extractRootPool returns the storage pool name of the container's root disk
// device, as reported in expanded_devices.root.pool. Returns "" if the field
// is missing (e.g., the container has no root device override and Incus is
// using a profile default that the JSON projection doesn't include).
func extractRootPool(c map[string]interface{}) string {
	expanded, ok := c["expanded_devices"].(map[string]interface{})
	if !ok {
		return ""
	}
	root, ok := expanded["root"].(map[string]interface{})
	if !ok {
		return ""
	}
	pool, _ := root["pool"].(string)
	return pool
}

// poolDeviceName matches the synthetic device suffix of identity-mapped pool
// ports (coi-port-pool-<n>); ResolvePorts rejects user entries that would
// collide with it, so the match is unambiguous.
var poolDeviceName = regexp.MustCompile(`^pool-\d+$`)

// extractPublishedPorts renders the container's coi-port-* proxy devices from
// expanded_devices (already in the `incus list --format=json` payload — no
// extra Incus calls). Sorted by host port for stable output.
func extractPublishedPorts(c map[string]interface{}) []string {
	expanded, ok := c["expanded_devices"].(map[string]interface{})
	if !ok {
		return nil
	}
	type portDev struct {
		name          string
		listenAddr    string
		hostPort      int
		containerPort int
	}
	var devs []portDev
	for devName, raw := range expanded {
		suffix, isPort := strings.CutPrefix(devName, "coi-port-")
		if !isPort {
			continue
		}
		dev, ok := raw.(map[string]interface{})
		if !ok || dev["type"] != "proxy" {
			continue
		}
		listen, _ := dev["listen"].(string)
		connect, _ := dev["connect"].(string)
		addr, hostPort, ok1 := parseProxyTCPAddr(listen)
		_, containerPort, ok2 := parseProxyTCPAddr(connect)
		if !ok1 || !ok2 {
			continue
		}
		devs = append(devs, portDev{suffix, addr, hostPort, containerPort})
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].hostPort < devs[j].hostPort })

	out := make([]string, 0, len(devs))
	for _, d := range devs {
		if poolDeviceName.MatchString(d.name) && d.hostPort == d.containerPort {
			out = append(out, strconv.Itoa(d.hostPort)) // pool: the ONE number both sides use
			continue
		}
		host := strconv.Itoa(d.hostPort)
		if d.listenAddr != "" && d.listenAddr != "127.0.0.1" {
			host = d.listenAddr + ":" + host
		}
		out = append(out, fmt.Sprintf("%s:%s->%d", d.name, host, d.containerPort))
	}
	return out
}

// parseProxyTCPAddr splits an Incus proxy address spec ("tcp:127.0.0.1:23410",
// "tcp:[::1]:8080") into address and port.
func parseProxyTCPAddr(spec string) (addr string, port int, ok bool) {
	rest, found := strings.CutPrefix(spec, "tcp:")
	if !found {
		return "", 0, false
	}
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		return "", 0, false
	}
	p, err := strconv.Atoi(rest[i+1:])
	if err != nil {
		return "", 0, false
	}
	return strings.Trim(rest[:i], "[]"), p, true
}

// extractEth0IPv4 extracts the IPv4 address from the eth0 interface
func extractEth0IPv4(container map[string]interface{}) string {
	// Get state object
	state, ok := container["state"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Get network object - it's null for stopped containers
	network, ok := state["network"].(map[string]interface{})
	if !ok || network == nil {
		return ""
	}

	// Get eth0 interface
	eth0, ok := network["eth0"].(map[string]interface{})
	if !ok {
		return ""
	}

	// Get addresses array
	addresses, ok := eth0["addresses"].([]interface{})
	if !ok {
		return ""
	}

	// Find the first inet (IPv4) address
	for _, addr := range addresses {
		addrMap, ok := addr.(map[string]interface{})
		if !ok {
			continue
		}

		family, _ := addrMap["family"].(string)
		if family == "inet" {
			ip, _ := addrMap["address"].(string)
			return ip
		}
	}

	return ""
}

// outputJSON formats container and session data as JSON
func outputJSON(containers []ContainerInfo, sessions []SessionInfo,
	workspaces map[string]string, persistent map[string]bool,
) error {
	// Enrich container data
	enrichedContainers := make([]map[string]interface{}, 0, len(containers))
	for _, c := range containers {
		item := map[string]interface{}{
			"name":            c.Name,
			"status":          c.Status,
			"created_at":      c.CreatedAt,
			"image":           c.Image,
			"persistent":      persistent[c.Name],
			"ipv4":            c.IPv4,
			"pool":            c.Pool,
			"alias":           c.Alias,
			"published_ports": append([]string{}, c.Ports...), // non-nil: stable JSON shape ([] not null)
		}
		if ws, ok := workspaces[c.Name]; ok {
			item["workspace"] = ws
		}
		enrichedContainers = append(enrichedContainers, item)
	}

	// Build output structure
	output := map[string]interface{}{
		"active_containers": enrichedContainers,
	}

	if len(sessions) > 0 {
		output["saved_sessions"] = sessions
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

// containersHeading names the containers section after the active status
// filter: the unfiltered default stays "Active Containers:" (backward
// compatible), while `--stopped` gets "Stopped Containers:" instead of
// claiming stopped containers are active (#592). statusFilter is canonical
// lowercase (see resolveStatusFilter).
func containersHeading(statusFilter string) string {
	if statusFilter == "" {
		return "Active Containers:"
	}
	return strings.ToUpper(statusFilter[:1]) + statusFilter[1:] + " Containers:"
}

// outputText formats container and session data as human-readable text
func outputText(containers []ContainerInfo, sessions []SessionInfo,
	workspaces map[string]string, persistent map[string]bool, statusFilter string,
) error {
	// Containers section, titled after the active filter
	heading := containersHeading(statusFilter)
	fmt.Println(heading)
	fmt.Println(strings.Repeat("-", len(heading)))

	if len(containers) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, c := range containers {
			// Show container name with alias and mode indicator
			nameDisplay := c.Name
			if c.Alias != "" {
				nameDisplay = fmt.Sprintf("%s (%s)", c.Name, c.Alias)
			}
			if persistent[c.Name] {
				fmt.Printf("  %s (persistent)\n", nameDisplay)
			} else {
				fmt.Printf("  %s (ephemeral)\n", nameDisplay)
			}
			fmt.Printf("    Status: %s\n", c.Status)
			if c.IPv4 != "" {
				fmt.Printf("    IPv4: %s\n", c.IPv4)
			}
			fmt.Printf("    Created: %s\n", c.CreatedAt)
			if c.Image != "" {
				fmt.Printf("    Image: %s\n", c.Image)
			}
			if c.Pool != "" {
				fmt.Printf("    Pool: %s\n", c.Pool)
			}
			if len(c.Ports) > 0 {
				fmt.Printf("    Ports: %s\n", strings.Join(c.Ports, ", "))
			}
			// Show workspace if we have it from session metadata
			if workspace, ok := workspaces[c.Name]; ok && workspace != "" {
				fmt.Printf("    Workspace: %s\n", workspace)
			}
		}
	}

	// Saved Sessions section (only with --all)
	if sessions != nil {
		fmt.Println("\nSaved Sessions:")
		fmt.Println("---------------")

		if len(sessions) == 0 {
			fmt.Println("  (none)")
		} else {
			for _, s := range sessions {
				fmt.Printf("  %s\n", s.ID)
				fmt.Printf("    Saved: %s\n", s.SavedAt)
				if s.Workspace != "" {
					fmt.Printf("    Workspace: %s\n", s.Workspace)
				}
			}
		}
	}

	return nil
}
