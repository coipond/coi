package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/cleanup"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/network"
	"github.com/mensfeld/coi/internal/session"
	"github.com/spf13/cobra"
)

var (
	cleanAll      bool
	cleanForce    bool
	cleanSessions bool
	cleanOrphans  bool
	cleanPools    bool
	cleanDryRun   bool
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Cleanup containers, sessions, and orphaned resources",
	Long: `Cleanup stopped containers, old session data, and orphaned system resources.

By default, cleans only stopped containers. Use flags to control what gets cleaned.

Orphaned resources include:
- Orphaned veth interfaces (network pairs with no master bridge)
- Orphaned nft rules (ip coi forward chain rules for container IPs that no longer exist)
- Orphaned iptables bridge rules (coi-bridge-forward rules with no containers running)

The --pools flag detects Coi containers in storage pools that are not
referenced by any profile loaded in the current directory and offers to
remove them. The pool itself is never deleted. Note that Coi can only see
profiles in ~/.coi/ and the current ./.coi/ — pools may still be in use by
other projects on this machine.

Examples:
  coi clean                    # Clean stopped containers
  coi clean --sessions         # Clean saved session data
  coi clean --orphans          # Clean orphaned veths and nft rules
  coi clean --pools            # Clean Coi containers in unreferenced pools
  coi clean --all              # Clean everything
  coi clean --all --force      # Clean without confirmation
  coi clean --orphans --dry-run # Show what orphans would be cleaned
`,
	RunE: app.cleanCommand,
}

func init() {
	cleanCmd.Flags().BoolVarP(&cleanAll, "all", "a", false, "Clean all containers, sessions, and orphaned resources")
	cleanCmd.Flags().BoolVarP(&cleanForce, "force", "f", false, "Skip confirmation prompts")
	cleanCmd.Flags().BoolVar(&cleanSessions, "sessions", false, "Clean saved session data")
	cleanCmd.Flags().BoolVar(&cleanOrphans, "orphans", false, "Clean orphaned veths and nft rules")
	cleanCmd.Flags().BoolVar(&cleanPools, "pools", false, "Clean Coi containers in unreferenced storage pools")
	cleanCmd.Flags().BoolVar(&cleanDryRun, "dry-run", false, "Show what would be cleaned without making changes")
}

func (a *App) cleanCommand(cmd *cobra.Command, args []string) error {
	// Get configured tool to determine tool-specific sessions directory
	toolInstance, err := getConfiguredTool(a.cfg)
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

	cleaned := 0

	// Clean stopped containers
	if cleanAll || (!cleanSessions) {
		count, cancelled, err := cleanStoppedContainers()
		if err != nil {
			return err
		}
		if cancelled {
			return nil
		}
		cleaned += count
	}

	// Clean saved sessions
	if cleanAll || cleanSessions {
		count, cancelled, err := cleanSavedSessions(sessionsDir)
		if err != nil {
			return err
		}
		if cancelled {
			return nil
		}
		cleaned += count
	}

	// Clean orphaned resources (veths and nft rules)
	if cleanAll || cleanOrphans {
		count, cancelled := cleanOrphanedResources()
		if cancelled {
			return nil
		}
		cleaned += count
	}

	// Clean Coi containers in unreferenced storage pools
	if cleanAll || cleanPools {
		count, cancelled, err := a.cleanUnreferencedPools()
		if err != nil {
			return err
		}
		if cancelled {
			return nil
		}
		cleaned += count
	}

	if cleanDryRun {
		fmt.Println("\n[Dry run] No changes made.")
		return nil
	}

	// Clean stale immutable locks (after dry-run check to avoid side effects)
	{
		logger := func(msg string) { fmt.Println(msg) }
		immutableCleaned := session.CleanStaleImmutableLocks(logger)
		if immutableCleaned > 0 {
			fmt.Printf("Cleaned %d stale immutable lock(s)\n", immutableCleaned)
			cleaned += immutableCleaned
		}
	}

	if cleaned > 0 {
		fmt.Printf("\n✓ Cleaned %d item(s)\n", cleaned)
	} else {
		fmt.Println("\nNothing to clean.")
	}

	return nil
}

// cleanStoppedContainers finds and removes stopped containers.
// Returns (count cleaned, was cancelled, error).
func cleanStoppedContainers() (int, bool, error) {
	fmt.Println("Checking for stopped Coi containers...")

	containers, err := listActiveContainers()
	if err != nil {
		return 0, false, fmt.Errorf("failed to list containers: %w", err)
	}

	stoppedContainers := []string{}
	for _, c := range containers {
		if container.StatusIsStopped(c.Status) {
			stoppedContainers = append(stoppedContainers, c.Name)
		}
	}

	if len(stoppedContainers) == 0 {
		fmt.Println("  (no stopped containers found)")
		return 0, false, nil
	}

	fmt.Printf("Found %d stopped container(s):\n", len(stoppedContainers))
	for _, name := range stoppedContainers {
		fmt.Printf("  - %s\n", name)
	}

	if cleanDryRun {
		return 0, false, nil
	}

	if !cleanForce {
		if !confirmYN("\nDelete these containers? [y/N]: ") {
			fmt.Println("Cancelled.")
			return 0, true, nil
		}
	}

	cleaned := 0
	for _, name := range stoppedContainers {
		fmt.Printf("Deleting container %s...\n", name)
		// Reclaim host-side firewall artefacts before deleting (#696 item 4):
		// the default reap path used to delete with zero nft cleanup. These
		// containers are already Stopped, so they hold no DHCP lease and their
		// IP is unresolvable here — GetContainerIPFast would only burn ~2s of
		// retries and still return "". So pass "" and reclaim the NAME-keyed
		// coi6-<name> IPv6 block; the IP-keyed coi-<ip> bundle + monitoring LOG
		// rules are left to the orphan sweep (coi clean --orphans), which
		// matches on the rules themselves rather than a live IP.
		cleanupContainerFirewall(name, "")
		mgr := container.NewManager(name)
		if err := mgr.Delete(true); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to delete %s: %v\n", name, err)
		} else {
			cleaned++
		}
	}

	return cleaned, false, nil
}

// cleanSavedSessions finds and removes saved session data.
// Returns (count cleaned, was cancelled, error).
func cleanSavedSessions(sessionsDir string) (int, bool, error) {
	fmt.Println("\nChecking for saved session data...")

	entries, err := os.ReadDir(sessionsDir)
	if err != nil && !os.IsNotExist(err) {
		return 0, false, fmt.Errorf("failed to read sessions directory: %w", err)
	}

	sessionDirs := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			sessionDirs = append(sessionDirs, entry.Name())
		}
	}

	if len(sessionDirs) == 0 {
		fmt.Println("  (no saved sessions found)")
		return 0, false, nil
	}

	fmt.Printf("Found %d session(s):\n", len(sessionDirs))
	for _, name := range sessionDirs {
		fmt.Printf("  - %s\n", name)
	}

	if cleanDryRun {
		return 0, false, nil
	}

	if !cleanForce {
		if !confirmYN("\nDelete all session data? [y/N]: ") {
			fmt.Println("Cancelled.")
			return 0, true, nil
		}
	}

	cleaned := 0
	for _, name := range sessionDirs {
		sessionPath := filepath.Join(sessionsDir, name)
		fmt.Printf("Deleting session %s...\n", name)
		if err := os.RemoveAll(sessionPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to delete %s: %v\n", name, err)
		} else {
			cleaned++
		}
	}

	return cleaned, false, nil
}

// cleanOrphanedResources finds and removes orphaned veths and nft rules.
// Returns (count cleaned, was cancelled).
func cleanOrphanedResources() (int, bool) {
	fmt.Println("\nScanning for orphaned resources...")

	orphans, err := cleanup.DetectAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to detect orphans: %v\n", err)
		return 0, false
	}

	// IPv6Rules included (#696): omitting them made coi clean --orphans report
	// "no orphaned resources found" when IPv6 blocks were the only leak class.
	totalOrphans := len(orphans.Veths) + len(orphans.NftRules) + len(orphans.NFTMonitorRules) + len(orphans.IptablesBridgeRules) + len(orphans.IPv6Rules)

	if totalOrphans == 0 {
		fmt.Println("  (no orphaned resources found)")
		return 0, false
	}

	printOrphanedResources(orphans)

	if cleanDryRun {
		return 0, false
	}

	if !cleanForce {
		if !confirmYN("\nClean up orphaned resources? [y/N]: ") {
			fmt.Println("Cancelled.")
			return 0, true
		}
	}

	return doCleanOrphanedResources(orphans), false
}

// printOrphanedResources prints the list of orphaned resources found.
func printOrphanedResources(orphans *cleanup.OrphanedResources) {
	totalOrphans := len(orphans.Veths) + len(orphans.NftRules) + len(orphans.IPv6Rules) +
		len(orphans.NFTMonitorRules) + len(orphans.IptablesBridgeRules)
	fmt.Printf("Found %d orphaned resource(s):\n", totalOrphans)

	if len(orphans.Veths) > 0 {
		fmt.Printf("  Orphaned veth interfaces (%d):\n", len(orphans.Veths))
		for _, veth := range orphans.Veths {
			fmt.Printf("    - %s\n", veth)
		}
	}

	if len(orphans.NftRules) > 0 {
		fmt.Printf("  Orphaned nft rules (%d):\n", len(orphans.NftRules))
		for _, rule := range orphans.NftRules {
			fmt.Printf("    - %s\n", rule)
		}
	}

	if len(orphans.IPv6Rules) > 0 {
		fmt.Printf("  Orphaned ip6 nft rules (%d):\n", len(orphans.IPv6Rules))
		for _, name := range orphans.IPv6Rules {
			fmt.Printf("    - %s\n", name)
		}
	}

	if len(orphans.NFTMonitorRules) > 0 {
		fmt.Printf("  Orphaned nft monitoring rules (%d):\n", len(orphans.NFTMonitorRules))
		shown := 0
		for _, handle := range orphans.NFTMonitorRules {
			if shown < 10 {
				fmt.Printf("    - handle %s\n", handle)
				shown++
			}
		}
		if len(orphans.NFTMonitorRules) > 10 {
			fmt.Printf("    ... and %d more\n", len(orphans.NFTMonitorRules)-10)
		}
	}

	if len(orphans.IptablesBridgeRules) > 0 {
		fmt.Printf("  Orphaned iptables bridge rules (%d):\n", len(orphans.IptablesBridgeRules))
		for _, rule := range orphans.IptablesBridgeRules {
			fmt.Printf("    - %s\n", rule)
		}
	}
}

// doCleanOrphanedResources performs the actual cleanup of orphaned resources.
func doCleanOrphanedResources(orphans *cleanup.OrphanedResources) int {
	cleaned := 0
	logger := func(msg string) {
		fmt.Println(msg)
	}

	if len(orphans.Veths) > 0 {
		vethsCleaned, _ := cleanup.CleanupOrphanedVeths(orphans.Veths, logger)
		cleaned += vethsCleaned
	}

	if len(orphans.NftRules) > 0 {
		rulesCleaned, _ := cleanup.CleanupOrphanedNftRules(orphans.NftRules, logger)
		cleaned += rulesCleaned
	}

	if len(orphans.IPv6Rules) > 0 {
		ipv6Cleaned, _ := cleanup.CleanupOrphanedIPv6Rules(orphans.IPv6Rules, logger)
		cleaned += ipv6Cleaned
	}

	if len(orphans.NFTMonitorRules) > 0 {
		nftRulesCleaned, _ := cleanup.CleanupOrphanedNFTMonitorRules(orphans.NFTMonitorRules, logger)
		cleaned += nftRulesCleaned
	}

	if len(orphans.IptablesBridgeRules) > 0 {
		iptablesCleaned, _ := cleanup.CleanupOrphanedIptablesBridgeRules(orphans.IptablesBridgeRules, logger)
		cleaned += iptablesCleaned
	}

	return cleaned
}

// cleanUnreferencedPools detects Coi containers in storage pools that are not
// referenced by any profile loaded in the current context, and offers to remove
// the containers. The pool itself is never deleted.
//
// "Coi containers" are identified by name prefix (the configured container
// prefix, default "coi-") AND verified via the container's expanded_devices
// root pool.
//
// Returns (count cleaned, was cancelled, error).
func (a *App) cleanUnreferencedPools() (int, bool, error) {
	fmt.Println("\nScanning storage pools for unreferenced Coi containers...")

	// Build referenced pool set from the loaded config + profiles.
	referenced := a.referencedPoolSet()

	// List all pools known to Incus.
	pools, err := container.ListStoragePools()
	if err != nil {
		return 0, false, fmt.Errorf("failed to list storage pools: %w", err)
	}

	// Resolve the Incus default pool name so an empty referenced entry
	// (meaning "use Incus default") matches the right pool.
	defaultPool := incusDefaultPool()

	// List all containers across all pools — one Incus call.
	allContainers, err := listAllContainersWithPool()
	if err != nil {
		return 0, false, fmt.Errorf("failed to list containers: %w", err)
	}

	prefix := session.GetContainerPrefix()

	type poolPlan struct {
		pool       string
		containers []string
	}
	var plans []poolPlan

	for _, p := range pools {
		// Skip pools the user's loaded config references.
		if referenced[p.Name] {
			continue
		}
		if p.Name == defaultPool && referenced[""] {
			// "use Incus default" referenced — skip the actual default pool.
			continue
		}

		var coiContainers []string
		for _, c := range allContainers {
			if c.Pool != p.Name {
				continue
			}
			if !strings.HasPrefix(c.Name, prefix) {
				continue
			}
			coiContainers = append(coiContainers, c.Name)
		}

		if len(coiContainers) == 0 {
			continue
		}
		plans = append(plans, poolPlan{pool: p.Name, containers: coiContainers})
	}

	if len(plans) == 0 {
		fmt.Println("  (no unreferenced pools contain Coi containers)")
		return 0, false, nil
	}

	// Print the loud cross-project warning once, then per-pool details.
	fmt.Println()
	fmt.Println("WARNING: these pools may still be referenced by profiles in other")
	fmt.Println("projects on this machine that Coi cannot see right now. Cleaning")
	fmt.Println("them will affect any project whose profile points here.")
	fmt.Println()

	for _, plan := range plans {
		fmt.Printf("Pool %q is not referenced by any profile loaded in this directory.\n", plan.pool)
		fmt.Printf("  Coi containers in %q (%d):\n", plan.pool, len(plan.containers))
		for _, name := range plan.containers {
			fmt.Printf("    - %s\n", name)
		}
		fmt.Println()
	}

	if cleanDryRun {
		return 0, false, nil
	}

	if !cleanForce {
		if !confirmYN("Delete these containers? [y/N]: ") {
			fmt.Println("Cancelled.")
			return 0, true, nil
		}
	}

	cleaned := 0
	for _, plan := range plans {
		for _, name := range plan.containers {
			fmt.Printf("Deleting container %s (pool %s)...\n", name, plan.pool)
			// Resolve the IP BEFORE stopping — a stopped container may not report
			// one via GetContainerIPFast — then reclaim its firewall artefacts
			// before delete (#696 item 4). If the IP is unresolvable the
			// name-keyed coi6-<name> block is still removed and the orphan sweep
			// remains the backstop for the IP-keyed rules.
			var ip string
			if network.NftAvailable() {
				ip, _ = network.GetContainerIPFast(name)
			}
			mgr := container.NewManager(name)
			// Best-effort stop; ignore errors (container may already be stopped).
			_ = mgr.Stop(true)
			cleanupContainerFirewall(name, ip)
			if err := mgr.Delete(true); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to delete %s: %v\n", name, err)
				continue
			}
			cleaned++
		}
	}

	return cleaned, false, nil
}

// referencedPoolSet returns the set of storage pool names referenced by the
// loaded global [container] section and any loaded profile's [container]
// section. Profiles that leave storage_pool empty inherit the global value
// at ApplyProfile time and are already covered by the global entry —
// including "" for them would make clean --pools treat the Incus default
// pool as referenced even when the effective pool is a non-empty global
// cfg.Container.StoragePool. The empty string ("") is only present when
// the global entry itself is empty (meaning "use Incus default pool").
func (a *App) referencedPoolSet() map[string]bool {
	set := map[string]bool{}
	if a.cfg == nil {
		return set
	}
	set[a.cfg.Container.StoragePool] = true
	for _, profile := range a.cfg.Profiles {
		if profile.Container.StoragePool != "" {
			set[profile.Container.StoragePool] = true
		}
	}
	return set
}

// incusDefaultPool returns the name of the storage pool used by the Incus
// "default" profile's root device, or "" if it cannot be determined.
func incusDefaultPool() string {
	out, err := container.IncusOutput("profile", "show", "default")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pool:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "pool:"))
		}
	}
	return ""
}

// containerWithPool is a minimal projection of an Incus container used for
// pool-aware cleanup planning.
type containerWithPool struct {
	Name string
	Pool string
}

// listAllContainersWithPool lists every container known to Incus along with
// the storage pool of its root device. Uses a single `incus list --format=json`
// call.
func listAllContainersWithPool() ([]containerWithPool, error) {
	out, err := container.IncusOutput("list", "--format=json")
	if err != nil {
		return nil, err
	}
	var raw []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}
	result := make([]containerWithPool, 0, len(raw))
	for _, c := range raw {
		name, _ := c["name"].(string)
		if name == "" {
			continue
		}
		result = append(result, containerWithPool{
			Name: name,
			Pool: extractRootPool(c),
		})
	}
	return result, nil
}
