// Package cleanup detects and removes host resources orphaned by containers
// that were not cleaned up properly: veth interfaces, nft and ip6 rules,
// nft monitoring rules, and iptables bridge-forward rules.
package cleanup

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/network"
)

// OrphanedResources holds information about orphaned system resources
type OrphanedResources struct {
	Veths               []string // Orphaned veth interfaces (no master bridge)
	NftRules            []string // Orphaned nft rules (for non-existent container IPs)
	DropChains          []string // Orphaned netdev coi drop chains (names of containers no longer running)
	NFTMonitorRules     []string // Orphaned nft monitoring rules (NFT_COI/NFT_DNS/NFT_SUSPICIOUS)
	IptablesBridgeRules []string // Orphaned iptables coi-bridge-forward rules (no coi containers running)
}

// netClassDir is where DetectOrphanedVeths reads host interfaces. Package var
// so tests can point it at a fixture.
var netClassDir = "/sys/class/net"

// DetectOrphanedVeths finds host veths that coi recorded for its containers
// and that have no master bridge. These are typically left over from
// improperly cleaned up containers. Unrecorded veths are never reported: a
// master-less veth of another tool (CNI, a manual netns pair) looks the same.
func DetectOrphanedVeths() ([]string, error) {
	recorded, err := network.RecordedHostVeths()
	if err != nil {
		// Records are best-effort; don't let them stop the other orphan scans.
		log.Printf("Warning: Could not read recorded veths: %v", err)
		return nil, nil
	}

	var candidates []string
	for _, name := range recorded {
		if !strings.HasPrefix(name, "veth") {
			continue
		}
		if _, err := os.Stat(filepath.Join(netClassDir, name)); err != nil {
			continue
		}
		// No master symlink = no bridge
		if _, err := os.Stat(filepath.Join(netClassDir, name, "master")); os.IsNotExist(err) {
			candidates = append(candidates, name)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	// A routed NIC's host veth has no master either; never take one from any
	// instance, coi's or not.
	inUse, err := instanceHostVeths()
	if err != nil {
		return nil, fmt.Errorf("failed to list instance NICs: %w", err)
	}

	var orphaned []string
	for _, name := range candidates {
		if !inUse[name] {
			orphaned = append(orphaned, name)
		}
	}
	return orphaned, nil
}

// DetectOrphanedNftRules finds container IPs in the ip coi forward chain
// that don't belong to any running container.
func DetectOrphanedNftRules() ([]string, error) {
	ipHandles, err := network.ListCOIFilterRuleIPs()
	if err != nil || len(ipHandles) == 0 {
		return nil, err
	}

	containerIPs, err := getRunningContainerIPs()
	if err != nil {
		return nil, fmt.Errorf("failed to get container IPs: %w", err)
	}

	running := make(map[string]bool, len(containerIPs))
	for _, ip := range containerIPs {
		running[ip] = true
	}

	var orphaned []string
	for ip := range ipHandles {
		if !running[ip] {
			orphaned = append(orphaned, ip)
		}
	}
	return orphaned, nil
}

// DetectOrphanedDropChains finds container names with a drop chain in the
// netdev coi table whose containers are no longer running (e.g. force-killed
// without teardown).
func DetectOrphanedDropChains() ([]string, error) {
	names, err := network.ListDropChainContainers()
	if err != nil || len(names) == 0 {
		return nil, err
	}

	runningNames, err := getRunningContainerNames()
	if err != nil {
		return nil, fmt.Errorf("failed to get container names: %w", err)
	}
	running := make(map[string]bool, len(runningNames))
	for _, n := range runningNames {
		running[n] = true
	}

	var orphaned []string
	for _, n := range names {
		if !running[n] {
			orphaned = append(orphaned, n)
		}
	}
	return orphaned, nil
}

// CleanupOrphanedDropChains removes the IPv6 and boot drop chains of each given
// container name. Returns the number cleaned.
func CleanupOrphanedDropChains(names []string, logger func(string)) (int, error) {
	if logger == nil {
		logger = func(msg string) { log.Println(msg) }
	}
	cleaned := 0
	for _, name := range names {
		logger(fmt.Sprintf("Removing orphaned drop chains for container: %s", name))
		if err := network.RemoveIPv6BlockForContainer(name); err != nil {
			logger(fmt.Sprintf("  Warning: Failed to remove IPv6 drop for %s: %v", name, err))
			continue
		}
		if err := network.RemoveBootBlockRule(name); err != nil {
			logger(fmt.Sprintf("  Warning: Failed to remove boot block for %s: %v", name, err))
			continue
		}
		cleaned++
	}
	return cleaned, nil
}

// instanceHostVeths returns the host-side interface names of every instance
// NIC Incus reports, in every project.
func instanceHostVeths() (map[string]bool, error) {
	output, err := container.IncusOutputAllProjects("list", "--format=json")
	if err != nil {
		return nil, err
	}

	var instances []struct {
		State struct {
			Network map[string]struct {
				HostName string `json:"host_name"`
			} `json:"network"`
		} `json:"state"`
	}
	if err := parseJSON(output, &instances); err != nil {
		return nil, err
	}

	veths := make(map[string]bool)
	for _, inst := range instances {
		for _, nic := range inst.State.Network {
			if nic.HostName != "" {
				veths[nic.HostName] = true
			}
		}
	}
	return veths, nil
}

// getRunningContainerNames returns the names of all running containers.
func getRunningContainerNames() ([]string, error) {
	return container.ListRunningContainerNames("")
}

// getRunningContainerIPs returns IPs of all running containers
func getRunningContainerIPs() ([]string, error) {
	output, err := container.IncusOutput("list", "--format=json")
	if err != nil {
		return nil, err
	}

	var containers []struct {
		Name  string `json:"name"`
		State struct {
			Status  string `json:"status"`
			Network map[string]struct {
				Addresses []struct {
					Family  string `json:"family"`
					Address string `json:"address"`
				} `json:"addresses"`
			} `json:"network"`
		} `json:"state"`
	}

	if err := parseJSON(output, &containers); err != nil {
		return nil, err
	}

	var ips []string
	for _, c := range containers {
		if !container.StatusIsRunning(c.State.Status) {
			continue
		}
		if eth0, ok := c.State.Network["eth0"]; ok {
			for _, addr := range eth0.Addresses {
				if addr.Family == "inet" {
					ips = append(ips, addr.Address)
				}
			}
		}
	}

	return ips, nil
}

// parseJSON is a helper to parse JSON output
func parseJSON(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}

// CleanupOrphanedVeths removes orphaned veth interfaces
// Returns the number of veths cleaned up and any error
func CleanupOrphanedVeths(veths []string, logger func(string)) (int, error) {
	if !network.SudoEnabled() {
		return 0, nil // use_sudo=false: cannot `sudo ip link delete`
	}
	if logger == nil {
		logger = func(msg string) { log.Println(msg) }
	}

	cleaned := 0
	for _, veth := range veths {
		logger(fmt.Sprintf("Removing orphaned veth: %s", veth))
		cmd := exec.Command("sudo", "-n", "ip", "link", "delete", veth)
		if err := cmd.Run(); err != nil {
			logger(fmt.Sprintf("  Warning: Failed to remove %s: %v", veth, err))
			continue
		}
		_ = network.ForgetHostVeth(veth)
		cleaned++
	}

	return cleaned, nil
}

// CleanupOrphanedNftRules removes all ip coi forward rules for the given container IPs.
// The rules slice contains container IP addresses (as returned by DetectOrphanedNftRules).
func CleanupOrphanedNftRules(rules []string, logger func(string)) (int, error) {
	if logger == nil {
		logger = func(msg string) { log.Println(msg) }
	}

	cleaned := 0
	for _, ip := range rules {
		logger(fmt.Sprintf("Removing orphaned nft rules for container IP: %s", ip))
		if err := network.DeleteCOIFilterRulesForIP(ip); err != nil {
			logger(fmt.Sprintf("  Warning: Failed to remove rules for %s: %v", ip, err))
			continue
		}
		cleaned++
	}
	return cleaned, nil
}

// monitorRuleIP returns the IP embedded in a FORWARD-chain rule's own
// NFT_COI[<ip>] / NFT_DNS[<ip>] / NFT_SUSPICIOUS[<ip>] log-prefix token, or ""
// if the line carries no such token. The closing ']' bounds the IP, so the
// match is exact (10.47.6.2 is never confused with 10.47.6.20). Pure/text-only
// so it is unit-testable without nft.
func monitorRuleIP(line string) string {
	for _, prefix := range []string{"NFT_COI[", "NFT_DNS[", "NFT_SUSPICIOUS["} {
		start := strings.Index(line, prefix)
		if start == -1 {
			continue
		}
		start += len(prefix)
		end := strings.IndexByte(line[start:], ']')
		if end == -1 {
			continue
		}
		return line[start : start+end]
	}
	return ""
}

// classifyMonitorLine decides whether a single FORWARD-chain rule line is an
// orphaned monitoring LOG rule. It returns the rule's nft handle and whether it
// is orphaned. A line is orphaned iff it carries a parseable NFT_*[<ip>] token
// whose IP is NOT in the running-container set — compared by EXACT equality on
// the extracted IP, not by substring against the whole line (#696 item 3b).
// Lines without a monitoring token or without a handle are skipped
// (orphaned=false).
//
// Bounded limitation: once the bridge DHCP pool legitimately recycles a dead
// container's IP to a new running container, a stale rule embedding that same
// IP is indistinguishable from a live one by IP alone, so it is (correctly, but
// conservatively) treated as live. Fully solving that requires keying the LOG
// rules by container name instead of IP — future work.
func classifyMonitorLine(line string, running map[string]bool) (handle string, orphaned bool) {
	ip := monitorRuleIP(line)
	if ip == "" {
		return "", false
	}
	handleIdx := strings.Index(line, "# handle ")
	if handleIdx == -1 {
		return "", false
	}
	handle = line[handleIdx+len("# handle "):]
	if spaceIdx := strings.Index(handle, " "); spaceIdx != -1 {
		handle = handle[:spaceIdx]
	}
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return "", false
	}
	return handle, !running[ip]
}

// DetectOrphanedNFTMonitorRules finds nft monitoring rules for IPs that don't belong to any running container
// These are rules with prefixes: NFT_COI[ip], NFT_DNS[ip], NFT_SUSPICIOUS[ip]
func DetectOrphanedNFTMonitorRules() ([]string, error) {
	if !network.SudoEnabled() {
		return nil, nil // use_sudo=false: cannot enumerate nft rules
	}
	// List all rules in the FORWARD chain with handles
	// Note: -a must come before the command (nft -a list chain...)
	cmd := exec.Command("sudo", "-n", "nft", "-a", "list", "chain", "ip", "filter", "FORWARD")
	output, err := cmd.Output()
	if err != nil {
		// Chain might not exist, which is fine
		return nil, nil
	}

	// Get all running container IPs as an exact-match set.
	containerIPs, err := getRunningContainerIPs()
	if err != nil {
		return nil, fmt.Errorf("failed to get container IPs: %w", err)
	}
	running := make(map[string]bool, len(containerIPs))
	for _, ip := range containerIPs {
		running[ip] = true
	}

	var orphaned []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if handle, isOrphaned := classifyMonitorLine(line, running); isOrphaned {
			orphaned = append(orphaned, handle)
		}
	}

	return orphaned, nil
}

// CleanupOrphanedNFTMonitorRules removes orphaned nft monitoring rules by handle
func CleanupOrphanedNFTMonitorRules(handles []string, logger func(string)) (int, error) {
	if !network.SudoEnabled() {
		return 0, nil // use_sudo=false: cannot `sudo nft delete`
	}
	if logger == nil {
		logger = func(msg string) { log.Println(msg) }
	}

	cleaned := 0
	for _, handle := range handles {
		logger(fmt.Sprintf("Removing orphaned nft monitoring rule handle: %s", handle))

		cmd := exec.Command("sudo", "-n", "nft", "delete", "rule", "ip", "filter", "FORWARD", "handle", handle)
		if err := cmd.Run(); err != nil {
			logger(fmt.Sprintf("  Warning: Failed to remove rule handle %s: %v", handle, err))
			continue
		}
		cleaned++
	}

	return cleaned, nil
}

// DetectOrphanedIptablesBridgeRules finds coi-bridge-forward iptables rules
// that are left over when no coi containers are running
func DetectOrphanedIptablesBridgeRules() ([]string, error) {
	if !network.SudoEnabled() {
		return nil, nil // use_sudo=false: cannot `sudo iptables -S`
	}
	if !network.IptablesAvailable() {
		return nil, nil
	}

	// Check if any coi containers are running; if yes, rules are not orphaned
	containerIPs, err := getRunningContainerIPs()
	if err != nil {
		return nil, fmt.Errorf("failed to get container IPs: %w", err)
	}
	if len(containerIPs) > 0 {
		return nil, nil
	}

	// List FORWARD chain rules and look for our comment tag
	cmd := exec.Command("sudo", "-n", "iptables", "-S", "FORWARD")
	output, err := cmd.Output()
	if err != nil {
		return nil, nil // iptables might not be accessible
	}

	var orphaned []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "coi-bridge-forward") {
			orphaned = append(orphaned, line)
		}
	}

	return orphaned, nil
}

// CleanupOrphanedIptablesBridgeRules removes orphaned coi-bridge-forward iptables rules
func CleanupOrphanedIptablesBridgeRules(rules []string, logger func(string)) (int, error) {
	if logger == nil {
		logger = func(msg string) { log.Println(msg) }
	}

	if len(rules) == 0 {
		return 0, nil
	}

	bridgeName, err := network.GetIncusBridgeName()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not get bridge name for iptables cleanup: %v", err))
		return 0, err
	}

	logger(fmt.Sprintf("Removing orphaned iptables bridge rules for %s", bridgeName))
	if err := network.RemoveIptablesBridgeRules(bridgeName); err != nil {
		logger(fmt.Sprintf("  Warning: Failed to remove iptables bridge rules: %v", err))
		return 0, err
	}

	return len(rules), nil
}

// DetectAll detects all orphaned resources
func DetectAll() (*OrphanedResources, error) {
	result := &OrphanedResources{}

	veths, err := DetectOrphanedVeths()
	if err != nil {
		return nil, fmt.Errorf("failed to detect orphaned veths: %w", err)
	}
	result.Veths = veths

	rules, err := DetectOrphanedNftRules()
	if err != nil {
		// Non-fatal - firewall might not be available
		log.Printf("Warning: Could not check nft rules: %v", err)
	}
	result.NftRules = rules

	dropChains, err := DetectOrphanedDropChains()
	if err != nil {
		// Non-fatal - nft might not be available
		log.Printf("Warning: Could not check drop chains: %v", err)
	}
	result.DropChains = dropChains

	nftRules, err := DetectOrphanedNFTMonitorRules()
	if err != nil {
		// Non-fatal - nft might not be available
		log.Printf("Warning: Could not check nft monitoring rules: %v", err)
	}
	result.NFTMonitorRules = nftRules

	iptablesBridgeRules, err := DetectOrphanedIptablesBridgeRules()
	if err != nil {
		// Non-fatal - iptables might not be available
		log.Printf("Warning: Could not check iptables bridge rules: %v", err)
	}
	result.IptablesBridgeRules = iptablesBridgeRules

	return result, nil
}
