package health

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mensfeld/coi/internal/cleanup"
	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/network"
	"github.com/mensfeld/coi/internal/session"
	"github.com/mensfeld/coi/internal/tool"
)

// CheckActiveContainers counts running Coi containers
func CheckActiveContainers() HealthCheck {
	prefix := session.GetContainerPrefix()
	pattern := fmt.Sprintf("^%s", prefix)

	output, err := container.IncusOutput("list", pattern, "--format=json")
	if err != nil {
		return HealthCheck{
			Name:    "active_containers",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not list containers: %v", err),
		}
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return HealthCheck{
			Name:    "active_containers",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not parse container list: %v", err),
		}
	}

	// Count running containers
	running := 0
	for _, c := range containers {
		if status, ok := c["status"].(string); ok && container.StatusIsRunning(status) {
			running++
		}
	}

	total := len(containers)
	message := fmt.Sprintf("%d running", running)
	if total > running {
		message = fmt.Sprintf("%d running, %d stopped", running, total-running)
	}
	if total == 0 {
		message = "None"
	}

	return HealthCheck{
		Name:    "active_containers",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"running": running,
			"total":   total,
		},
	}
}

// CheckSavedSessions counts saved sessions
func CheckSavedSessions(cfg *config.Config) HealthCheck {
	// Get configured tool
	toolName := cfg.Tool.Name
	if toolName == "" {
		toolName = "claude"
	}
	toolInstance, err := tool.Get(toolName)
	if err != nil {
		toolInstance = tool.GetDefault()
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return HealthCheck{
			Name:    "saved_sessions",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not determine home directory: %v", err),
		}
	}

	baseDir := filepath.Join(homeDir, ".coi")
	sessionsDir := session.GetSessionsDir(baseDir, toolInstance)

	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return HealthCheck{
				Name:    "saved_sessions",
				Status:  StatusOK,
				Message: "None",
				Details: map[string]interface{}{
					"count": 0,
				},
			}
		}
		return HealthCheck{
			Name:    "saved_sessions",
			Status:  StatusWarning,
			Message: fmt.Sprintf("Could not read sessions directory: %v", err),
		}
	}

	// Count directories (sessions)
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}

	message := fmt.Sprintf("%d session(s)", count)
	if count == 0 {
		message = "None"
	}

	return HealthCheck{
		Name:    "saved_sessions",
		Status:  StatusOK,
		Message: message,
		Details: map[string]interface{}{
			"count": count,
			"path":  sessionsDir,
		},
	}
}

// CheckFirewalldVethBloat detects dead veth interfaces still registered in
// firewalld's zones (#695). NetworkManager enrolls each container's host-side
// veth into the default zone; leaked registrations survive container deletion,
// and firewalld's FORWARD policy rules are generated as the cross product of
// zone interfaces — so the ruleset grows QUADRATICALLY with leaked veths
// (145 dead veths ≈ 101k rules on the reporting host) while coi's own tables
// stay tiny. Not a coi leak, but coi's container churn is what feeds it, so
// health is the right place to name it.
func CheckFirewalldVethBloat() HealthCheck {
	const name = "firewalld_veth_bloat"
	// The nft listing and the interface stats are not atomic: a container
	// being torn down concurrently shows its veth as transiently dead. The
	// threshold absorbs that churn so normal session turnover can't flap the
	// warning; genuine leaks accumulate well past it.
	const deadVethWarnThreshold = 3
	audit := network.AuditFirewalldVeths()
	if audit.Unreadable {
		return HealthCheck{Name: name, Status: StatusOK, Message: "firewalld nft table not readable (sudo/nft unavailable or listing timed out) — veth bloat check skipped"}
	}
	if !audit.Present {
		return HealthCheck{Name: name, Status: StatusOK, Message: "no firewalld nft table on this host"}
	}
	dead := len(audit.DeadVeths)
	details := map[string]interface{}{
		"entry_count": audit.RuleCount,
		"dead_veths":  dead,
		"live_veths":  audit.LiveVeths,
	}
	if dead < deadVethWarnThreshold {
		return HealthCheck{
			Name:    name,
			Status:  StatusOK,
			Message: fmt.Sprintf("firewalld table healthy (~%d entries, %d dead veth registrations)", audit.RuleCount, dead),
			Details: details,
		}
	}
	return HealthCheck{
		Name:   name,
		Status: StatusWarning,
		Message: fmt.Sprintf(
			"%d dead veth interfaces registered in firewalld zones (~%d entries in table inet firewalld — grows quadratically per leaked veth). "+
				"Fix now: sudo firewall-cmd --reload. Prevent: mark veths unmanaged in NetworkManager "+
				"(/etc/NetworkManager/conf.d/99-coi-unmanaged.conf: [keyfile] unmanaged-devices+=interface-name:veth*)",
			dead, audit.RuleCount),
		Details: details,
	}
}

// CheckOrphanedResources checks for orphaned system resources
func CheckOrphanedResources() HealthCheck {
	// Check for orphaned veths
	orphanedVeths := 0
	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "veth") {
				continue
			}
			masterPath := fmt.Sprintf("/sys/class/net/%s/master", name)
			if _, err := os.Stat(masterPath); os.IsNotExist(err) {
				orphanedVeths++
			}
		}
	}

	// Check for orphaned firewall rules
	orphanedRules := 0
	if network.NftAvailable() {
		// Get running container IPs and names
		containerIPs := make(map[string]bool)
		containerNames := make(map[string]bool)
		output, err := container.IncusOutput("list", "--format=json")
		if err == nil {
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
			if json.Unmarshal([]byte(output), &containers) == nil {
				for _, c := range containers {
					if container.StatusIsRunning(c.State.Status) {
						containerNames[c.Name] = true
						if eth0, ok := c.State.Network["eth0"]; ok {
							for _, addr := range eth0.Addresses {
								if addr.Family == "inet" {
									containerIPs[addr.Address] = true
								}
							}
						}
					}
				}
			}
		}

		// Check nft coi chain for orphaned IPv4 rules
		if ipHandles, err := network.ListCOIFilterRuleIPs(); err == nil {
			for ip := range ipHandles {
				if !containerIPs[ip] {
					orphanedRules++
				}
			}
		}

		// Check ip6 coi chain for orphaned IPv6 drop rules
		if names, err := network.ListCOIIP6RuleContainers(); err == nil {
			for _, name := range names {
				if !containerNames[name] {
					orphanedRules++
				}
			}
		}

		// Count orphaned monitoring LOG rules too (#696 item 6): the per-IP /
		// per-name tallies above ignore the NFT_COI/NFT_DNS/NFT_SUSPICIOUS rules
		// in ip filter FORWARD, so heavy LOG-rule bloat used to under-report.
		// Reuse the cleanup detector (which does exact-IP matching) rather than
		// DetectAll, which would re-count the veth/IPv4/IPv6 dimensions above.
		if handles, err := cleanup.DetectOrphanedNFTMonitorRules(); err == nil {
			orphanedRules += len(handles)
		}
	}

	totalOrphans := orphanedVeths + orphanedRules

	if totalOrphans == 0 {
		return HealthCheck{
			Name:    "orphaned_resources",
			Status:  StatusOK,
			Message: "No orphaned resources",
		}
	}

	message := fmt.Sprintf("%d orphaned resource(s) found", totalOrphans)
	if orphanedVeths > 0 {
		message += fmt.Sprintf(" (%d veths", orphanedVeths)
		if orphanedRules > 0 {
			message += fmt.Sprintf(", %d firewall rules)", orphanedRules)
		} else {
			message += ")"
		}
	} else if orphanedRules > 0 {
		message += fmt.Sprintf(" (%d firewall rules)", orphanedRules)
	}
	message += " - run 'coi clean --orphans' to remove"

	return HealthCheck{
		Name:    "orphaned_resources",
		Status:  StatusWarning,
		Message: message,
		Details: map[string]interface{}{
			"orphaned_veths":     orphanedVeths,
			"orphaned_nft_rules": orphanedRules,
		},
	}
}
