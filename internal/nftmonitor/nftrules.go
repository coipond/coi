package nftmonitor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RuleManager manages nftables LOG rules for container monitoring
type RuleManager struct {
	config      *Config
	ruleHandles []string // Store rule handles for cleanup
}

// NewRuleManager creates a new nftables rule manager
func NewRuleManager(cfg *Config) *RuleManager {
	return &RuleManager{
		config:      cfg,
		ruleHandles: []string{},
	}
}

// monitorRulesPresentForIP reports whether any NFT_COI/NFT_DNS/NFT_SUSPICIOUS
// LOG rule for exactly this IP already exists in the given `nft list chain`
// output text. It matches the same bracketed tokens RemoveRules deletes on
// (e.g. "NFT_COI[10.0.0.5]"), so "10.0.0.5" never matches a rule for
// "10.0.0.50". Pure and text-only so it is unit-testable without nft.
func monitorRulesPresentForIP(chainText, ip string) bool {
	if ip == "" {
		return false
	}
	for _, prefix := range []string{"NFT_COI", "NFT_DNS", "NFT_SUSPICIOUS"} {
		if strings.Contains(chainText, fmt.Sprintf("%s[%s]", prefix, ip)) {
			return true
		}
	}
	return false
}

// AddRules adds nftables LOG rules for the container
func (rm *RuleManager) AddRules() error {
	// First, ensure the ip filter table and FORWARD chain exist
	if err := rm.ensureChainExists(); err != nil {
		return fmt.Errorf("failed to ensure chain exists: %w", err)
	}

	// Idempotency guard (#696 item 3a): the three rules below are inserted and
	// removed as a per-IP set, so if a set for this exact IP already exists in
	// the FORWARD chain, re-running would just stack 3-4 duplicates. Skip in
	// that case. On a list failure we fall through and insert, preserving the
	// previous behaviour and never silently disabling monitoring.
	if out, err := rm.runNFTCommand("list", "chain", "ip", "filter", "FORWARD"); err == nil {
		if monitorRulesPresentForIP(string(out), rm.config.ContainerIP) {
			return nil
		}
	}

	// Rule 1: High priority - Always log suspicious traffic (no rate limit)
	// Metadata endpoint, RFC1918, suspicious ports
	if err := rm.addSuspiciousTrafficRule(); err != nil {
		return fmt.Errorf("failed to add suspicious traffic rule: %w", err)
	}

	// Rule 2: Medium priority - Always log DNS queries (if enabled)
	if rm.config.LogDNSQueries {
		if err := rm.addDNSRule(); err != nil {
			return fmt.Errorf("failed to add DNS rule: %w", err)
		}
	}

	// Rule 3: Low priority - Rate-limited logging for all other traffic
	if err := rm.addGeneralTrafficRule(); err != nil {
		return fmt.Errorf("failed to add general traffic rule: %w", err)
	}

	return nil
}

// RemoveRules removes all nftables LOG rules added by this manager
func (rm *RuleManager) RemoveRules() error {
	// List all rules with handles in FORWARD chain
	// Note: -a must come before the command (nft -a list chain...)
	output, err := rm.runNFTCommand("-a", "list", "chain", "ip", "filter", "FORWARD")
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}

	// Find and delete all rules with our log prefix
	lines := strings.Split(string(output), "\n")
	containerIP := rm.config.ContainerIP

	rulesRemoved := 0
	var errs []error
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("NFT_COI[%s]", containerIP)) ||
			strings.Contains(line, fmt.Sprintf("NFT_DNS[%s]", containerIP)) ||
			strings.Contains(line, fmt.Sprintf("NFT_SUSPICIOUS[%s]", containerIP)) {
			// Extract handle number from line like: "... # handle 123"
			if handle := extractHandle(line); handle != "" {
				// Keep going on a failed delete: another remover (coi container
				// delete / kill cleanup) often runs concurrently, and stopping at
				// the first handle it already took would strand the rest.
				if err := rm.deleteRuleByHandle(handle); err != nil {
					if !ruleAlreadyGone(err) {
						errs = append(errs, fmt.Errorf("failed to delete rule handle %s: %w", handle, err))
					}
					continue
				}
				rulesRemoved++
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if rulesRemoved == 0 {
		// This might indicate a problem - we added rules but found none to remove
		// Could happen if container IP changed or rules were already cleaned
		return fmt.Errorf("no NFT rules found to remove for IP %s (this may indicate rules were not created or IP changed)", containerIP)
	}

	return nil
}

// ensureChainExists creates the ip filter table and FORWARD chain if they don't exist
// This is needed because nftables doesn't create iptables-legacy compatible tables by default
func (rm *RuleManager) ensureChainExists() error {
	// Check if the chain exists
	_, err := rm.runNFTCommand("list", "chain", "ip", "filter", "FORWARD")
	if err == nil {
		// Chain already exists
		return nil
	}

	// Create the table if it doesn't exist (ignore error if already exists)
	_, _ = rm.runNFTCommand("add", "table", "ip", "filter")

	// Create the FORWARD chain as a filter chain
	// type filter, hook forward, priority 0 (same as iptables FORWARD)
	_, err = rm.runNFTCommand("add", "chain", "ip", "filter", "FORWARD",
		"{", "type", "filter", "hook", "forward", "priority", "0", ";", "}")
	if err != nil {
		return fmt.Errorf("failed to create FORWARD chain: %w", err)
	}

	return nil
}

// addSuspiciousTrafficRule adds high-priority rule for suspicious destinations
func (rm *RuleManager) addSuspiciousTrafficRule() error {
	// Metadata endpoint + RFC1918 addresses + suspicious ports
	// Note: log prefix must be quoted because [] are special nft syntax characters
	// Use "insert" instead of "add" to place rules at the BEGINNING of the chain
	// This ensures our LOG rules run BEFORE any ACCEPT rules from firewalld
	ruleArgs := []string{
		"insert", "rule", "ip", "filter", "FORWARD",
		"ip", "saddr", rm.config.ContainerIP,
		"ip", "daddr", "{", "169.254.169.254", ",", "10.0.0.0/8", ",", "172.16.0.0/12", ",", "192.168.0.0/16", "}",
		"log", "prefix", fmt.Sprintf(`"NFT_SUSPICIOUS[%s]: "`, rm.config.ContainerIP),
		"level", "info",
		"counter",
	}

	_, err := rm.runNFTCommand(ruleArgs...)
	if err != nil {
		return err
	}

	// Insert rule for suspicious ports
	suspiciousPorts := []string{"4444", "5555", "1234", "31337", "12345", "6666-6697"}
	portsArgs := []string{
		"insert", "rule", "ip", "filter", "FORWARD",
		"ip", "saddr", rm.config.ContainerIP,
		"tcp", "dport", "{",
	}
	portsArgs = append(portsArgs, strings.Join(suspiciousPorts, ","))
	portsArgs = append(portsArgs, "}", "log", "prefix", fmt.Sprintf(`"NFT_SUSPICIOUS[%s]: "`, rm.config.ContainerIP),
		"level", "info", "counter")

	_, err = rm.runNFTCommand(portsArgs...)
	return err
}

// addDNSRule adds medium-priority rule for DNS queries
func (rm *RuleManager) addDNSRule() error {
	ruleArgs := []string{
		"insert", "rule", "ip", "filter", "FORWARD",
		"ip", "saddr", rm.config.ContainerIP,
		"udp", "dport", "53",
		"log", "prefix", fmt.Sprintf(`"NFT_DNS[%s]: "`, rm.config.ContainerIP),
		"level", "info",
		"counter",
	}

	_, err := rm.runNFTCommand(ruleArgs...)
	return err
}

// addGeneralTrafficRule adds low-priority rate-limited rule for all traffic
func (rm *RuleManager) addGeneralTrafficRule() error {
	rateLimit := rm.config.RateLimitPerSecond
	if rateLimit <= 0 {
		rateLimit = 100 // Default
	}

	ruleArgs := []string{
		"insert", "rule", "ip", "filter", "FORWARD",
		"ip", "saddr", rm.config.ContainerIP,
		"limit", "rate", fmt.Sprintf("%d/second", rateLimit),
		"log", "prefix", fmt.Sprintf(`"NFT_COI[%s]: "`, rm.config.ContainerIP),
		"level", "info",
		"counter",
	}

	_, err := rm.runNFTCommand(ruleArgs...)
	return err
}

// deleteRuleByHandle deletes a rule by its handle number
func (rm *RuleManager) deleteRuleByHandle(handle string) error {
	_, err := rm.runNFTCommand("delete", "rule", "ip", "filter", "FORWARD", "handle", handle)
	return err
}

// NFTCommandTimeout is the maximum time to wait for nft commands
const NFTCommandTimeout = 10 * time.Second

// runNFTCommand executes an nft command with proper sudo/lima handling
// Uses a timeout to prevent hanging if nft command blocks
func (rm *RuleManager) runNFTCommand(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), NFTCommandTimeout)
	defer cancel()

	var cmd *exec.Cmd

	if rm.config.LimaHost != "" {
		// Run inside Lima VM
		cmdArgs := append([]string{"shell", rm.config.LimaHost, "sudo", "-n", "nft"}, args...)
		cmd = exec.CommandContext(ctx, "limactl", cmdArgs...)
	} else {
		// Native Linux - use sudo -n (non-interactive, fail if password required)
		cmdArgs := append([]string{"-n", "nft"}, args...)
		cmd = exec.CommandContext(ctx, "sudo", cmdArgs...)
	}

	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("nft command timed out after %v", NFTCommandTimeout)
	}
	if err != nil {
		return output, fmt.Errorf("nft command failed: %w (output: %s)", err, string(output))
	}

	return output, nil
}

// ruleAlreadyGone reports whether an nft delete failed only because the rule
// no longer exists (removed concurrently by another cleanup path).
func ruleAlreadyGone(err error) bool {
	return err != nil && strings.Contains(err.Error(), "No such file or directory")
}

// extractHandle extracts the handle number from a nft rule line
// Example: "... # handle 123" -> "123"
func extractHandle(line string) string {
	parts := strings.Split(line, "# handle ")
	if len(parts) < 2 {
		return ""
	}
	handleStr := strings.TrimSpace(parts[1])
	// Handle might have additional text after it
	if idx := strings.Index(handleStr, " "); idx != -1 {
		handleStr = handleStr[:idx]
	}
	// Validate it's a number
	if _, err := strconv.Atoi(handleStr); err != nil {
		return ""
	}
	return handleStr
}
