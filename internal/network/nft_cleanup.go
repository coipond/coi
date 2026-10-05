package network

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/coipond/coi/internal/timing"
)

// NFTCommandTimeout is the maximum time to wait for nft commands
const NFTCommandTimeout = 10 * time.Second

// CleanupNFTMonitoringRules removes any NFT monitoring rules for a container IP.
// This is used during container kill to clean up rules that were added by the
// nftmonitor package. Returns nil if no rules found (not an error during cleanup).
func CleanupNFTMonitoringRules(containerIP string) error {
	if containerIP == "" {
		return nil
	}

	// List all rules with handles in FORWARD chain
	output, err := runNFTCommand("-a", "list", "chain", "ip", "filter", "FORWARD")
	if err != nil {
		// If the chain doesn't exist, there are no rules to clean up
		if strings.Contains(err.Error(), "No such file or directory") ||
			strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("failed to list rules: %w", err)
	}

	// Find and delete all rules with our log prefixes for this IP
	lines := strings.Split(string(output), "\n")
	rulesRemoved := 0

	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("NFT_COI[%s]", containerIP)) ||
			strings.Contains(line, fmt.Sprintf("NFT_DNS[%s]", containerIP)) ||
			strings.Contains(line, fmt.Sprintf("NFT_SUSPICIOUS[%s]", containerIP)) {
			// Extract handle number from line like: "... # handle 123"
			if handle := extractNFTHandle(line); handle != "" {
				if err := deleteNFTRuleByHandle(handle); err != nil {
					return fmt.Errorf("failed to delete rule handle %s: %w", handle, err)
				}
				rulesRemoved++
			}
		}
	}

	// Not finding any rules is OK during cleanup - the container may not have
	// had monitoring enabled or rules may have already been cleaned
	return nil
}

// runNFTCommand executes an nft command with proper sudo handling
func runNFTCommand(args ...string) ([]byte, error) {
	if !SudoEnabled() {
		return nil, fmt.Errorf("nft command skipped: sudo disabled (use_sudo=false)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), NFTCommandTimeout)
	defer cancel()

	// Use sudo -n (non-interactive, fail if password required)
	cmdArgs := append([]string{"-n", "nft"}, args...)
	cmd := exec.CommandContext(ctx, "sudo", cmdArgs...)

	// Every nft rule change funnels through here, so timing it here accounts
	// for all firewall time under COI_TIMING_DEBUG (no-op when unset).
	stop := timing.Start(timing.CatHost, "nft "+strings.Join(args, " "))
	output, err := cmd.CombinedOutput()
	stop()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("nft command timed out after %v", NFTCommandTimeout)
	}
	if err != nil {
		return output, fmt.Errorf("nft command failed: %w (output: %s)", err, string(output))
	}

	return output, nil
}

// deleteNFTRuleByHandle deletes a rule by its handle number
func deleteNFTRuleByHandle(handle string) error {
	_, err := runNFTCommand("delete", "rule", "ip", "filter", "FORWARD", "handle", handle)
	return err
}

// extractNFTHandle extracts the handle number from a nft rule line
// Example: "... # handle 123" -> "123"
func extractNFTHandle(line string) string {
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

// runNFTScript applies cmds (each one nft command's argv, exactly as it would
// be passed to runNFTCommand) as ONE `nft -f -` script. The nft CLI joins its
// argv with spaces and parses the result, so a script line built the same way
// is the identical command — but the whole script is a single kernel
// transaction: every command applies, or none does. That makes a rule set
// all-or-nothing (no half-applied policy on failure) and costs one sudo+nft
// exec instead of one per rule.
func runNFTScript(cmds [][]string) error {
	if len(cmds) == 0 {
		return nil
	}
	if !SudoEnabled() {
		return fmt.Errorf("nft command skipped: sudo disabled (use_sudo=false)")
	}
	script := nftScript(cmds)
	ctx, cancel := context.WithTimeout(context.Background(), NFTCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)

	stop := timing.Start(timing.CatHost, fmt.Sprintf("nft -f - (%d commands)", len(cmds)))
	output, err := cmd.CombinedOutput()
	stop()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("nft script timed out after %v", NFTCommandTimeout)
	}
	if err != nil {
		return fmt.Errorf("nft script failed: %w (output: %s)", err, string(output))
	}
	return nil
}

// nftScript renders cmds as nft script lines (see runNFTScript).
func nftScript(cmds [][]string) string {
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
