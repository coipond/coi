package monitor

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// CollectProcessStats collects running processes by walking the host /proc
// filtered to the container's PID namespace. Because the read happens outside
// the container, an attacker inside cannot hide processes by manipulating their
// own /proc, replacing ps, or pausing incus exec.
func CollectProcessStats(ctx context.Context, containerName string) (ProcessStats, error) {
	processes, err := collectProcessesViaHostProc(ctx, containerName)
	if err != nil {
		return ProcessStats{Available: false}, fmt.Errorf("process monitoring unavailable: %w", err)
	}

	for i := range processes {
		processes[i].EnvAccess = checkEnvAccess(processes[i].Command)
	}
	return ProcessStats{
		Available:  true,
		TotalCount: len(processes),
		Processes:  processes,
	}, nil
}

// collectProcessesViaHostProc walks the host /proc directory and returns all
// processes that belong to the container's cgroup subtree. Using cgroup
// membership avoids the ptrace permission required to read /proc/<pid>/ns/pid
// symlinks (which restricts namespace-inode comparison to root or
// CAP_SYS_PTRACE). /proc/<pid>/cgroup is world-readable on Linux. This also
// naturally covers processes that create nested PID namespaces inside the
// container via unshare -p.
func collectProcessesViaHostProc(ctx context.Context, containerName string) ([]Process, error) {
	rawPath, err := GetCgroupPath(ctx, containerName)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("could not resolve container cgroup path: %w", err)
	}

	// GetCgroupPath may return the init process's sub-scope (e.g. /init.scope)
	// when falling back to incus info. Strip it so the prefix match covers all
	// processes in the container, not just init.scope — same strip
	// CollectResourceStats uses so both views agree on the container root.
	cgroupPath := stripSystemdScopeSuffix(rawPath)

	// /proc/<pid>/cgroup lines use paths relative to /sys/fs/cgroup.
	// e.g. "0::/incus.monitor/coi-abc123-1"
	const cgroupMount = "/sys/fs/cgroup"
	relCgroup := strings.TrimPrefix(cgroupPath, cgroupMount)
	if relCgroup == cgroupPath {
		return nil, fmt.Errorf("unexpected cgroup path format (no %s prefix): %s", cgroupMount, cgroupPath)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("could not read /proc: %w", err)
	}

	var processes []Process
	for _, entry := range entries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil || !processBelongsToContainerCgroup(string(cgroupData), relCgroup) {
			continue
		}

		proc, err := readProcessFromProc(pid)
		if err != nil {
			continue
		}
		processes = append(processes, proc)
	}

	// A running container must have at least its init process visible. Zero
	// results indicate a cgroup mismatch or permission problem rather than a
	// genuinely empty container.
	if len(processes) == 0 {
		return nil, fmt.Errorf("no processes found in container cgroup %s — cgroup path mismatch or hidepid", relCgroup)
	}

	return processes, nil
}

// processBelongsToContainerCgroup reports whether the /proc/<pid>/cgroup
// content places the process inside the container's cgroup subtree.
// Cgroup v2 format: "0::<relative-path>"
func processBelongsToContainerCgroup(cgroupContent, containerRelCgroup string) bool {
	for _, line := range strings.Split(cgroupContent, "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		procCgroup := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		if procCgroup == containerRelCgroup || strings.HasPrefix(procCgroup, containerRelCgroup+"/") {
			return true
		}
	}
	return false
}

// readProcessFromProc reads /proc/<pid>/status and /proc/<pid>/cmdline to build
// a Process. The PID here is the host-side PID.
func readProcessFromProc(pid int) (Process, error) {
	statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return Process{}, err
	}

	name, ppid, uid := parseStatusFields(string(statusData))

	command := name
	if cmdlineData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil && len(cmdlineData) > 0 {
		command = parseCmdline(cmdlineData)
	}

	return Process{
		PID:  pid,
		PPID: ppid,
		// User is the real (host-side) UID as a decimal string. Unlike the
		// old incus exec ps aux path, this is numeric rather than a username.
		User:    strconv.Itoa(uid),
		Command: command,
	}, nil
}

// parseStatusFields extracts Name, PPid, and real Uid from /proc/<pid>/status
// content. Kept separate so it can be unit-tested without a live /proc.
func parseStatusFields(status string) (name string, ppid, uid int) {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Name:":
			name = fields[1]
		case "PPid:":
			ppid, _ = strconv.Atoi(fields[1])
		case "Uid:":
			uid, _ = strconv.Atoi(fields[1]) // real UID is the first field
		}
	}
	return
}

// parseCmdline converts null-delimited /proc/<pid>/cmdline bytes to a
// space-joined command string. Kept separate so it can be unit-tested.
func parseCmdline(data []byte) string {
	trimmed := strings.TrimRight(string(data), "\x00")
	if trimmed == "" {
		return ""
	}
	return strings.Join(strings.Split(trimmed, "\x00"), " ")
}

// checkEnvAccess checks if a command is likely accessing environment variables
func checkEnvAccess(command string) bool {
	// Check for common environment-scanning commands
	envCommands := []string{
		"env",
		"printenv",
		"set",
		"export",
	}

	cmdLower := strings.ToLower(command)

	// Check if command is exactly one of the env commands
	for _, envCmd := range envCommands {
		if strings.HasPrefix(cmdLower, envCmd+" ") || cmdLower == envCmd {
			return true
		}
	}

	// Check for grep/awk/sed parsing environment variables with secret-related keywords
	secretKeywords := []string{"api", "key", "password", "secret", "token", "credential", "auth"}
	if strings.Contains(cmdLower, "grep") || strings.Contains(cmdLower, "awk") || strings.Contains(cmdLower, "sed") {
		for _, keyword := range secretKeywords {
			if strings.Contains(cmdLower, keyword) {
				return true
			}
		}
	}

	// Check for /proc/*/environ access via any tool
	if strings.Contains(cmdLower, "/proc/") && strings.Contains(cmdLower, "environ") {
		return true
	}

	// Check for language-specific environment access patterns
	langEnvPatterns := []string{
		// Python: os.environ, os.getenv
		"os.environ",
		"os.getenv",
		// Node.js: process.env
		"process.env",
		// Ruby: ENV[
		"env[",
		// awk ENVIRON array
		"environ[",
	}
	for _, pattern := range langEnvPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	// Check for binary tools reading /proc/*/environ
	procEnvTools := []string{
		"strings /proc",
		"xxd /proc",
		"hexdump /proc",
		"xargs",
	}
	for _, tool := range procEnvTools {
		if strings.Contains(cmdLower, tool) && strings.Contains(cmdLower, "environ") {
			return true
		}
	}

	// Check for xargs specifically reading null-delimited environ files
	if strings.Contains(cmdLower, "xargs") && strings.Contains(cmdLower, "/proc/") {
		return true
	}

	return false
}

// DetectReverseShells checks processes for reverse shell indicators
func DetectReverseShells(processes []Process) []ProcessThreat {
	var threats []ProcessThreat

	reverseShellPatterns := []struct {
		pattern    string
		indicators []string
	}{
		// Netcat reverse shells
		{"nc -e", []string{"netcat with exec"}},
		{"nc.traditional -e", []string{"netcat with exec"}},
		{"ncat -e", []string{"ncat with exec"}},
		{"nc.openbsd -e", []string{"netcat with exec"}},

		// Bash/sh reverse shells
		{"bash -i", []string{"interactive bash"}},
		{"sh -i", []string{"interactive shell"}},
		{"/dev/tcp/", []string{"bash tcp redirect"}},
		{"/dev/udp/", []string{"bash udp redirect"}},

		// Python reverse shells
		{"python -c", []string{"python one-liner"}},
		{"python3 -c", []string{"python one-liner"}},
		{"socket.socket", []string{"python socket"}},

		// Perl reverse shells
		{"perl -e", []string{"perl one-liner"}},
		{"perl -MIO", []string{"perl IO module"}},

		// PHP reverse shells
		{"php -r", []string{"php one-liner"}},
		{"fsockopen", []string{"php socket"}},

		// Ruby reverse shells
		{"ruby -rsocket", []string{"ruby socket"}},
		{"ruby -e", []string{"ruby one-liner"}},

		// Socat reverse shells
		{"socat", []string{"socat"}},
		{"EXEC:", []string{"socat exec"}},

		// PowerShell reverse shells (if Wine/mono present)
		{"powershell", []string{"powershell"}},
		{"System.Net.Sockets", []string{"dotnet sockets"}},
	}

	for _, proc := range processes {
		cmdLower := strings.ToLower(proc.Command)

		for _, pattern := range reverseShellPatterns {
			if strings.Contains(cmdLower, strings.ToLower(pattern.pattern)) {
				// Additional check: the interpreter one-liner patterns
				// (python -c, perl -e, ruby -e, php -r, ...) are only a threat
				// when the command actually carries a network indicator. Require
				// a real one — a socket/tcp/udp/connect keyword, an IP, or a
				// host:port endpoint — NOT a bare ':' (issue #842): agent Bash
				// tools wrap commands in a shell-snapshot line and quote code
				// that almost always contains ':' (PATH entries like
				// /usr/bin:/bin, dict literals like {"k": v}, URLs, log text),
				// so a bare-':' check turned every agent-run `python -c` /
				// `perl -e` / `ruby -e` / `php -r` into a kill-on-sight false
				// positive.
				if isNetworkRelated(cmdLower) || pattern.pattern == "bash -i" || pattern.pattern == "sh -i" {
					threats = append(threats, ProcessThreat{
						PID:        proc.PID,
						Command:    proc.Command,
						User:       proc.User,
						Pattern:    pattern.pattern,
						Indicators: pattern.indicators,
					})
					break
				}
			}
		}
	}

	return threats
}

// ipv4Re matches a dotted-quad IPv4 address anywhere in a command, including
// when embedded in punctuation such as a Python tuple `("10.0.0.1",4444)`.
// The word boundaries keep it from matching version strings inside a longer
// dotted run (e.g. it won't fire on the "1.2.3" of "1.2.3.4.5"-style noise).
var ipv4Re = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// hostPortRe matches an explicit network endpoint — an IPv4 address or a
// dotted hostname (needs a TLD-like final label) followed by ':' and a numeric
// port. Requiring a dot in the host is what keeps it from matching dict
// literals ({"k":1}), "hello: world", or PATH fragments (/usr/bin:/bin), which
// is the whole point of #842's fix.
var hostPortRe = regexp.MustCompile(`(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+):\d{1,5}\b`)

// isNetworkRelated reports whether a reverse-shell candidate command actually
// carries a network indicator. It deliberately does NOT treat a bare ':' as an
// indicator — see the caller and issue #842.
func isNetworkRelated(cmdLower string) bool {
	return strings.Contains(cmdLower, "sock") || // socket, fsockopen, tcpsocket, ...
		strings.Contains(cmdLower, "tcp") ||
		strings.Contains(cmdLower, "udp") ||
		strings.Contains(cmdLower, "connect") ||
		containsIPPattern(cmdLower) ||
		hostPortRe.MatchString(cmdLower)
}

// containsIPPattern checks if command contains an IPv4 address pattern.
func containsIPPattern(cmd string) bool {
	return ipv4Re.MatchString(cmd)
}

// DetectProcessCountSpike checks whether the total number of processes in the
// container exceeds the configured threshold. A sudden spike is the primary
// indicator of a fork bomb (:(){:|:&};:) or runaway process spawner.
// Returns nil when threshold is 0 (disabled) or not exceeded.
func DetectProcessCountSpike(stats ProcessStats, threshold int) *ProcessCountThreat {
	if threshold <= 0 || !stats.Available {
		return nil
	}
	if stats.TotalCount > threshold {
		return &ProcessCountThreat{
			Count:     stats.TotalCount,
			Threshold: threshold,
		}
	}
	return nil
}

// DetectProcessSpawnRate checks whether processes spawned faster than threshold
// since the last poll. Returns nil when threshold is 0 (disabled) or when
// previous is negative (first poll — no baseline yet).
func DetectProcessSpawnRate(current, previous, threshold int) *ProcessCountThreat {
	if threshold <= 0 || previous < 0 {
		return nil
	}
	delta := current - previous
	if delta > threshold {
		return &ProcessCountThreat{
			Count:     current,
			Threshold: threshold,
			Delta:     delta,
		}
	}
	return nil
}

// DetectEnvScanning checks processes for environment variable scanning
func DetectEnvScanning(processes []Process) []ProcessThreat {
	var threats []ProcessThreat

	for _, proc := range processes {
		if proc.EnvAccess {
			threats = append(threats, ProcessThreat{
				PID:        proc.PID,
				Command:    proc.Command,
				User:       proc.User,
				Pattern:    "environment scanning",
				Indicators: []string{"accessing environment variables"},
			})
		}
	}

	return threats
}
