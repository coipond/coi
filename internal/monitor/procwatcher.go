package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1

	procEventExec = 0x00000002
	procEventUID  = 0x00000004
)

// execPattern defines how to detect a suspicious process exec.
// arg0 (if non-empty) restricts the match to processes whose argv[0] basename
// starts with the given prefix (case-insensitive), preventing false positives
// from shell scripts whose argument strings happen to contain suspicious words
// (e.g. "bash -c '... python -c socket.socket ...'").
// All keywords must also appear in the full cmdline (case-insensitive).
type execPattern struct {
	Name     string
	Arg0     string
	Keywords []string
}

// defaultExecPatterns is the compiled-in fallback set used when no GTFOBins
// clone is present at ~/.coi/gtfobins/. loadExecPatterns() merges GTFOBins-
// derived patterns on top, with compiled-in entries filling any gaps.
var defaultExecPatterns = []execPattern{
	// Netcat reverse shells — requires argv[0] to be nc/ncat so that
	// shell scripts that mention nc in arguments don't trigger.
	{Name: "nc-exec", Arg0: "nc", Keywords: []string{"-e"}},
	{Name: "ncat-exec", Arg0: "ncat", Keywords: []string{"-e"}},
	// Bash TCP/UDP redirect — /dev/tcp appearing in bash's own argument
	// string is the canonical reverse-shell one-liner indicator.
	{Name: "bash-tcp-redirect", Arg0: "bash", Keywords: []string{"/dev/tcp/"}},
	{Name: "bash-udp-redirect", Arg0: "bash", Keywords: []string{"/dev/udp/"}},
	// Python reverse shells — python3 must be checked before python (substring).
	// arg0 scoping prevents "bash -c 'python3 -c socket.socket'" from matching.
	{Name: "python3-socket", Arg0: "python3", Keywords: []string{"socket.socket"}},
	{Name: "python-socket", Arg0: "python", Keywords: []string{"socket.socket"}},
	// Perl reverse shells
	{Name: "perl-socket", Arg0: "perl", Keywords: []string{"-mio"}},
	{Name: "perl-socket-connect", Arg0: "perl", Keywords: []string{"sockaddr_in"}},
	// Socat reverse shells
	{Name: "socat-exec", Arg0: "socat", Keywords: []string{"exec:"}},
	{Name: "socat-system", Arg0: "socat", Keywords: []string{"system:"}},
	// PHP reverse shell via fsockopen (GTFOBins)
	{Name: "php-fsockopen", Arg0: "php", Keywords: []string{"fsockopen"}},
	// Ruby reverse shell via TCPSocket (GTFOBins)
	{Name: "ruby-socket", Arg0: "ruby", Keywords: []string{"-rsocket"}},
	// Node.js reverse shell: child_process + net.connect (GTFOBins)
	{Name: "node-reverse-shell", Arg0: "node", Keywords: []string{"child_process", "net"}},
	// Lua reverse shell via lua-socket (GTFOBins)
	{Name: "lua-socket", Arg0: "lua", Keywords: []string{"require(\"socket\")", ":connect("}},
	// gawk reverse shell via /inet/tcp built-in (GTFOBins)
	{Name: "gawk-inet", Arg0: "gawk", Keywords: []string{"/inet/tcp/"}},
	// zsh reverse shell via zsh/net/tcp module (GTFOBins)
	{Name: "zsh-net-tcp", Arg0: "zsh", Keywords: []string{"ztcp"}},
	// busybox nc reverse shell (GTFOBins)
	{Name: "busybox-nc-exec", Arg0: "busybox", Keywords: []string{"nc", "-e"}},
	// Crypto miners — presence of the binary name is sufficient.
	{Name: "xmrig", Arg0: "xmrig", Keywords: []string{}},
}

// loadExecPatterns loads exec patterns from the GTFOBins clone at cloneDir
// (if present) and merges them with the compiled-in defaults.
// GTFOBins-derived patterns take priority (matched by Name); compiled-in
// entries not covered by the clone are appended as fallback. The compiled-in
// defaults are returned as-is when the clone directory is absent, unreadable,
// or contains no parseable reverse-shell entries.
func loadExecPatterns(cloneDir string) []execPattern {
	external := loadExecPatternsFromGTFOBins(cloneDir)
	if len(external) == 0 {
		return defaultExecPatterns
	}

	// Build name set from GTFOBins-derived patterns.
	seen := make(map[string]bool, len(external))
	for _, p := range external {
		seen[p.Name] = true
	}
	// Append compiled-in defaults not covered by GTFOBins derivation.
	merged := external
	for _, p := range defaultExecPatterns {
		if !seen[p.Name] {
			merged = append(merged, p)
		}
	}
	return merged
}

// ProcEventWatcher monitors container process exec events via the kernel's
// NETLINK_CONNECTOR/PROC_EVENTS interface. It subscribes to PROC_EVENT_EXEC
// and PROC_EVENT_UID notifications at the host level, filters them to the
// target container's cgroup, and emits ThreatEvents for suspicious activity
// (reverse shell patterns, privilege escalation to root).
//
// Because events arrive via a host-side netlink socket, an attacker inside the
// container cannot suppress or forge them.
type ProcEventWatcher struct {
	containerName string
	onThreat      func(ThreatEvent)
	onError       func(error)
	gtfobinsDir   string         // local GTFOBins clone directory
	sigmaDir      string         // local Sigma clone directory
	patterns      []execPattern  // loaded once at Run() start
	sigmaPatterns []sigmaPattern // loaded once at Run() start
}

// NewProcEventWatcher creates a ProcEventWatcher for the named container.
// gtfobinsDir and sigmaDir are the local clone directories for the threat
// detection databases; pass empty strings to use the built-in defaults.
func NewProcEventWatcher(containerName string, onThreat func(ThreatEvent), onError func(error), gtfobinsDir, sigmaDir string) *ProcEventWatcher {
	return &ProcEventWatcher{
		containerName: containerName,
		onThreat:      onThreat,
		onError:       onError,
		gtfobinsDir:   gtfobinsDir,
		sigmaDir:      sigmaDir,
	}
}

// Run listens for process events until ctx is cancelled. Setup errors (cgroup
// resolution failures, NETLINK_CONNECTOR unavailability) are surfaced via
// onError and cause Run to return early.
func (pw *ProcEventWatcher) Run(ctx context.Context) {
	pw.patterns = loadExecPatterns(pw.gtfobinsDir)
	pw.sigmaPatterns = loadSigmaPatterns(pw.sigmaDir)

	cgroupPath, err := GetCgroupPath(ctx, pw.containerName)
	if err != nil {
		if ctx.Err() == nil && pw.onError != nil {
			pw.onError(fmt.Errorf("procwatcher: could not resolve cgroup: %w", err))
		}
		return
	}

	const cgroupMount = "/sys/fs/cgroup"
	relCgroup := strings.TrimPrefix(cgroupPath, cgroupMount)
	if relCgroup == cgroupPath {
		if pw.onError != nil {
			pw.onError(fmt.Errorf("procwatcher: unexpected cgroup path format: %s", cgroupPath))
		}
		return
	}
	// Strip the trailing init.scope or init.service sub-cgroup so the prefix
	// matches all container processes, not only those under the init slice.
	// Guard against producing an empty relCgroup (would match every process).
	if idx := strings.LastIndex(relCgroup, "/"); idx > 0 {
		last := relCgroup[idx+1:]
		if strings.HasSuffix(last, ".scope") || strings.HasSuffix(last, ".service") {
			relCgroup = relCgroup[:idx]
		}
	}

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		if pw.onError != nil {
			pw.onError(fmt.Errorf("procwatcher: netlink socket: %w", err))
		}
		return
	}
	defer unix.Close(sock)

	bindAddr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}
	if err := unix.Bind(sock, bindAddr); err != nil {
		if pw.onError != nil {
			pw.onError(fmt.Errorf("procwatcher: bind: %w", err))
		}
		return
	}

	if err := procSubscribe(sock); err != nil {
		if pw.onError != nil {
			pw.onError(fmt.Errorf("procwatcher: subscribe: %w", err))
		}
		return
	}

	go func() {
		<-ctx.Done()
		unix.Close(sock)
	}()

	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(sock, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return // socket closed (ctx cancelled) or unrecoverable error
		}
		pw.processMessages(buf[:n], relCgroup)
	}
}

// procSubscribe sends the PROC_CN_MCAST_LISTEN message to enable proc events.
//
// Message layout (40 bytes total):
//
//	nlmsghdr (16) + cn_msg (20) + uint32 mcast-op (4)
func procSubscribe(sock int) error {
	const dataLen = 4 // sizeof(PROC_CN_MCAST_LISTEN)
	const msgLen = 16 + 20 + dataLen

	var buf [msgLen]byte

	// nlmsghdr at offset 0
	binary.LittleEndian.PutUint32(buf[0:], msgLen)
	binary.LittleEndian.PutUint16(buf[4:], unix.NLMSG_DONE)
	// flags, seq, pid left as zero

	// cn_msg at offset 16
	binary.LittleEndian.PutUint32(buf[16:], cnIdxProc)
	binary.LittleEndian.PutUint32(buf[20:], cnValProc)
	// seq, ack left as zero
	binary.LittleEndian.PutUint16(buf[32:], dataLen)
	// flags left as zero

	// PROC_CN_MCAST_LISTEN at offset 36
	binary.LittleEndian.PutUint32(buf[36:], procCnMcastListen)

	return unix.Sendto(sock, buf[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// processMessages parses one or more netlink messages from buf and dispatches
// matching proc events to the appropriate handler.
func (pw *ProcEventWatcher) processMessages(buf []byte, relCgroup string) {
	const nlHdrSize = 16 // sizeof(nlmsghdr)
	const cnMsgSize = 20 // sizeof(cn_msg)
	const evHdrSize = 16 // proc_event: what(4) + cpu(4) + timestamp(8)

	for len(buf) >= nlHdrSize {
		msgLen := int(binary.LittleEndian.Uint32(buf[0:]))
		if msgLen < nlHdrSize || msgLen > len(buf) {
			break
		}
		data := buf[nlHdrSize:msgLen]
		// Advance by NLMSG_ALIGN(msgLen) — round up to 4-byte boundary.
		aligned := (msgLen + 3) &^ 3
		if aligned >= len(buf) {
			buf = buf[len(buf):]
		} else {
			buf = buf[aligned:]
		}

		if len(data) < cnMsgSize+evHdrSize {
			continue
		}
		// cn_msg.len is at offset 16 within the cn_msg block.
		cnLen := int(binary.LittleEndian.Uint16(data[16:]))
		eventData := data[cnMsgSize:]
		if len(eventData) < cnLen || cnLen < evHdrSize {
			continue
		}
		eventData = eventData[:cnLen]
		payload := eventData[evHdrSize:] // after proc_event header (what+cpu+timestamp)

		what := binary.LittleEndian.Uint32(eventData[0:])
		switch what {
		case procEventExec:
			if len(payload) < 8 {
				continue
			}
			pid := int(binary.LittleEndian.Uint32(payload[0:]))
			pw.handleExec(pid, relCgroup)

		case procEventUID:
			if len(payload) < 16 {
				continue
			}
			pid := int(binary.LittleEndian.Uint32(payload[0:]))
			euid := binary.LittleEndian.Uint32(payload[12:])
			if euid == 0 {
				pw.handleUIDToRoot(pid, relCgroup)
			}
		}
	}
}

// handleExec checks whether the exec'd process belongs to the container and
// whether its cmdline matches a suspicious exec pattern or Sigma rule.
func (pw *ProcEventWatcher) handleExec(pid int, relCgroup string) {
	if !procInContainerCgroup(pid, relCgroup) {
		return
	}
	cmd := procReadCmdline(pid)
	if cmd == "" {
		return
	}

	// GTFOBins / compiled-in pattern matching.
	if pattern := matchSuspiciousExec(cmd, pw.patterns); pattern != "" {
		ev := ThreatEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Level:     ThreatLevelHigh,
			Category:  "proc_event",
			Title:     "Suspicious process execution detected",
			Description: fmt.Sprintf("Process (PID %d) matched suspicious exec pattern '%s': %s",
				pid, pattern, truncateToRunes(cmd, 200)),
			Evidence: Evidence{
				ProcEvent: &ProcEventThreat{
					PID:     pid,
					Command: truncateToRunes(cmd, 300),
					Pattern: pattern,
				},
			},
			Action: "pending",
		}
		if pw.onThreat != nil {
			pw.onThreat(ev)
		}
	}

	// Sigma rule matching — only when rules have been loaded.
	if len(pw.sigmaPatterns) > 0 {
		ppid := procReadPPID(pid)
		image := procReadExe(pid)
		parentImage := procReadExe(ppid)
		parentCmdline := procReadCmdline(ppid)
		for _, sp := range pw.sigmaPatterns {
			if matchSigmaPattern(image, cmd, parentImage, parentCmdline, sp) {
				level := ThreatLevelHigh
				if sp.Level == "critical" {
					level = ThreatLevelCritical
				}
				ev := ThreatEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Level:     level,
					Category:  "proc_event",
					Title:     fmt.Sprintf("Sigma rule matched: %s", sp.Title),
					Description: fmt.Sprintf("Process (PID %d) matched Sigma rule '%s': %s",
						pid, sp.Title, truncateToRunes(cmd, 200)),
					Evidence: Evidence{
						ProcEvent: &ProcEventThreat{
							PID:     pid,
							Command: truncateToRunes(cmd, 300),
							Pattern: sp.Title,
						},
					},
					Action: "pending",
				}
				if pw.onThreat != nil {
					pw.onThreat(ev)
				}
				break // emit at most one Sigma threat per exec event
			}
		}
	}
}

// handleUIDToRoot emits a threat when a container process elevates its
// effective UID to 0 (root).
func (pw *ProcEventWatcher) handleUIDToRoot(pid int, relCgroup string) {
	if !procInContainerCgroup(pid, relCgroup) {
		return
	}
	cmd := procReadCmdline(pid)
	ev := ThreatEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Level:     ThreatLevelHigh,
		Category:  "proc_event",
		Title:     "Process privilege escalation to root detected",
		Description: fmt.Sprintf("Process (PID %d) changed effective UID to root: %s",
			pid, truncateToRunes(cmd, 200)),
		Evidence: Evidence{
			ProcEvent: &ProcEventThreat{
				PID:     pid,
				Command: truncateToRunes(cmd, 300),
				Pattern: "uid-to-root",
			},
		},
		Action: "pending",
	}
	if pw.onThreat != nil {
		pw.onThreat(ev)
	}
}

// procInContainerCgroup returns true if /proc/<pid>/cgroup shows membership in
// the container's cgroup subtree (relCgroup is relative to /sys/fs/cgroup).
// It delegates to processBelongsToContainerCgroup for boundary-safe matching,
// preventing false positives when container names share a common prefix
// (e.g. "coi-1" must not match "coi-11").
func procInContainerCgroup(pid int, relCgroup string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	return processBelongsToContainerCgroup(string(data), relCgroup)
}

// procReadCmdline reads /proc/<pid>/cmdline, replacing NUL delimiters with
// spaces, and returns the result. Returns "" if the file is unreadable (process
// may have already exited).
func procReadCmdline(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	return strings.TrimRight(strings.ReplaceAll(string(data), "\x00", " "), " ")
}

// procReadExe resolves the /proc/<pid>/exe symlink to the binary's full path.
// Returns "" if the process has already exited or the link is unreadable.
func procReadExe(pid int) string {
	if pid <= 0 {
		return ""
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

// procReadPPID reads the parent PID from /proc/<pid>/status.
// Returns 0 on any error (process exited, permission denied, etc.).
func procReadPPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ppid, _ := strconv.Atoi(fields[1])
				return ppid
			}
		}
	}
	return 0
}

// execKeywordRefine narrows keywords that also occur in benign commands; it
// applies to compiled-in and GTFOBins-derived patterns alike, so
// `bash -c 'grep -rn /dev/tcp/ docs'`, a loopback port probe, or
// `perl -MIO::File` no longer match. See reverseShellRefine.
var execKeywordRefine = map[string]func(lower string) bool{
	"/dev/tcp/": devNetEndpointNonLoopback,
	"/dev/udp/": devNetEndpointNonLoopback,
	"-mio":      perlLoadsIOSocket,
}

// matchSuspiciousExec returns the name of the first matching execPattern for
// the given command, or "" if none match. patterns must be pre-loaded by the
// caller (e.g. via loadExecPatterns) to avoid a file read on every invocation.
func matchSuspiciousExec(cmd string, patterns []execPattern) string {
	if cmd == "" {
		return ""
	}
	// Extract argv[0] (first space-delimited token) then its basename.
	arg0 := cmd
	if idx := strings.Index(cmd, " "); idx >= 0 {
		arg0 = cmd[:idx]
	}
	arg0Base := strings.ToLower(arg0[strings.LastIndex(arg0, "/")+1:])

	lower := strings.ToLower(cmd)
	for _, p := range patterns {
		if p.Arg0 != "" && !strings.HasPrefix(arg0Base, strings.ToLower(p.Arg0)) {
			continue
		}
		matched := true
		for _, kw := range p.Keywords {
			if !strings.Contains(lower, kw) {
				matched = false
				break
			}
			if refine, ok := execKeywordRefine[kw]; ok && !refine(lower) {
				matched = false
				break
			}
		}
		if matched {
			return p.Name
		}
	}
	return ""
}
