package monitor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/mensfeld/coi/internal/container"
	"golang.org/x/sys/unix"
)

// logCandidates are log paths (relative to container rootfs) that the watcher tails.
var logCandidates = []string{
	"var/log/auth.log",
	"var/log/syslog",
	"var/log/audit/audit.log",
}

// logPattern defines a set of keywords that must all appear in a log line
// (case-insensitive) and the threat to raise when matched.
type logPattern struct {
	name     string
	keywords []string
	level    ThreatLevel
	title    string
	desc     string
}

var authLogPatterns = []logPattern{
	{
		name:     "ssh_failed_password",
		keywords: []string{"failed password"},
		level:    ThreatLevelWarning,
		title:    "SSH authentication failure",
		desc:     "Failed SSH password attempt detected in auth log",
	},
	{
		name:     "ssh_invalid_user",
		keywords: []string{"invalid user"},
		level:    ThreatLevelWarning,
		title:    "SSH login attempt with invalid user",
		desc:     "SSH login attempt with an unknown username detected in auth log",
	},
	{
		name:     "pam_auth_failure",
		keywords: []string{"pam_unix", "authentication failure"},
		level:    ThreatLevelWarning,
		title:    "PAM authentication failure",
		desc:     "PAM authentication failure detected in auth log",
	},
	{
		name:     "sudo_not_allowed",
		keywords: []string{"sudo", "command not allowed"},
		level:    ThreatLevelHigh,
		title:    "Unauthorized sudo command",
		desc:     "A user attempted an unauthorized sudo command",
	},
	{
		name:     "sudo_not_in_sudoers",
		keywords: []string{"sudo", "sudoers"},
		level:    ThreatLevelHigh,
		title:    "Unauthorized sudo attempt (not in sudoers)",
		desc:     "A user not listed in sudoers attempted to use sudo",
	},
	{
		name:     "su_failed",
		keywords: []string{"failed su for"},
		level:    ThreatLevelHigh,
		title:    "Failed su privilege escalation",
		desc:     "A failed su attempt was detected, indicating a possible privilege escalation",
	},
	{
		name:     "root_session",
		keywords: []string{"session opened for user root"},
		level:    ThreatLevelWarning,
		title:    "Root session opened",
		desc:     "A root session was opened inside the container",
	},
	// ── auditd patterns (key=value structured lines) ──────────────────────
	{
		name:     "auditd_auth_failure",
		keywords: []string{"type=user_auth", "res=failed"},
		level:    ThreatLevelHigh,
		title:    "Auditd: authentication failure",
		desc:     "auditd recorded a USER_AUTH failure",
	},
	{
		name:     "auditd_user_cmd_failed",
		keywords: []string{"type=user_cmd", "res=failed"},
		level:    ThreatLevelHigh,
		title:    "Auditd: unauthorized command",
		desc:     "auditd recorded a USER_CMD failure (unauthorized sudo or su)",
	},
	{
		name:     "auditd_login_failure",
		keywords: []string{"type=user_login", "res=failed"},
		level:    ThreatLevelWarning,
		title:    "Auditd: login failure",
		desc:     "auditd recorded a USER_LOGIN failure",
	},
	{
		name:     "auditd_acct_failure",
		keywords: []string{"type=user_acct", "res=failed"},
		level:    ThreatLevelWarning,
		title:    "Auditd: account action failure",
		desc:     "auditd recorded a USER_ACCT failure (account modification rejected)",
	},
}

// logState tracks the read position and inode for a single log file across
// polls so the watcher can detect log rotation and only process new lines.
type logState struct {
	offset        int64
	inode         uint64 // 0 = unknown (incus fallback has no fd-level inode)
	usingFallback bool   // true while the host-side path is unavailable
}

// inotifyRawEvent is a minimal parsed inotify event.
type inotifyRawEvent struct {
	wd   int32
	mask uint32
}

// LogWatcher tails auth.log, syslog, and audit.log from the container. It
// uses inotify for near-instant detection, watching /proc/<initPID>/root/<rel>
// directly from the host so the incus daemon subprocess is never involved.
//
// The inotify approach watches each log file for IN_MODIFY events and the
// parent directory for IN_CREATE so log rotation (mv + new file) is handled
// transparently. A 30-second backstop ticker covers missed events and
// container restarts. If inotify is unavailable the watcher falls back to
// 5-second polling.
//
// Note: unlike kernel-maintained sources (network, process, cgroup), auth.log
// and syslog are regular writable files. A root attacker inside the container
// could truncate or modify them. The host-side read buys independence from the
// incus daemon/agent and access to the live mount-namespace view.
//
// When the host path is unreadable (e.g. the monitor lacks ptrace permission
// in the container's user-namespace) the watcher falls back to incus file
// pull and logs the transition once via onError.
type LogWatcher struct {
	containerName string
	onThreat      func(ThreatEvent)
	onError       func(error)
}

// NewLogWatcher creates a LogWatcher for the named container.
func NewLogWatcher(containerName string, onThreat func(ThreatEvent), onError func(error)) *LogWatcher {
	return &LogWatcher{
		containerName: containerName,
		onThreat:      onThreat,
		onError:       onError,
	}
}

// Run tails log files until ctx is cancelled. It tries inotify first for
// low-latency detection and falls back to 5-second polling if unavailable.
func (lw *LogWatcher) Run(ctx context.Context) {
	states := make(map[string]logState)

	ifd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		lw.runPolling(ctx, states)
		return
	}
	// Close ifd exactly once — either when ctx is cancelled or on return.
	var closeOnce sync.Once
	closeFd := func() { closeOnce.Do(func() { unix.Close(ifd) }) }
	defer closeFd()
	// This goroutine may outlive Run when ifd closes due to a read error before
	// ctx is done; it exits as soon as the session context is cancelled.
	go func() { <-ctx.Done(); closeFd() }()

	pid, _ := GetContainerInitPID(ctx, lw.containerName)
	wdToRel, dirWd := addInotifyWatches(ifd, pid)

	// Initial read: catch lines written before the watches were registered.
	for _, rel := range logCandidates {
		lw.pollFile(ctx, rel, states, pid)
	}

	events := inotifyReader(ifd)
	// Backstop: re-resolve PID on container restart and fill any missing watches.
	// 3 s keeps detection latency low when log files don't exist at watch-setup
	// time (e.g. container using overlayfs where IN_CREATE doesn't cross the
	// namespace boundary reliably). GetContainerInitPID is fast (cgroup reads).
	backstop := time.NewTicker(3 * time.Second)
	defer backstop.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return // ifd closed (ctx cancelled or unrecoverable read error)
			}
			switch {
			case ev.mask&unix.IN_IGNORED != 0:
				// Kernel confirms watch removal (explicit rm or file deleted).
				delete(wdToRel, ev.wd)
				if ev.wd == dirWd {
					dirWd = -1
				}
			case ev.wd == dirWd && ev.mask&unix.IN_CREATE != 0:
				// A file appeared in the log directory (rotation target recreated).
				newWds, newDir := addInotifyWatches(ifd, pid)
				for wd, rel := range newWds {
					wdToRel[wd] = rel
				}
				if dirWd < 0 {
					dirWd = newDir
				}
				for _, rel := range logCandidates {
					lw.pollFile(ctx, rel, states, pid)
				}
			case ev.mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0:
				// Log file rotated away; the directory watch will fire IN_CREATE
				// when the replacement appears.
				unix.InotifyRmWatch(ifd, uint32(ev.wd)) //nolint:errcheck,gosec // G115: inotify wd fits in uint32
				delete(wdToRel, ev.wd)
			case ev.mask&unix.IN_MODIFY != 0:
				if rel, ok := wdToRel[ev.wd]; ok {
					lw.pollFile(ctx, rel, states, pid)
				}
			}
		case <-backstop.C:
			newPid, _ := GetContainerInitPID(ctx, lw.containerName)
			if newPid != pid {
				// Container restarted; all /proc/<old-pid> paths are invalid.
				pid = newPid
				for wd := range wdToRel {
					unix.InotifyRmWatch(ifd, uint32(wd)) //nolint:errcheck,gosec // G115: inotify wd fits in uint32
				}
				if dirWd >= 0 {
					unix.InotifyRmWatch(ifd, uint32(dirWd)) //nolint:errcheck,gosec // G115: inotify wd fits in uint32
				}
				wdToRel, dirWd = addInotifyWatches(ifd, pid)
			} else if len(wdToRel) < len(logCandidates) {
				// Some log files haven't been created yet; retry.
				newWds, newDir := addInotifyWatches(ifd, pid)
				for wd, rel := range newWds {
					wdToRel[wd] = rel
				}
				if dirWd < 0 {
					dirWd = newDir
				}
			}
			// Safety-net read to catch any events delivered while inotify fd
			// was being rebuilt or on the rare missed event.
			for _, rel := range logCandidates {
				lw.pollFile(ctx, rel, states, pid)
			}
		}
	}
}

// runPolling is the fallback 5-second ticker path used when inotify is
// unavailable (e.g. kernel too old or resource limit reached).
func (lw *LogWatcher) runPolling(ctx context.Context, states map[string]logState) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pid, _ := GetContainerInitPID(ctx, lw.containerName)
			for _, rel := range logCandidates {
				lw.pollFile(ctx, rel, states, pid)
			}
		}
	}
}

// addInotifyWatches registers IN_MODIFY/rotate watches on each log candidate
// and an IN_CREATE watch on their parent directory. Returns a wd→rel map and
// the directory watch descriptor (-1 if the watch could not be added).
func addInotifyWatches(ifd, pid int) (wdToRel map[int32]string, dirWd int32) {
	wdToRel = make(map[int32]string)
	dirWd = -1
	if pid <= 0 {
		return
	}
	for _, rel := range logCandidates {
		hostPath := fmt.Sprintf("/proc/%d/root/%s", pid, rel)
		wd, err := unix.InotifyAddWatch(ifd, hostPath,
			unix.IN_MODIFY|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
		if err == nil {
			wdToRel[int32(wd)] = rel //nolint:gosec // G115: InotifyAddWatch returns a 32-bit wd
		}
	}
	// Directory watch so we notice when a rotated log file is recreated.
	dirPath := fmt.Sprintf("/proc/%d/root/var/log", pid)
	wd, err := unix.InotifyAddWatch(ifd, dirPath, unix.IN_CREATE)
	if err == nil {
		dirWd = int32(wd) //nolint:gosec // G115: InotifyAddWatch returns a 32-bit wd
	}
	return
}

// inotifyBufSize is large enough for a burst of 16 maximum-sized inotify events
// (each at most SizeofInotifyEvent + NAME_MAX + 1 bytes).
const inotifyBufSize = (unix.SizeofInotifyEvent + unix.NAME_MAX + 1) * 16

// inotifyReader spawns a goroutine that polls ifd (non-blocking) and forwards
// parsed events to the returned channel. The channel is closed when ifd is
// closed or an unrecoverable read error occurs.
func inotifyReader(ifd int) <-chan inotifyRawEvent {
	ch := make(chan inotifyRawEvent, 64)
	go func() {
		defer close(ch)
		buf := make([]byte, inotifyBufSize)
		fds := []unix.PollFd{{Fd: int32(ifd), Events: unix.POLLIN}} //nolint:gosec // G115: fd values are small non-negative ints
		for {
			n, err := unix.Poll(fds, 200) // 200 ms so ctx cancellation is noticed promptly
			if err != nil || n < 0 {
				return
			}
			if n == 0 {
				continue
			}
			nr, err := unix.Read(ifd, buf)
			if err != nil || nr < 16 {
				return
			}
			data := buf[:nr]
			for len(data) >= 16 {
				wd := int32(binary.NativeEndian.Uint32(data[0:])) //nolint:gosec // G115: inotify wd is a kernel int32 stored as 4 bytes
				mask := binary.NativeEndian.Uint32(data[4:])
				// data[8:12] = cookie (unused)
				nameLen := binary.NativeEndian.Uint32(data[12:])
				data = data[16:]
				if int(nameLen) > len(data) {
					break
				}
				data = data[nameLen:]
				ch <- inotifyRawEvent{wd: wd, mask: mask}
			}
		}
	}()
	return ch
}

// pollFile reads lines appended to rel since the last poll and fires threat
// events for any that match. It tries a direct host-side read first and falls
// back to incus file pull on failure, logging the transition once.
//
// Only newline-terminated lines are processed; a trailing partial line is
// left at the current offset and re-read once the newline arrives.
func (lw *LogWatcher) pollFile(ctx context.Context, rel string, states map[string]logState, pid int) {
	state := states[rel]

	var newData []byte
	var base int64
	var inode uint64
	hostOK := false

	if pid > 0 {
		hostPath := fmt.Sprintf("/proc/%d/root/%s", pid, rel)
		d, b, ino, err := readFileChunk(hostPath, state)
		if err == nil {
			hostOK = true
			newData = d
			base = b
			inode = ino
		}
	}

	if !hostOK {
		// Log once when transitioning into fallback mode.
		if !state.usingFallback && lw.onError != nil {
			lw.onError(fmt.Errorf("logwatcher: host-side read unavailable for %s (pid=%d), falling back to incus file pull", rel, pid))
		}
		d, b, ok := lw.pullFileChunk(ctx, rel, state)
		if !ok {
			return
		}
		newData = d
		base = b
		// The incus file pull has no file descriptor, so no fresh inode. Preserve
		// the last-known inode rather than clobbering it with 0 — otherwise a
		// single transient fallback blip (e.g. GetContainerInitPID momentarily
		// returns 0 under load) permanently disables inode-based rotation
		// detection in readFileChunk, which can silently miss a post-rotation
		// file whose size happens to be >= the stored offset.
		inode = state.inode
	}

	newState := logState{inode: inode, usingFallback: !hostOK}

	if len(newData) == 0 {
		newState.offset = base
		states[rel] = newState
		return
	}

	// Only advance the offset to the last complete (newline-terminated) line.
	// Bytes after the final newline are a partial line mid-write; leaving the
	// offset before them means they will be re-read and completed next tick.
	lastNL := bytes.LastIndexByte(newData, '\n')
	if lastNL < 0 {
		// No complete line yet — preserve offset, update inode.
		newState.offset = base
		states[rel] = newState
		return
	}
	newState.offset = base + int64(lastNL+1)
	states[rel] = newState

	logFile := rel[strings.LastIndex(rel, "/")+1:]
	reader := bufio.NewReader(bytes.NewReader(newData[:lastNL+1]))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			continue
		}
		if threat := parseAuthLogLine(logFile, trimmed); threat != nil && lw.onThreat != nil {
			lw.onThreat(*threat)
		}
	}
}

// readFileChunk opens path, detects log rotation (inode change or file
// smaller than the stored offset), seeks to the appropriate offset, and
// reads all available bytes. It returns the data, the base offset the read
// started from (0 after a rotation reset), and the current inode.
// Returns (nil, offset, inode, nil) when the file has not grown.
func readFileChunk(path string, state logState) ([]byte, int64, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, state.offset, 0, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, state.offset, 0, err
	}

	var curInode uint64
	if sysInfo, ok := fi.Sys().(*syscall.Stat_t); ok {
		curInode = sysInfo.Ino
	}

	offset := state.offset
	// Detect log rotation: inode changed (skip check when state.inode is 0,
	// which means the previous read used the incus fallback with no inode) or
	// file is smaller than our offset (truncation / fresh rotation target).
	inodeChanged := state.inode != 0 && curInode != 0 && curInode != state.inode
	if inodeChanged || fi.Size() < offset {
		offset = 0
	}

	if fi.Size() == offset {
		return nil, offset, curInode, nil // no new data
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, curInode, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, offset, curInode, err
	}

	return data, offset, curInode, nil
}

// pullFileChunk fetches the log file via incus file pull and returns bytes
// appended since state.offset. It detects truncation by size (no inode
// available for this path). Returns (nil, base, true) when there is no new
// content and (nil, offset, false) on error.
func (lw *LogWatcher) pullFileChunk(ctx context.Context, rel string, state logState) ([]byte, int64, bool) {
	tmp, err := os.CreateTemp("", "coi-log-*")
	if err != nil {
		return nil, state.offset, false
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	src := lw.containerName + "/" + rel
	if _, err := container.IncusOutputContext(ctx, "file", "pull", src, tmpPath); err != nil {
		return nil, state.offset, false // file absent or container not running — benign
	}

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, state.offset, false
	}

	offset := state.offset
	// Detect truncation (no inode for incus file pull).
	if int64(len(content)) < offset {
		offset = 0
	}

	if int64(len(content)) == offset {
		return nil, offset, true // no new content
	}

	return content[offset:], offset, true
}

// parseAuthLogLine checks a single log line against known auth patterns and
// returns a ThreatEvent if it matches, nil otherwise.
func parseAuthLogLine(logFile, line string) *ThreatEvent {
	lower := strings.ToLower(line)
	for _, p := range authLogPatterns {
		matched := true
		for _, kw := range p.keywords {
			if !strings.Contains(lower, kw) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}

		evLine := truncateToRunes(line, 300)

		return &ThreatEvent{
			ID:          uuid.New().String(),
			Timestamp:   time.Now(),
			Level:       p.level,
			Category:    "auth",
			Title:       p.title,
			Description: p.desc + ": " + evLine,
			Evidence: Evidence{
				AuthLog: &AuthLogThreat{
					LogFile: logFile,
					Line:    evLine,
					Pattern: p.name,
				},
			},
			Action: "pending",
		}
	}
	return nil
}

// truncateToRunes truncates s to at most max Unicode code points, appending
// "…" if truncation occurs. This avoids splitting UTF-8 sequences mid-byte.
func truncateToRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	runes := []rune(s)
	return string(runes[:limit]) + "…"
}
