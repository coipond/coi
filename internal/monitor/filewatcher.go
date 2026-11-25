package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// monitoredFile describes a container-rootfs-relative path to watch with
// fanotify and the threat to raise when the inode is opened or written.
type monitoredFile struct {
	rel        string      // container-relative path, e.g. "etc/shadow"
	openLevel  ThreatLevel // non-empty → flag FAN_OPEN at this level
	writeLevel ThreatLevel // non-empty → flag FAN_CLOSE_WRITE at this level
	category   string
	openTitle  string
	openDesc   string
	writeTitle string
	writeDesc  string
	authRead   bool // reads by an authentication helper are not flagged
}

// sensitiveFiles is the list of files watched inside every monitored container.
var sensitiveFiles = []monitoredFile{
	// ── Credential reads ───────────────────────────────────────────────────
	{
		rel: "etc/shadow", openLevel: ThreatLevelHigh, writeLevel: ThreatLevelCritical,
		category:   "credential_access",
		authRead:   true,
		openTitle:  "Shadow password file read",
		openDesc:   "A process opened /etc/shadow which contains hashed passwords",
		writeTitle: "Shadow password file modified",
		writeDesc:  "A process wrote to /etc/shadow, potentially adding or changing a password hash",
	},
	{
		rel: "etc/gshadow", openLevel: ThreatLevelHigh, writeLevel: ThreatLevelHigh,
		category:   "credential_access",
		openTitle:  "Group shadow file read",
		openDesc:   "A process opened /etc/gshadow which contains group password hashes",
		writeTitle: "Group shadow file modified",
		writeDesc:  "A process wrote to /etc/gshadow",
	},
	{
		rel: "root/.ssh/id_rsa", openLevel: ThreatLevelHigh,
		category:  "credential_access",
		openTitle: "Root SSH RSA private key read",
		openDesc:  "A process opened the root account's RSA private key",
	},
	{
		rel: "root/.ssh/id_ecdsa", openLevel: ThreatLevelHigh,
		category:  "credential_access",
		openTitle: "Root SSH ECDSA private key read",
		openDesc:  "A process opened the root account's ECDSA private key",
	},
	{
		rel: "root/.ssh/id_ed25519", openLevel: ThreatLevelHigh,
		category:  "credential_access",
		openTitle: "Root SSH Ed25519 private key read",
		openDesc:  "A process opened the root account's Ed25519 private key",
	},
	{
		rel: "root/.ssh/id_dsa", openLevel: ThreatLevelHigh,
		category:  "credential_access",
		openTitle: "Root SSH DSA private key read",
		openDesc:  "A process opened the root account's DSA private key",
	},
	// ── Persistence writes ─────────────────────────────────────────────────
	{
		rel: "etc/passwd", writeLevel: ThreatLevelHigh,
		category:   "persistence",
		writeTitle: "Passwd file modified",
		writeDesc:  "A process wrote to /etc/passwd, potentially adding a backdoor account",
	},
	{
		rel: "etc/sudoers", writeLevel: ThreatLevelCritical,
		category:   "persistence",
		writeTitle: "Sudoers file modified",
		writeDesc:  "A process wrote to /etc/sudoers which controls privileged command access",
	},
	{
		rel: "root/.ssh/authorized_keys", writeLevel: ThreatLevelCritical,
		category:   "persistence",
		writeTitle: "Root authorized_keys modified",
		writeDesc:  "A process wrote to root's authorized_keys, potentially adding a backdoor SSH key",
	},
	{
		rel: "etc/crontab", writeLevel: ThreatLevelHigh,
		category:   "persistence",
		writeTitle: "Crontab modified",
		writeDesc:  "A process wrote to /etc/crontab, potentially adding a persistent scheduled task",
	},
	{
		rel: "root/.bashrc", writeLevel: ThreatLevelHigh,
		category:   "persistence",
		writeTitle: "Root .bashrc modified",
		writeDesc:  "A process wrote to root's .bashrc, potentially adding persistent shell commands",
	},
	{
		rel: "root/.profile", writeLevel: ThreatLevelHigh,
		category:   "persistence",
		writeTitle: "Root .profile modified",
		writeDesc:  "A process wrote to root's .profile",
	},
	{
		rel: "root/.bash_profile", writeLevel: ThreatLevelHigh,
		category:   "persistence",
		writeTitle: "Root .bash_profile modified",
		writeDesc:  "A process wrote to root's .bash_profile",
	},
}

// inodeKey uniquely identifies a file across all filesystems using the
// (device, inode) pair returned by fstat.
type inodeKey struct {
	dev uint64
	ino uint64
}

// inodeEntry records which sensitiveFile a watched inode corresponds to.
type inodeEntry struct {
	file *monitoredFile
}

// rawFanEvent holds the decoded fanotify event metadata extracted from the
// kernel-supplied byte stream before dispatch to the main loop.
type rawFanEvent struct {
	mask uint64
	fd   int
	pid  int
}

// FileWatcher monitors sensitive files inside a container via fanotify.
// Marks are placed on individual inodes (FAN_MARK_INODE) so only the specific
// files generate events — CPU overhead is near-zero during normal development
// work. A 30-second backstop re-marks files to recover from overlayfs copy-up,
// which replaces the inode on first write, invalidating the original mark.
// A 30-second startup grace period suppresses events that fire during container
// boot, when system daemons (PAM, sshd, cron) legitimately access sensitive
// files as part of normal initialisation.
type FileWatcher struct {
	containerName string
	onThreat      func(ThreatEvent)
	onError       func(error)
}

// NewFileWatcher creates a new FileWatcher for containerName.
func NewFileWatcher(containerName string, onThreat func(ThreatEvent), onError func(error)) *FileWatcher {
	return &FileWatcher{
		containerName: containerName,
		onThreat:      onThreat,
		onError:       onError,
	}
}

// Run starts the fanotify watch loop and blocks until ctx is cancelled.
// If fanotify is unavailable (no CAP_SYS_ADMIN, kernel too old, or inotify
// init limit reached) the method logs once via onError and returns immediately
// so the rest of the security monitor continues unaffected.
func (w *FileWatcher) Run(ctx context.Context) {
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		if w.onError != nil {
			w.onError(fmt.Errorf("filewatcher: fanotify_init: %w (sensitive file monitoring disabled)", err))
		}
		return
	}
	defer unix.Close(ifd)

	st := watchState{inodes: make(map[inodeKey]inodeEntry)}

	// Initial mark pass.
	if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
		w.mark(ifd, pid, &st)
	}

	// Background goroutine: poll the fanotify fd and decode events into evCh.
	evCh := make(chan rawFanEvent, 64)
	// The deferred Close of ifd above must not run while readEvents can still
	// poll/read it: once closed, the number can be reused (e.g. by an nft
	// child's pidfd during the parallel NFT teardown) and readEvents would read
	// that fd and close the "event fds" it parses out of it. Stop it first.
	readCtx, stopReading := context.WithCancel(ctx)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		w.readEvents(readCtx, ifd, evCh)
	}()
	defer func() {
		stopReading()
		<-readDone
	}()

	backstop := time.NewTicker(30 * time.Second)
	defer backstop.Stop()

	selfPID := os.Getpid()

	for {
		select {
		case <-ctx.Done():
			return

		case ev := <-evCh:
			if ev.fd < 0 {
				continue
			}
			// Discard events from our own monitoring process.
			if ev.pid == selfPID {
				unix.Close(ev.fd)
				continue
			}
			// Suppress events during the post-boot grace period to avoid
			// false positives from system daemons accessing sensitive files
			// as part of normal container initialisation.
			if time.Now().Before(st.graceUntil) {
				unix.Close(ev.fd)
				continue
			}
			var stat unix.Stat_t
			fstatErr := unix.Fstat(ev.fd, &stat)
			unix.Close(ev.fd)
			if fstatErr != nil {
				continue
			}
			key := inodeKey{dev: stat.Dev, ino: stat.Ino}
			if entry, ok := st.inodes[key]; ok {
				w.handle(entry, ev.mask, ev.pid)
			}

		case <-backstop.C:
			if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
				w.mark(ifd, pid, &st)
			}
		}
	}
}

// readEvents polls the fanotify fd and decodes events into evCh until ctx is
// cancelled. The caller is responsible for closing each ev.fd after use.
func (w *FileWatcher) readEvents(ctx context.Context, ifd int, evCh chan<- rawFanEvent) {
	buf := make([]byte, 4096)
	pfds := []unix.PollFd{{Fd: int32(ifd), Events: unix.POLLIN}} //nolint:gosec // fanotify fd fits in int32

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := unix.Poll(pfds, 200 /* ms */)
		if err != nil || n == 0 {
			continue
		}

		nr, err := unix.Read(ifd, buf)
		if err != nil || nr < 24 {
			continue
		}

		pos := 0
		for pos+24 <= nr {
			evLen := int(binary.NativeEndian.Uint32(buf[pos:]))
			if evLen < 24 || pos+evLen > nr {
				break
			}
			mask := binary.NativeEndian.Uint64(buf[pos+8:])
			fd := int(binary.NativeEndian.Uint32(buf[pos+16:]))
			pid := int(binary.NativeEndian.Uint32(buf[pos+20:]))
			pos += evLen

			select {
			case evCh <- rawFanEvent{mask: mask, fd: fd, pid: pid}:
			default:
				// Channel full — close fd to avoid leaking it and drop the event.
				if fd >= 0 {
					unix.Close(fd)
				}
			}
		}
	}
}

// watchState is what Run keeps between mark passes.
type watchState struct {
	lastPID    int
	inodes     map[inodeKey]inodeEntry
	graceUntil time.Time // suppress threats until container boot settles
	warned     bool      // the "no file marked" error was reported
}

// mark re-marks the sensitive files of the container whose init PID is pid.
// The inode map is replaced, not merged: that picks up new inodes from
// copy-up and drops deleted or moved files, which a group without
// FAN_REPORT_FID is not told about. A new PID (first pass, container restart)
// starts the grace period: system daemons (PAM, sshd, cron) open /etc/shadow
// and other sensitive files during boot.
func (w *FileWatcher) mark(ifd, pid int, st *watchState) {
	st.inodes = w.markFiles(ifd, pid)
	if pid != st.lastPID {
		st.lastPID = pid
		st.graceUntil = time.Now().Add(30 * time.Second)
	}
	if len(st.inodes) == 0 && !st.warned && w.onError != nil {
		st.warned = true
		w.onError(fmt.Errorf("filewatcher: no sensitive file could be marked under "+procRootPattern+
			" (needs CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH besides CAP_SYS_ADMIN; sensitive file monitoring disabled)", pid))
	}
}

// handle raises the threat for one event on a watched file. An
// authentication helper (sudo, su, PAM's unix_chkpwd) reads /etc/shadow on
// every use, so its reads of a file marked authRead do not count.
func (w *FileWatcher) handle(entry inodeEntry, mask uint64, pid int) {
	if mask&unix.FAN_OPEN != 0 && entry.file.openLevel != "" && (!entry.file.authRead || !isAuthHelper(pid)) {
		w.fire(entry.file.openLevel, entry.file.category,
			entry.file.openTitle, entry.file.openDesc,
			entry.file.rel, "read", pid)
	}
	if mask&unix.FAN_CLOSE_WRITE != 0 && entry.file.writeLevel != "" {
		w.fire(entry.file.writeLevel, entry.file.category,
			entry.file.writeTitle, entry.file.writeDesc,
			entry.file.rel, "write", pid)
	}
}

// procRootPattern and procPidPattern are the host paths of a process's root
// and of its /proc directory; tests point them at a temp dir.
var (
	procRootPattern = "/proc/%d/root"
	procPidPattern  = "/proc/%d"
)

// authHelpers are the container paths of the programs that read /etc/shadow
// to authenticate: sudo (also sudo-rs), su and PAM's unix_chkpwd.
var authHelpers = map[string]bool{
	"/usr/bin/sudo":           true,
	"/usr/lib/cargo/bin/sudo": true,
	"/usr/bin/su":             true,
	"/usr/lib/cargo/bin/su":   true,
	"/usr/sbin/unix_chkpwd":   true,
}

// isAuthHelper reports whether host process pid runs an authentication
// helper that is not editing a file: sudoedit (sudo -e) opens the file it
// edits itself, as root. An unreadable executable or command line (the
// process is gone) counts as not one.
func isAuthHelper(pid int) bool {
	dir := fmt.Sprintf(procPidPattern, pid)
	exe, err := os.Readlink(dir + "/exe")
	if err != nil || !authHelpers[exe] {
		return false
	}
	cmdline, err := os.ReadFile(dir + "/cmdline")
	if err != nil {
		return false
	}
	return !sudoEdits(strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"))
}

// sudo's option tables (sudo_short_opts and sudo_long_opts in sudo 1.9's
// src/parse_args.c). sudoValueOpts are the short options that take a value;
// -h takes one only when attached ("h::"). sudoLongOpts are the long options,
// true for those that take a value (preserve-env only as --preserve-env=).
var (
	sudoValueOpts = "aCcDgpRrTtUu"
	sudoLongOpts  = map[string]bool{
		"askpass": false, "auth-type": true, "background": false, "bell": false,
		"chdir": true, "chroot": true, "close-from": true, "command-timeout": true,
		"edit": false, "group": true, "help": false, "host": true, "list": false,
		"login": false, "login-class": true, "no-update": false,
		"non-interactive": false, "other-user": true, "preserve-env": false,
		"preserve-groups": false, "prompt": true, "remove-timestamp": false,
		"reset-timestamp": false, "role": true, "set-home": false, "shell": false,
		"stdin": false, "type": true, "user": true, "validate": false,
		"version": false,
	}
)

// sudoLongOpt resolves a long option name as getopt_long does: an exact
// name, or a prefix of exactly one name. ok is false for an unknown or
// ambiguous name.
func sudoLongOpt(name string) (resolved string, ok bool) {
	if _, exact := sudoLongOpts[name]; exact {
		return name, true
	}
	for opt := range sudoLongOpts {
		if strings.HasPrefix(opt, name) {
			if resolved != "" {
				return "", false
			}
			resolved = opt
		}
	}
	return resolved, resolved != ""
}

// sudoEdits reports whether argv runs sudo in edit mode: argv[0] sudoedit,
// or -e/--edit (or a prefix of it) among sudo's own options (before the
// command). An unknown or ambiguous long option counts as edit mode: sudo
// rejects it, so nothing is exempted that sudo would accept.
func sudoEdits(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	if filepath.Base(argv[0]) == "sudoedit" {
		return true
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-":
			return false
		case strings.HasPrefix(arg, "--"):
			name, _, inline := strings.Cut(arg[2:], "=")
			opt, ok := sudoLongOpt(name)
			if !ok || opt == "edit" {
				return true
			}
			if sudoLongOpts[opt] && !inline {
				i++
			}
		default:
			for j := 1; j < len(arg); j++ {
				if arg[j] == 'e' {
					return true
				}
				if arg[j] == 'h' {
					break
				}
				if strings.IndexByte(sudoValueOpts, arg[j]) >= 0 {
					if j == len(arg)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return false
}

// markFiles registers FAN_MARK_INODE watches for all sensitive files inside
// the container rooted at /proc/<pid>/root and returns the resulting inode map.
// Files that don't exist yet are silently skipped; the backstop retries them.
func (w *FileWatcher) markFiles(ifd, pid int) map[inodeKey]inodeEntry {
	inodes := make(map[inodeKey]inodeEntry)
	for i := range sensitiveFiles {
		sf := &sensitiveFiles[i]
		hostPath := fmt.Sprintf(procRootPattern+"/%s", pid, sf.rel)

		if err := unix.FanotifyMark(ifd, unix.FAN_MARK_ADD, sf.markMask(), unix.AT_FDCWD, hostPath); err != nil {
			// File does not exist (ENOENT) or not accessible — skip silently.
			continue
		}

		var stat unix.Stat_t
		if err := unix.Stat(hostPath, &stat); err != nil {
			continue
		}
		inodes[inodeKey{dev: stat.Dev, ino: stat.Ino}] = inodeEntry{file: sf}
	}
	return inodes
}

// markMask returns the fanotify events to mark sf with. Only events that
// carry an fd: FAN_DELETE_SELF or FAN_MOVE_SELF needs a FAN_REPORT_FID group,
// and fanotify_mark refuses the whole mask with EINVAL without one.
func (sf *monitoredFile) markMask() uint64 {
	var mask uint64
	if sf.openLevel != "" {
		mask |= unix.FAN_OPEN
	}
	if sf.writeLevel != "" {
		mask |= unix.FAN_CLOSE_WRITE
	}
	return mask
}

// fire emits a ThreatEvent via the onThreat callback.
func (w *FileWatcher) fire(level ThreatLevel, category, title, desc, relPath, access string, pid int) {
	if w.onThreat == nil {
		return
	}
	w.onThreat(sensitiveFileThreat(level, category, title, desc, relPath, access, pid))
}

// sensitiveFileThreat builds the ThreatEvent for an access to the
// container-relative file relPath by host process pid.
func sensitiveFileThreat(level ThreatLevel, category, title, desc, relPath, access string, pid int) ThreatEvent {
	return ThreatEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Level:       level,
		Category:    category,
		Title:       title,
		Description: fmt.Sprintf("%s (path: %s, host pid: %d)", desc, relPath, pid),
		Evidence: Evidence{
			SensitiveFile: &SensitiveFileThreat{
				Path:   relPath,
				Access: access,
				Pid:    pid,
			},
		},
	}
}
