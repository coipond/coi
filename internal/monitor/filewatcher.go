package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
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
}

// sensitiveFiles is the list of files watched inside every monitored container.
var sensitiveFiles = []monitoredFile{
	// ── Credential reads ───────────────────────────────────────────────────
	{
		rel: "etc/shadow", openLevel: ThreatLevelHigh, writeLevel: ThreatLevelCritical,
		category:   "credential_access",
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
// so the rest of the monitoring daemon continues unaffected.
func (w *FileWatcher) Run(ctx context.Context) {
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		if w.onError != nil {
			w.onError(fmt.Errorf("filewatcher: fanotify_init: %w (sensitive file monitoring disabled)", err))
		}
		return
	}
	defer unix.Close(ifd)

	var (
		lastPID    int
		inodes     map[inodeKey]inodeEntry
		graceUntil time.Time // suppress threats until container boot settles
	)

	// Initial mark pass.
	if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
		inodes = w.markFiles(ifd, pid)
		lastPID = pid
		// System daemons (PAM, sshd, cron) open /etc/shadow and other sensitive
		// files during container boot. Suppress threats for 30 s so these normal
		// init reads don't trigger false-positive auto-pause events.
		graceUntil = time.Now().Add(30 * time.Second)
	}
	if inodes == nil {
		inodes = make(map[inodeKey]inodeEntry)
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
			if time.Now().Before(graceUntil) {
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
			entry, ok := inodes[key]
			if !ok {
				continue
			}
			// File deleted or moved — drop the inode entry; the backstop will
			// re-mark the path if/when a new file appears there.
			if ev.mask&(unix.FAN_DELETE_SELF|unix.FAN_MOVE_SELF) != 0 {
				delete(inodes, key)
				continue
			}
			if ev.mask&unix.FAN_OPEN != 0 && entry.file.openLevel != "" {
				w.fire(entry.file.openLevel, entry.file.category,
					entry.file.openTitle, entry.file.openDesc,
					entry.file.rel, "read", ev.pid)
			}
			if ev.mask&unix.FAN_CLOSE_WRITE != 0 && entry.file.writeLevel != "" {
				w.fire(entry.file.writeLevel, entry.file.category,
					entry.file.writeTitle, entry.file.writeDesc,
					entry.file.rel, "write", ev.pid)
			}

		case <-backstop.C:
			pid, _ := GetContainerInitPID(ctx, w.containerName)
			if pid <= 0 {
				continue
			}
			newInodes := w.markFiles(ifd, pid)
			if pid != lastPID {
				// Container restarted — replace the map and reset the grace period.
				inodes = newInodes
				lastPID = pid
				graceUntil = time.Now().Add(30 * time.Second)
			} else {
				// Same container — merge to pick up new inodes from copy-up.
				for k, v := range newInodes {
					inodes[k] = v
				}
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

// markFiles registers FAN_MARK_INODE watches for all sensitive files inside
// the container rooted at /proc/<pid>/root and returns the resulting inode map.
// Files that don't exist yet are silently skipped; the backstop retries them.
func (w *FileWatcher) markFiles(ifd, pid int) map[inodeKey]inodeEntry {
	inodes := make(map[inodeKey]inodeEntry)
	for i := range sensitiveFiles {
		sf := &sensitiveFiles[i]
		hostPath := fmt.Sprintf("/proc/%d/root/%s", pid, sf.rel)

		mask := uint64(unix.FAN_DELETE_SELF | unix.FAN_MOVE_SELF)
		if sf.openLevel != "" {
			mask |= unix.FAN_OPEN
		}
		if sf.writeLevel != "" {
			mask |= unix.FAN_CLOSE_WRITE
		}

		if err := unix.FanotifyMark(ifd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, hostPath); err != nil {
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

// fire emits a ThreatEvent via the onThreat callback.
func (w *FileWatcher) fire(level ThreatLevel, category, title, desc, relPath, access string, pid int) {
	if w.onThreat == nil {
		return
	}
	w.onThreat(ThreatEvent{
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
	})
}
