package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// userFile is a container-rootfs-relative file of the code user whose
// creation, modification or replacement (rename over it) raises a threat.
type userFile struct {
	rel      string // e.g. "home/code/.bashrc"
	category string
	title    string
	desc     string
}

// userFiles returns the persistence and credential files of the code user
// named user: shell startup files, authorized_keys, the user crontab and the
// tool credential files coi copies (secretPaths, relative to the home).
func userFiles(user string, secretPaths []string) []userFile {
	home := "home/" + user
	files := []userFile{
		{
			rel: home + "/.ssh/authorized_keys", category: "persistence",
			title: "User authorized_keys modified",
			desc:  "A process wrote to the code user's authorized_keys, potentially adding a backdoor SSH key",
		},
		{
			rel: home + "/.bashrc", category: "persistence",
			title: "User .bashrc modified",
			desc:  "A process wrote to the code user's .bashrc, potentially adding persistent shell commands",
		},
		{
			rel: home + "/.profile", category: "persistence",
			title: "User .profile modified",
			desc:  "A process wrote to the code user's .profile, potentially adding persistent shell commands",
		},
		{
			rel: "var/spool/cron/crontabs/" + user, category: "persistence",
			title: "User crontab modified",
			desc:  "A process wrote to the code user's crontab, potentially adding a persistent scheduled task",
		},
	}
	for _, p := range secretPaths {
		files = append(files, userFile{
			rel: home + "/" + p, category: "credential_access",
			title: "Tool credential file modified",
			desc:  "A process in the container wrote to a tool credential file that coi copies in",
		})
	}
	return files
}

// dirKey identifies a directory by its filesystem id and file handle, as a
// FAN_REPORT_DFID_NAME event names it.
type dirKey string

// newDirKey builds the dirKey of a filesystem id and file handle.
func newDirKey(fsid [8]byte, handleType int32, handle []byte) dirKey {
	var b bytes.Buffer
	b.Write(fsid[:])
	_ = binary.Write(&b, binary.NativeEndian, handleType)
	b.Write(handle)
	return dirKey(b.String())
}

// fanNameEvent is a decoded FAN_REPORT_DFID_NAME event: the directory, the
// name of the entry in it, and the host PID of the process that caused it.
type fanNameEvent struct {
	mask uint64
	pid  int
	dir  dirKey
	name string
}

// UserFileWatcher watches the code user's persistence and credential files
// with a FAN_REPORT_DFID_NAME fanotify group. It marks the parent
// directories, so a file created after the mark pass, written in place or
// replaced by a rename is reported, with the PID of the writer. A write by
// a process outside the container (coi's own copy through Incus) is not
// flagged. Directories that do not exist yet are marked when created in a
// marked ancestor, and by the 30-second backstop. The 30-second boot grace
// period of FileWatcher applies too.
type UserFileWatcher struct {
	containerName string
	user          string
	files         []userFile
	onThreat      func(ThreatEvent)
	onError       func(error)
}

// NewUserFileWatcher creates a UserFileWatcher for the files of the code
// user named user in containerName.
func NewUserFileWatcher(containerName, user string, secretPaths []string, onThreat func(ThreatEvent), onError func(error)) *UserFileWatcher {
	return &UserFileWatcher{
		containerName: containerName,
		user:          user,
		files:         userFiles(user, secretPaths),
		onThreat:      onThreat,
		onError:       onError,
	}
}

// userWatchState is what Run keeps between mark passes: the marked
// directories by key (their container-relative path) and the grace period.
type userWatchState struct {
	pid        int
	dirs       map[dirKey]string
	graceUntil time.Time
}

// Run starts the watch loop and blocks until ctx is cancelled. Without
// fanotify name events (kernel before 5.9, no CAP_SYS_ADMIN) it reports
// once via onError and returns.
func (w *UserFileWatcher) Run(ctx context.Context) {
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		if w.onError != nil {
			w.onError(fmt.Errorf("filewatcher: fanotify_init(FAN_REPORT_DFID_NAME): %w (user persistence and credential file monitoring disabled)", err))
		}
		return
	}
	defer unix.Close(ifd)

	st := userWatchState{dirs: make(map[dirKey]string)}
	if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
		w.mark(ifd, pid, &st)
	}

	evCh := make(chan fanNameEvent, 64)
	readCtx, stopReading := context.WithCancel(ctx)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readNameEvents(readCtx, ifd, evCh)
	}()
	defer func() {
		stopReading()
		<-readDone
	}()

	backstop := time.NewTicker(30 * time.Second)
	defer backstop.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-evCh:
			w.handle(ifd, ev, &st)
		case <-backstop.C:
			if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
				w.mark(ifd, pid, &st)
			}
		}
	}
}

// handle raises the threat for one event in a marked directory, or marks a
// directory on a watched path that was just created.
func (w *UserFileWatcher) handle(ifd int, ev fanNameEvent, st *userWatchState) {
	dir, ok := st.dirs[ev.dir]
	if !ok || st.pid == 0 {
		return
	}
	rel := path.Join(dir, ev.name)
	if ev.mask&unix.FAN_ONDIR != 0 {
		// A directory on a watched path appeared: mark it now.
		if w.onWatchedPath(rel) {
			w.mark(ifd, st.pid, st)
		}
		return
	}
	if time.Now().Before(st.graceUntil) {
		return
	}
	if ev.mask&unix.FAN_CREATE != 0 {
		return // the FAN_CLOSE_WRITE of the creator follows
	}
	if f := w.file(rel); f != nil && !w.fromHost(ev.pid) {
		w.fire(f, ev.pid)
	}
}

// mark marks every existing directory on a watched path in the container
// whose init PID is pid and replaces st.dirs. A new PID (first pass,
// container restart) starts the grace period.
func (w *UserFileWatcher) mark(ifd, pid int, st *userWatchState) {
	if pid != st.pid {
		st.pid = pid
		st.graceUntil = time.Now().Add(30 * time.Second)
	}
	dirs := make(map[dirKey]string)
	for _, rel := range w.watchedDirs() {
		hostPath := fmt.Sprintf(procRootFmt+"/%s", pid, rel)
		mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_MOVED_TO | unix.FAN_CREATE | unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD)
		if err := unix.FanotifyMark(ifd, unix.FAN_MARK_ADD|unix.FAN_MARK_ONLYDIR|unix.FAN_MARK_DONT_FOLLOW, mask, unix.AT_FDCWD, hostPath); err != nil {
			continue // not there yet: marked once created
		}
		key, err := dirKeyOf(hostPath)
		if err != nil {
			continue
		}
		dirs[key] = rel
	}
	st.dirs = dirs
}

// procRootFmt is the host path of a process's root directory; tests point
// it at a temp dir.
var procRootFmt = "/proc/%d/root"

// procCgroupFmt is the host path of a process's cgroup file; tests point it
// at a temp dir.
var procCgroupFmt = "/proc/%d/cgroup"

// dirKeyOf returns the dirKey fanotify reports for the directory at p.
func dirKeyOf(p string) (dirKey, error) {
	var sfs unix.Statfs_t
	if err := unix.Statfs(p, &sfs); err != nil {
		return "", err
	}
	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, p, 0)
	if err != nil {
		return "", err
	}
	var fsid [8]byte
	binary.NativeEndian.PutUint32(fsid[0:], uint32(sfs.Fsid.Val[0])) //nolint:gosec // raw fsid bytes
	binary.NativeEndian.PutUint32(fsid[4:], uint32(sfs.Fsid.Val[1])) //nolint:gosec // raw fsid bytes
	return newDirKey(fsid, fh.Type(), fh.Bytes()), nil
}

// watchedDirs returns every directory on the path of a watched file, from
// the home (or the crontab directory) down, without duplicates.
func (w *UserFileWatcher) watchedDirs() []string {
	home := "home/" + w.user
	seen := make(map[string]bool)
	var dirs []string
	for _, f := range w.files {
		for d := path.Dir(f.rel); d != "." && d != "/"; d = path.Dir(d) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
			if d == home || !strings.HasPrefix(d, home+"/") {
				break
			}
		}
	}
	return dirs
}

// onWatchedPath reports whether rel is a directory on the path of a watched
// file.
func (w *UserFileWatcher) onWatchedPath(rel string) bool {
	for _, f := range w.files {
		if strings.HasPrefix(f.rel, rel+"/") {
			return true
		}
	}
	return false
}

// file returns the watched file at rel, or nil.
func (w *UserFileWatcher) file(rel string) *userFile {
	for i := range w.files {
		if w.files[i].rel == rel {
			return &w.files[i]
		}
	}
	return nil
}

// fromHost reports whether host process pid runs outside the container's
// cgroup, as Incus does for coi's file pushes. A process that is gone
// counts as in the container.
func (w *UserFileWatcher) fromHost(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf(procCgroupFmt, pid))
	if err != nil {
		return false
	}
	cg := string(data)
	return !strings.Contains(cg, "/lxc.payload."+w.containerName+"/") &&
		!strings.HasSuffix(strings.TrimSpace(cg), "/lxc.payload."+w.containerName) &&
		!strings.Contains(cg, "/lxc.payload/"+w.containerName+"/") &&
		!strings.HasSuffix(strings.TrimSpace(cg), "/lxc.payload/"+w.containerName)
}

// fire emits the HIGH threat for a write to f by host process pid.
func (w *UserFileWatcher) fire(f *userFile, pid int) {
	if w.onThreat == nil {
		return
	}
	(&FileWatcher{onThreat: w.onThreat}).fire(ThreatLevelHigh, f.category, f.title, f.desc, f.rel, "write", pid)
}

// readNameEvents polls the FAN_REPORT_DFID_NAME fanotify fd and decodes its
// events into evCh until ctx is cancelled.
func readNameEvents(ctx context.Context, ifd int, evCh chan<- fanNameEvent) {
	buf := make([]byte, 8192)
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
		if err != nil {
			continue
		}
		for _, ev := range parseNameEvents(buf[:nr]) {
			select {
			case evCh <- ev:
			default: // drop if buffer full rather than blocking
			}
		}
	}
}

// parseNameEvents decodes the events in buf, read from a
// FAN_REPORT_DFID_NAME group: event metadata (24 bytes), then info records.
// An event without a DFID_NAME record is skipped.
func parseNameEvents(buf []byte) []fanNameEvent {
	const metaLen = 24
	var events []fanNameEvent
	for pos := 0; pos+metaLen <= len(buf); {
		evLen := int(binary.NativeEndian.Uint32(buf[pos:]))
		if evLen < metaLen || pos+evLen > len(buf) {
			break
		}
		ev := buf[pos : pos+evLen]
		pos += evLen
		mask := binary.NativeEndian.Uint64(ev[8:])
		pid := int(binary.NativeEndian.Uint32(ev[20:]))
		for off := metaLen; off+4 <= len(ev); {
			infoType := ev[off]
			infoLen := int(binary.NativeEndian.Uint16(ev[off+2:]))
			if infoLen < 4 || off+infoLen > len(ev) {
				break
			}
			rec := ev[off : off+infoLen]
			off += infoLen
			// hdr (4), fsid (8), handle_bytes (4), handle_type (4), handle, name.
			if infoType != unix.FAN_EVENT_INFO_TYPE_DFID_NAME || len(rec) < 20 {
				continue
			}
			hlen := int(binary.NativeEndian.Uint32(rec[12:]))
			if 20+hlen > len(rec) {
				continue
			}
			var fsid [8]byte
			copy(fsid[:], rec[4:12])
			htype := int32(binary.NativeEndian.Uint32(rec[16:])) //nolint:gosec // handle_type is an int32
			name, _, _ := bytes.Cut(rec[20+hlen:], []byte{0})
			events = append(events, fanNameEvent{
				mask: mask,
				pid:  pid,
				dir:  newDirKey(fsid, htype, rec[20:20+hlen]),
				name: string(name),
			})
			break
		}
	}
	return events
}
