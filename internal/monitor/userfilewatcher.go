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

// userFiles returns the persistence and credential files of the code user
// named user, whose creation, modification or replacement (rename over it)
// raises a threat: shell startup files, authorized_keys, the user crontab and
// the tool credential files coi copies (credentialPaths, relative to the
// home).
func userFiles(user string, credentialPaths []string) []monitoredFile {
	home := "home/" + user
	files := []monitoredFile{
		{
			rel: home + "/.ssh/authorized_keys", writeLevel: ThreatLevelHigh, category: "persistence",
			writeTitle: "User authorized_keys modified",
			writeDesc:  "A process wrote to the code user's authorized_keys, potentially adding a backdoor SSH key",
		},
		{
			rel: home + "/.bashrc", writeLevel: ThreatLevelHigh, category: "persistence",
			writeTitle: "User .bashrc modified",
			writeDesc:  "A process wrote to the code user's .bashrc, potentially adding persistent shell commands",
		},
		{
			rel: home + "/.profile", writeLevel: ThreatLevelHigh, category: "persistence",
			writeTitle: "User .profile modified",
			writeDesc:  "A process wrote to the code user's .profile, potentially adding persistent shell commands",
		},
		{
			rel: "var/spool/cron/crontabs/" + user, writeLevel: ThreatLevelHigh, category: "persistence",
			writeTitle: "User crontab modified",
			writeDesc:  "A process wrote to the code user's crontab, potentially adding a persistent scheduled task",
		},
	}
	for _, p := range credentialPaths {
		files = append(files, monitoredFile{
			rel: home + "/" + p, writeLevel: ThreatLevelHigh, category: "credential_access",
			writeTitle: "Tool credential file modified",
			writeDesc:  "A process in the container wrote to a tool credential file that coi copies in",
		})
	}
	return files
}

// fidKey identifies a file or directory by its filesystem id and file
// handle, as a FAN_REPORT_FID or FAN_REPORT_DFID_NAME record names it.
type fidKey string

// newFidKey builds the fidKey of a filesystem id and file handle.
func newFidKey(fsid [8]byte, handleType int32, handle []byte) fidKey {
	var b bytes.Buffer
	b.Write(fsid[:])
	_ = binary.Write(&b, binary.NativeEndian, handleType)
	b.Write(handle)
	return fidKey(b.String())
}

// fanFidEvent is a decoded event of a FAN_REPORT_DFID_NAME|FAN_REPORT_FID
// group: the object it is about, its directory and name in it (when the
// kernel reports them), and the host PID of the process that caused it.
type fanFidEvent struct {
	mask uint64
	pid  int
	obj  fidKey
	dir  fidKey
	name string
}

// UserFileWatcher watches the code user's persistence and credential files
// with a FAN_REPORT_DFID_NAME|FAN_REPORT_FID fanotify group. It marks the
// parent directories, so a file created after the mark pass or replaced by
// a rename is reported, and each existing file's inode, so a write through
// a hard link, a write on an fd held open and a truncate are reported too.
// Each event carries the PID of the writer. A write by a process outside
// the container (coi's own copy through Incus) is not flagged. Directories
// that do not exist yet are marked when created in a marked ancestor, and
// by the 30-second backstop. The 30-second boot grace period of FileWatcher
// applies too.
type UserFileWatcher struct {
	containerName string
	user          string
	files         []monitoredFile
	onThreat      func(ThreatEvent)
	onError       func(error)
}

// NewUserFileWatcher creates a UserFileWatcher for the files of the code
// user named user in containerName.
func NewUserFileWatcher(containerName, user string, credentialPaths []string, onThreat func(ThreatEvent), onError func(error)) *UserFileWatcher {
	return &UserFileWatcher{
		containerName: containerName,
		user:          user,
		files:         userFiles(user, credentialPaths),
		onThreat:      onThreat,
		onError:       onError,
	}
}

// userWatchState is what Run keeps between mark passes: the container's
// cgroup, the marked directories and files by key (their container-relative
// path), the grace period and when each file was last flagged for each PID.
type userWatchState struct {
	pid        int
	relCgroup  string // relative to /sys/fs/cgroup; "" counts every process in
	dirs       map[fidKey]string
	files      map[fidKey]string
	graceUntil time.Time
	flagged    map[string]time.Time
}

// refireAfter is how long a threat for one file and PID is not raised
// again: a process appending to a file causes a FAN_MODIFY per write.
var refireAfter = 10 * time.Second

// Run starts the watch loop and blocks until ctx is cancelled. Without
// fanotify FID events (kernel before 5.9, no CAP_SYS_ADMIN) it reports
// once via onError and returns.
func (w *UserFileWatcher) Run(ctx context.Context) {
	ifd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME|unix.FAN_REPORT_FID, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		if w.onError != nil {
			w.onError(fmt.Errorf("filewatcher: fanotify_init(FAN_REPORT_DFID_NAME|FAN_REPORT_FID): %w (user persistence and credential file monitoring disabled)", err))
		}
		return
	}
	defer unix.Close(ifd)

	st := newUserWatchState()
	if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
		w.resolveCgroup(ctx, pid, st)
		w.mark(ifd, pid, st)
	}

	evCh := make(chan fanFidEvent, 64)
	readCtx, stopReading := context.WithCancel(ctx)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		readFidEvents(readCtx, ifd, evCh)
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
			w.handle(ifd, ev, st)
		case <-backstop.C:
			if pid, _ := GetContainerInitPID(ctx, w.containerName); pid > 0 {
				w.resolveCgroup(ctx, pid, st)
				w.mark(ifd, pid, st)
			}
		}
	}
}

// resolveCgroup sets st.relCgroup for a new init PID (first pass,
// container restart). If it cannot be resolved, every process counts as in
// the container.
func (w *UserFileWatcher) resolveCgroup(ctx context.Context, pid int, st *userWatchState) {
	if pid == st.pid && st.relCgroup != "" {
		return
	}
	st.relCgroup, _ = containerRelCgroup(ctx, w.containerName)
}

// newUserWatchState returns an empty userWatchState.
func newUserWatchState() *userWatchState {
	return &userWatchState{
		dirs:    make(map[fidKey]string),
		files:   make(map[fidKey]string),
		flagged: make(map[string]time.Time),
	}
}

// handle raises the threat for one event on a marked file or in a marked
// directory, or marks a directory on a watched path that was just created.
func (w *UserFileWatcher) handle(ifd int, ev fanFidEvent, st *userWatchState) {
	if st.pid == 0 {
		return
	}
	if ev.mask&unix.FAN_Q_OVERFLOW != 0 {
		if w.onError != nil {
			w.onError(fmt.Errorf("filewatcher: user file event queue overflowed, writes may be missed"))
		}
		w.mark(ifd, st.pid, st)
		return
	}
	if rel, ok := st.files[ev.obj]; ok && ev.mask&unix.FAN_ONDIR == 0 && ev.mask&(unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
		w.flag(w.file(rel), ev.pid, st)
		return
	}
	dir, ok := st.dirs[ev.dir]
	if !ok {
		return
	}
	rel := path.Join(dir, ev.name)
	if ev.mask&unix.FAN_ONDIR != 0 {
		if !w.onWatchedPath(rel) {
			return
		}
		// A directory renamed into place brings its files with no event of
		// their own.
		w.mark(ifd, st.pid, st)
		for i := range w.files {
			f := &w.files[i]
			if strings.HasPrefix(f.rel, rel+"/") && w.exists(st.pid, f.rel) {
				w.flag(f, ev.pid, st)
			}
		}
		return
	}
	f := w.file(rel)
	if f == nil {
		return
	}
	// A new inode at a watched path: mark it, so later writes to it are
	// seen through any path.
	if ev.mask&(unix.FAN_CREATE|unix.FAN_MOVED_TO) != 0 {
		w.mark(ifd, st.pid, st)
	}
	// A new regular file is flagged by the FAN_CLOSE_WRITE of its creator
	// (fanotify may merge both into one event); a symlink or hard link is
	// written through another path.
	if ev.mask&(unix.FAN_CLOSE_WRITE|unix.FAN_MOVED_TO) == 0 && w.newRegularFile(st.pid, f.rel) {
		return
	}
	w.flag(f, ev.pid, st)
}

// flag raises the threat for a write to f by host process pid, unless it
// is in the grace period, from a process outside the container, or raised
// for f and pid in the last refireAfter.
func (w *UserFileWatcher) flag(f *monitoredFile, pid int, st *userWatchState) {
	now := time.Now()
	if f == nil || now.Before(st.graceUntil) || fromHost(pid, st.relCgroup) {
		return
	}
	key := fmt.Sprintf("%s\x00%d", f.rel, pid)
	if last, ok := st.flagged[key]; ok && now.Sub(last) < refireAfter {
		return
	}
	if len(st.flagged) > 1024 {
		for k, t := range st.flagged {
			if now.Sub(t) >= refireAfter {
				delete(st.flagged, k)
			}
		}
	}
	st.flagged[key] = now
	w.fire(f, pid)
}

// exists reports whether rel exists (not followed) in the container whose
// init PID is pid.
func (w *UserFileWatcher) exists(pid int, rel string) bool {
	var stat unix.Stat_t
	return unix.Lstat(fmt.Sprintf(procRootFmt+"/%s", pid, rel), &stat) == nil
}

// newRegularFile reports whether rel in the container whose init PID is pid
// is a regular file with one link.
func (w *UserFileWatcher) newRegularFile(pid int, rel string) bool {
	var stat unix.Stat_t
	if err := unix.Lstat(fmt.Sprintf(procRootFmt+"/%s", pid, rel), &stat); err != nil {
		return false
	}
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
}

// mark marks every existing directory on a watched path and every existing
// watched file in the container whose init PID is pid, and replaces
// st.dirs and st.files. A new PID (first pass, container restart) starts
// the grace period.
func (w *UserFileWatcher) mark(ifd, pid int, st *userWatchState) {
	if pid != st.pid {
		st.pid = pid
		st.graceUntil = time.Now().Add(30 * time.Second)
	}
	const flags = unix.FAN_MARK_ADD | unix.FAN_MARK_DONT_FOLLOW
	dirs := make(map[fidKey]string)
	for _, rel := range w.watchedDirs() {
		mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_MOVED_TO | unix.FAN_CREATE | unix.FAN_ONDIR | unix.FAN_EVENT_ON_CHILD)
		if key, ok := markPath(ifd, flags|unix.FAN_MARK_ONLYDIR, mask, fmt.Sprintf(procRootFmt+"/%s", pid, rel)); ok {
			dirs[key] = rel
		}
	}
	files := make(map[fidKey]string)
	for _, f := range w.files {
		mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
		if key, ok := markPath(ifd, flags, mask, fmt.Sprintf(procRootFmt+"/%s", pid, f.rel)); ok {
			files[key] = f.rel
		}
	}
	st.dirs, st.files = dirs, files
}

// markPath marks p (not followed) with mask and returns its fidKey. ok is
// false when p does not exist yet: it is marked once created.
func markPath(ifd int, flags uint, mask uint64, p string) (key fidKey, ok bool) {
	if err := unix.FanotifyMark(ifd, flags, mask, unix.AT_FDCWD, p); err != nil {
		return "", false
	}
	key, err := fidKeyOf(p)
	return key, err == nil
}

// procRootFmt is the host path of a process's root directory; tests point
// it at a temp dir.
var procRootFmt = "/proc/%d/root"

// procCgroupFmt is the host path of a process's cgroup file; tests point it
// at a temp dir.
var procCgroupFmt = "/proc/%d/cgroup"

// fidKeyOf returns the fidKey fanotify reports for p (not followed).
func fidKeyOf(p string) (fidKey, error) {
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
	return newFidKey(fsid, fh.Type(), fh.Bytes()), nil
}

// watchedDirs returns every directory on the path of a watched file, from
// the home (or /var/spool, for the crontab) down, without duplicates. The
// parents are marked so a missing directory is marked when created.
func (w *UserFileWatcher) watchedDirs() []string {
	home := "home/" + w.user
	seen := make(map[string]bool)
	var dirs []string
	for _, f := range w.files {
		top := home
		if !strings.HasPrefix(f.rel, home+"/") {
			top = "var/spool"
		}
		for d := path.Dir(f.rel); d != "." && d != "/"; d = path.Dir(d) {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
			if d == top || !strings.HasPrefix(d, top+"/") {
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
func (w *UserFileWatcher) file(rel string) *monitoredFile {
	for i := range w.files {
		if w.files[i].rel == rel {
			return &w.files[i]
		}
	}
	return nil
}

// fromHost reports whether host process pid runs outside the container's
// cgroup subtree relCgroup, as Incus does for coi's file pushes. A process
// that is gone counts as in the container.
func fromHost(pid int, relCgroup string) bool {
	data, err := os.ReadFile(fmt.Sprintf(procCgroupFmt, pid))
	if err != nil {
		return false
	}
	return !processBelongsToContainerCgroup(string(data), relCgroup)
}

// fire emits the threat for a write to f by host process pid.
func (w *UserFileWatcher) fire(f *monitoredFile, pid int) {
	if w.onThreat == nil {
		return
	}
	w.onThreat(sensitiveFileThreat(f.writeLevel, f.category, f.writeTitle, f.writeDesc, f.rel, "write", pid))
}

// readFidEvents polls the fanotify fd and decodes its events into evCh
// until ctx is cancelled. It blocks on a full evCh: a dropped event could
// be the one write that matters.
func readFidEvents(ctx context.Context, ifd int, evCh chan<- fanFidEvent) {
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
		for _, ev := range parseFidEvents(buf[:nr]) {
			select {
			case evCh <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// parseFidEvents decodes the events in buf, read from a
// FAN_REPORT_DFID_NAME|FAN_REPORT_FID group: event metadata (24 bytes),
// then info records. A record is hdr (4), fsid (8), handle_bytes (4),
// handle_type (4), handle, and for DFID_NAME a NUL-terminated name.
func parseFidEvents(buf []byte) []fanFidEvent {
	const metaLen = 24
	var events []fanFidEvent
	for pos := 0; pos+metaLen <= len(buf); {
		evLen := int(binary.NativeEndian.Uint32(buf[pos:]))
		if evLen < metaLen || pos+evLen > len(buf) {
			break
		}
		mask := binary.NativeEndian.Uint64(buf[pos+8:])
		pid := int(binary.NativeEndian.Uint32(buf[pos+20:]))
		raw := buf[pos : pos+evLen]
		pos += evLen
		ev := fanFidEvent{mask: mask, pid: pid}
		for off := metaLen; off+4 <= len(raw); {
			infoType := raw[off]
			infoLen := int(binary.NativeEndian.Uint16(raw[off+2:]))
			if infoLen < 4 || off+infoLen > len(raw) {
				break
			}
			rec := raw[off : off+infoLen]
			off += infoLen
			if len(rec) < 20 {
				continue
			}
			hlen := int(binary.NativeEndian.Uint32(rec[12:]))
			if 20+hlen > len(rec) {
				continue
			}
			var fsid [8]byte
			copy(fsid[:], rec[4:12])
			htype := int32(binary.NativeEndian.Uint32(rec[16:])) //nolint:gosec // handle_type is an int32
			key := newFidKey(fsid, htype, rec[20:20+hlen])
			switch infoType {
			case unix.FAN_EVENT_INFO_TYPE_FID:
				ev.obj = key
			case unix.FAN_EVENT_INFO_TYPE_DFID_NAME:
				name, _, _ := bytes.Cut(rec[20+hlen:], []byte{0})
				ev.dir, ev.name = key, string(name)
			}
		}
		events = append(events, ev)
	}
	return events
}
