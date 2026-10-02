package session

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// subuidPath / subgidPath are the host files listing subordinate ID
// delegations. Package vars so tests can point them at fixtures.
var (
	subuidPath = "/etc/subuid"
	subgidPath = "/etc/subgid"
)

// incusdStartTime reports when the running Incus daemon started (false if it
// can't be found). A package var so tests can stub it.
var incusdStartTime = findIncusdStartTime

// rootDelegation scans `content` (the /etc/subuid or /etc/subgid format, one
// `owner:start:count` line each) for ROOT-owned delegations covering `id`. It
// returns the first multi-ID range containing it (bigLine, "" if none) and
// whether a DEDICATED size-1 delegation for exactly that id exists.
//
// Only root's lines count: incusd runs as root and allocates idmaps from root's
// delegations, so another user's range (e.g. `ubuntu:100000:65536`) covering
// the id is irrelevant.
func rootDelegation(id int, content string) (bigLine string, dedicated bool) {
	for _, raw := range strings.Split(content, "\n") {
		fields := strings.Split(strings.TrimSpace(raw), ":")
		if len(fields) != 3 {
			continue
		}
		if owner := strings.TrimSpace(fields[0]); owner != "root" && owner != "0" {
			continue
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(fields[1]))
		count, err2 := strconv.Atoi(strings.TrimSpace(fields[2]))
		if err1 != nil || err2 != nil || count < 1 {
			continue
		}
		if id < start || id >= start+count {
			continue
		}
		if count == 1 {
			dedicated = true
		} else if bigLine == "" {
			bigLine = strings.TrimSpace(raw)
		}
	}
	return bigLine, dedicated
}

// subuidRangeContaining reports the first root-owned multi-ID range in an
// /etc/subuid `content` that contains `uid`, unless a dedicated `root:<uid>:1`
// delegation also exists.
//
// The count>1 restriction is deliberate and load-bearing (#838): Incus refuses
// `raw.idmap` for a host UID that lives inside a multi-ID delegation block (e.g.
// GCE Google OS Login UIDs falling inside `root:1000000:1000000000`), which is
// the bug. A DEDICATED size-1 delegation (`root:<uid>:1`, the technique Lima/CI
// use to make a specific host UID mappable) is the *working* case. This file-
// only view is what the parse tests pin; HostUIDSubordinateRange adds the
// /etc/subgid and Incus-restart conditions the fix also needs.
func subuidRangeContaining(uid int, content string) (line string, found bool) {
	big, dedicated := rootDelegation(uid, content)
	if big == "" || dedicated {
		return "", false
	}
	return big, true
}

// HostUIDSubordinateRange reports whether the current process's UID sits inside a
// root multi-ID subordinate range in /etc/subuid, returning the offending line.
// This is the condition under which Incus rejects `raw.idmap` (#838).
//
// A dedicated `root:<uid>:1` delegation clears it only once the whole fix coi
// prints is in effect: the line in BOTH /etc/subuid and /etc/subgid (raw.idmap
// is "both <uid> ..."), and Incus restarted since (it reads the files at
// start). Until then the UID stays flagged and the returned line says what is
// still missing, so the probes keep skipping with actionable guidance instead
// of failing with a cryptic forkmount error.
//
// Best-effort: an unreadable /etc/subuid yields ("", false). Diagnostic use only
// — the actual fail-fast is driven by the real `raw.idmap` set failure.
func HostUIDSubordinateRange() (line string, inRange bool) {
	data, err := os.ReadFile(subuidPath)
	if err != nil {
		return "", false
	}
	uid := os.Getuid()
	big, dedicated := rootDelegation(uid, string(data))
	if big == "" {
		return "", false
	}
	if !dedicated {
		return big, true
	}
	gidData, _ := os.ReadFile(subgidPath)
	if _, gidDedicated := rootDelegation(uid, string(gidData)); !gidDedicated {
		return fmt.Sprintf("%s (root:%d:1 is in /etc/subuid but missing from /etc/subgid)", big, uid), true
	}
	// +1s: btime is whole seconds, so the computed start can be up to a second
	// early; an edit made in the same second as the restart must not read as
	// "after" it.
	if started, ok := incusdStartTime(); ok && modifiedAfter(started.Add(time.Second), subuidPath, subgidPath) {
		return fmt.Sprintf("%s (root:%d:1 added, but Incus hasn't been restarted since: sudo systemctl restart incus)", big, uid), true
	}
	return "", false
}

// modifiedAfter reports whether any of paths was modified after t.
func modifiedAfter(t time.Time, paths ...string) bool {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.ModTime().After(t) {
			return true
		}
	}
	return false
}

// findIncusdStartTime locates the running Incus daemon in /proc and returns
// its start time. ok=false when none is visible (e.g. Incus runs in a VM).
func findIncusdStartTime() (time.Time, bool) { return incusdStartTimeIn("/proc") }

// incusdStartTimeIn is findIncusdStartTime over a given proc root (tests use a
// fixture). The start time is boot time (<root>/stat btime) plus the process
// start in clock ticks (<root>/<pid>/stat field 22, USER_HZ=100 on Linux).
//
// Only the DAEMON counts. Container monitors and helpers carry the comm
// "incusd" too ("[lxc monitor] ..." after setproctitle, "incusd forkproxy",
// "incusd forkstart"), and monitors survive `systemctl restart incus` — an
// old monitor would make a restarted Incus look stale. So argv[0] must be
// incusd and argv[1], if any, a flag, not a fork* subcommand. An incusd
// inside a container (nested PID namespace) is skipped too: the host's /proc
// lists it, and /proc is scanned in name order, not numeric order.
func incusdStartTimeIn(root string) (time.Time, bool) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return time.Time{}, false
	}
	btime := procBootTime(root)
	if btime.IsZero() {
		return time.Time{}, false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := root + "/" + e.Name()
		if !isIncusDaemonCmdline(dir+"/cmdline") || inNestedPIDNamespace(dir+"/status") {
			continue
		}
		stat, err := os.ReadFile(dir + "/stat")
		if err != nil {
			continue
		}
		// "<pid> (<comm>) <state> ..." — comm may contain spaces, so split
		// after the last ')'.
		st := string(stat)
		closeIdx := strings.LastIndexByte(st, ')')
		if closeIdx < 0 {
			continue
		}
		fields := strings.Fields(st[closeIdx+1:])
		if len(fields) < 20 { // starttime is field 22 overall = index 19 here
			continue
		}
		ticks, err := strconv.ParseInt(fields[19], 10, 64)
		if err != nil {
			continue
		}
		const userHZ = 100
		return btime.Add(time.Duration(ticks) * time.Second / userHZ), true
	}
	return time.Time{}, false
}

// inNestedPIDNamespace reports whether the process whose status file is at
// path lives in a nested PID namespace — e.g. an incusd running inside a
// container, which the host's /proc also lists and which would otherwise be
// mistaken for the host daemon. The "NSpid:" line (Linux 4.1+) lists the
// process's PID at each namespace level; more than one means nested. An
// unreadable file or missing line counts as not nested.
func inNestedPIDNamespace(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "NSpid:"); ok {
			return len(strings.Fields(rest)) > 1
		}
	}
	return false
}

// isIncusDaemonCmdline reports whether the NUL-separated cmdline at path is
// the Incus daemon itself (see incusdStartTimeIn).
func isIncusDaemonCmdline(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	argv := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	if base := argv[0][strings.LastIndexByte(argv[0], '/')+1:]; base != "incusd" {
		return false
	}
	return len(argv) == 1 || strings.HasPrefix(argv[1], "-")
}

// procBootTime reads the system boot time from <root>/stat ("btime <unix>").
func procBootTime(root string) time.Time {
	data, err := os.ReadFile(root + "/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "btime" {
			if sec, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}
