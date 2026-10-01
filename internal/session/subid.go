package session

import (
	"os"
	"strconv"
	"strings"
)

// subuidPath is the host file listing subordinate UID delegations. A package
// var so tests can point it at a fixture.
var subuidPath = "/etc/subuid"

// subuidRangeContaining reports the first ROOT-owned subordinate-UID range in
// `content` (the /etc/subuid format, one `owner:start:count` line each) that
// contains `uid` AND delegates more than a single ID. It returns the raw
// matching line.
//
// The count>1 restriction is deliberate and load-bearing (#838): Incus refuses
// `raw.idmap` for a host UID that lives inside a multi-ID delegation block (e.g.
// GCE Google OS Login UIDs falling inside `root:1000000:1000000000`), which is
// the bug. A DEDICATED size-1 delegation (`root:<uid>:1`, the technique Lima/CI
// use to make a specific host UID mappable) is the *working* case, so it must
// NOT be flagged — and its presence clears the UID even when a large root block
// also covers it, since adding exactly that line is the fix coi itself prints.
//
// Only root's lines count: incusd runs as root and allocates idmaps from root's
// delegations, so another user's range (e.g. `ubuntu:100000:65536`) covering
// the UID is irrelevant. This is a diagnostic aid only — the actual fail-fast
// is driven by the real `raw.idmap` set failure, never by this parse.
func subuidRangeContaining(uid int, content string) (line string, found bool) {
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
		if uid < start || uid >= start+count {
			continue
		}
		if count == 1 {
			return "", false // dedicated delegation: the UID is mappable
		}
		if !found {
			line, found = strings.TrimSpace(raw), true
		}
	}
	return line, found
}

// HostUIDSubordinateRange reports whether the current process's UID sits inside a
// multi-ID subordinate range in /etc/subuid, returning the offending line. This
// is the condition under which Incus rejects `raw.idmap` (#838). Best-effort: an
// unreadable /etc/subuid yields ("", false). Diagnostic use only — see
// subuidRangeContaining.
func HostUIDSubordinateRange() (line string, inRange bool) {
	data, err := os.ReadFile(subuidPath)
	if err != nil {
		return "", false
	}
	return subuidRangeContaining(os.Getuid(), string(data))
}
