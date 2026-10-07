package container

import (
	"strings"
	"testing"
)

// The start log of a container whose start aborted on a disk device mount (a
// real failure: the git-identity source was replaced while the container
// started).
const abortedStartLog = `Name: coi-8361c8eb-1
Status: STOPPED
Type: container

Log (lxc.log):

lxc coi-8361c8eb-1 20261006165650.603 ERROR    utils - ../src/lxc/utils.c:safe_mount:1332 - No such file or directory - Failed to mount "/var/lib/incus/devices/coi-8361c8eb-1/disk.git--identity.home-code-.gitconfig" onto "/opt/incus/lib/lxc/rootfs/home/code/.gitconfig"
lxc coi-8361c8eb-1 20261006165650.603 ERROR    conf - ../src/lxc/conf.c:lxc_setup:3820 - Failed to setup mount entries
lxc coi-8361c8eb-1 20261006165650.610 WARN     network - ../src/lxc/network.c:lxc_delete_network_priv:3940 - Failed to restore altnames
lxc coi-8361c8eb-1 20261006165650.610 ERROR    lxccontainer - ../src/lxc/lxccontainer.c:wait_on_daemonized_start:837 - Received container state "ABORTING" instead of "RUNNING"
`

func TestParseStartLogErrors(t *testing.T) {
	got := parseStartLogErrors(abortedStartLog, 0)
	if len(got) != 3 {
		t.Fatalf("got %d ERROR lines, want 3 (WARN skipped): %q", len(got), got)
	}
	if !strings.HasPrefix(got[0], "ERROR utils - ") || !strings.Contains(got[0], "Failed to mount") {
		t.Errorf("first line should be the cause, from the level on: %q", got[0])
	}
	if strings.Contains(got[1], "  ") {
		t.Errorf("runs of spaces should be collapsed: %q", got[1])
	}
}

// The cause comes first, so a cap keeps the first lines.
func TestParseStartLogErrors_KeepsFirstLines(t *testing.T) {
	got := parseStartLogErrors(abortedStartLog, 1)
	if len(got) != 1 || !strings.Contains(got[0], "Failed to mount") {
		t.Errorf("capped output must keep the cause: %q", got)
	}
}

func TestParseStartLogErrors_NoLog(t *testing.T) {
	if got := parseStartLogErrors("Name: c1\nStatus: RUNNING\n", 5); got != nil {
		t.Errorf("no log section must yield nil, got %q", got)
	}
}
