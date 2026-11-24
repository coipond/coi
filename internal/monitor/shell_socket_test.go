package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const tcpTableHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// fakeSocketProc points the socket check at an empty fake /proc tree and fails
// the test on an unexpected incus exec fallback.
func fakeSocketProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldLinks := procRoot, readContainerFDLinks
	t.Cleanup(func() { procRoot, readContainerFDLinks = oldRoot, oldLinks })
	procRoot = root
	readContainerFDLinks = func(context.Context, string, []string) (map[string]string, error) {
		t.Fatal("unexpected incus exec fallback")
		return nil, nil
	}
	return root
}

// fakeTCPTables gives host pid's network namespace TCP sockets of the given
// inodes in /proc/<pid>/net/tcp and tcp6.
func fakeTCPTables(t *testing.T, root string, pid int, tcp4, tcp6 []uint64) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid), "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, inodes := range map[string][]uint64{"tcp": tcp4, "tcp6": tcp6} {
		table := tcpTableHeader
		for n, inode := range inodes {
			table += fmt.Sprintf("   %d: 0100007F:1F90 0100007F:115B 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 20 4 30 10 -1\n", n, inode)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeFDs gives host pid the fd 0 and fd 1 link targets in root.
func fakeFDs(t *testing.T, root string, pid int, fd0, fd1 string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid), "fd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for fd, target := range []string{fd0, fd1} {
		if err := os.Symlink(target, filepath.Join(dir, fmt.Sprint(fd))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMarkSocketShells(t *testing.T) {
	root := fakeSocketProc(t)
	container := []uint64{4242}
	for pid := 10; pid <= 16; pid++ {
		fakeTCPTables(t, root, pid, container, []uint64{6666})
	}
	fakeTCPTables(t, root, 17, []uint64{5151}, nil)        // nested netns
	fakeFDs(t, root, 10, "socket:[4242]", "socket:[4242]") // sh on the TCP socket
	fakeFDs(t, root, 11, "/dev/pts/0", "/dev/pts/0")       // interactive shell
	fakeFDs(t, root, 12, "pipe:[77]", "socket:[4242]")     // stdout only
	fakeFDs(t, root, 13, "socket:[4242]", "socket:[4242]") // not a shell
	fakeFDs(t, root, 14, "socket:[999]", "socket:[999]")   // unix socket, not TCP
	fakeFDs(t, root, 15, "socket:[4242]", "pipe:[1]")      // busybox sh, stdin only
	fakeFDs(t, root, 16, "socket:[6666]", "socket:[6666]") // tcp6 socket
	fakeFDs(t, root, 17, "socket:[5151]", "socket:[5151]") // socket of its own netns

	procs := []Process{
		{PID: 10, Name: "sh", Command: "sh"},
		{PID: 11, Name: "bash", Command: "bash"},
		{PID: 12, Name: "dash", Command: "dash"},
		{PID: 13, Name: "sleep", Command: "sleep 30"},
		{PID: 14, Name: "zsh", Command: "zsh"},
		{PID: 15, Name: "busybox", Command: "busybox sh"},
		{PID: 16, Name: "bash", Command: "bash"},
		{PID: 17, Name: "sh", Command: "sh"},
	}
	markSocketShells(t.Context(), "c", procs)

	want := map[int]bool{10: true, 12: true, 15: true, 16: true, 17: true}
	for _, p := range procs {
		if p.StdioTCPSocket != want[p.PID] {
			t.Errorf("PID %d (%s): StdioTCPSocket = %v, want %v", p.PID, p.Command, p.StdioTCPSocket, want[p.PID])
		}
	}
}

func TestMarkSocketShellsFallsBackToContainerWhenHostDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 directory")
	}
	root := fakeSocketProc(t)
	// 20: TCP socket on fd 0; 21: unix socket (e.g. journald) on fd 1.
	for pid, nsPID := range map[int]int{20: 7, 21: 8} {
		fakeTCPTables(t, root, pid, []uint64{4242}, nil)
		fakeFDs(t, root, pid, "pipe:[1]", "pipe:[1]")
		status := fmt.Sprintf("Name:\tsh\nNSpid:\t%d\t%d\n", pid, nsPID)
		if err := os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "status"), []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		fdDir := filepath.Join(root, fmt.Sprint(pid), "fd")
		if err := os.Chmod(fdDir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })
	}

	var asked []string
	readContainerFDLinks = func(_ context.Context, name string, paths []string) (map[string]string, error) {
		if name != "c" {
			t.Errorf("container = %q, want c", name)
		}
		asked = paths
		return parseFDLinks("/proc/7/fd/0 socket:[4242]\n/proc/8/fd/1 socket:[999]\n"), nil
	}

	procs := []Process{{PID: 20, Name: "sh", Command: "sh"}, {PID: 21, Name: "sh", Command: "sh"}}
	markSocketShells(t.Context(), "c", procs)

	if len(asked) != 4 {
		t.Errorf("fallback paths = %v, want fd 0 and 1 of PIDs 7 and 8", asked)
	}
	if !procs[0].StdioTCPSocket {
		t.Error("shell on a TCP socket not marked through the container fallback")
	}
	if procs[1].StdioTCPSocket {
		t.Error("shell on a unix socket marked through the container fallback")
	}
}

func TestMarkSocketShellsIgnoresShellsWithoutSocket(t *testing.T) {
	root := fakeSocketProc(t)
	fakeTCPTables(t, root, 11, []uint64{4242}, nil)
	fakeFDs(t, root, 11, "/dev/pts/0", "pipe:[1]")
	procs := []Process{
		{PID: 13, Name: "sleep", Command: "sleep 1"},
		{PID: 11, Name: "bash", Command: "bash"},
	}
	markSocketShells(t.Context(), "c", procs)
	for _, p := range procs {
		if p.StdioTCPSocket {
			t.Errorf("PID %d marked without a socket", p.PID)
		}
	}
}

func TestMarkSocketShellsReadsTablesOncePerNetns(t *testing.T) {
	root := fakeSocketProc(t)
	fakeTCPTables(t, root, 30, []uint64{4242}, nil)
	fakeTCPTables(t, root, 32, []uint64{5151}, nil) // nested netns
	// 31 shares 30's netns: same /proc/<pid>/net.
	if err := os.MkdirAll(filepath.Join(root, "31"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "30", "net"), filepath.Join(root, "31", "net")); err != nil {
		t.Fatal(err)
	}
	fakeFDs(t, root, 30, "socket:[4242]", "socket:[4242]")
	fakeFDs(t, root, 31, "socket:[999]", "socket:[4242]")
	fakeFDs(t, root, 32, "socket:[5151]", "pipe:[1]")

	reads := map[int]int{}
	readTCPInodes = func(pid int) map[uint64]bool { reads[pid]++; return tcpSocketInodes(pid) }
	t.Cleanup(func() { readTCPInodes = tcpSocketInodes })

	procs := []Process{
		{PID: 30, Name: "sh", Command: "sh"},
		{PID: 31, Name: "bash", Command: "bash"},
		{PID: 32, Name: "sh", Command: "sh"},
	}
	markSocketShells(t.Context(), "c", procs)

	for _, p := range procs {
		if !p.StdioTCPSocket {
			t.Errorf("PID %d not marked", p.PID)
		}
	}
	if reads[30]+reads[31] != 1 || reads[32] != 1 {
		t.Errorf("table reads per pid = %v, want one for the netns of 30/31 and one for 32", reads)
	}
}

func TestSocketInode(t *testing.T) {
	cases := map[string]uint64{
		"socket:[4242]": 4242,
		"pipe:[4242]":   0,
		"/dev/pts/0":    0,
		"socket:[x]":    0,
	}
	for link, want := range cases {
		if got := socketInode(link); got != want {
			t.Errorf("socketInode(%q) = %d, want %d", link, got, want)
		}
	}
}

func TestDetectReverseShellsFlagsSocketShell(t *testing.T) {
	threats := DetectReverseShells([]Process{
		{PID: 1, Command: "sh", Name: "sh", StdioTCPSocket: true},
		{PID: 2, Command: "sh", Name: "sh"},
	})
	if len(threats) != 1 || threats[0].PID != 1 {
		t.Fatalf("threats = %+v, want one for PID 1", threats)
	}
	if threats[0].Pattern != stdioTCPSocketPattern || threats[0].Class != ReverseShellClassStrong {
		t.Errorf("threat = %+v, want strong %q", threats[0], stdioTCPSocketPattern)
	}
}

func TestSocketShellIsCriticalWhateverTheOneLinerPolicy(t *testing.T) {
	// The command line also matches the python one-liner pattern.
	shell := Process{PID: 1, Name: "bash", Command: "bash -c python3 -c 'print(1)' # tcp", StdioTCPSocket: true}
	for _, policy := range []string{"critical", "warn", "off"} {
		d := NewDetector(0, 0).WithReverseShellOneLinerPolicy(policy)
		events := d.Analyze(MonitorSnapshot{Processes: ProcessStats{Available: true, Processes: []Process{shell}}})
		if len(events) != 1 || events[0].Level != ThreatLevelCritical {
			t.Errorf("policy %q: events = %+v, want one critical", policy, events)
		}
	}

	// A strong argv match keeps its own pattern.
	threats := DetectReverseShells([]Process{{PID: 2, Name: "bash", Command: "bash -i", StdioTCPSocket: true}})
	if len(threats) != 1 || threats[0].Pattern != "bash -i" {
		t.Errorf("threats = %+v, want one with pattern bash -i", threats)
	}
}
