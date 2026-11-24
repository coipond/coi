package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const tcpTableHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// fakeSocketProc builds a /proc tree with init PID 1 owning a TCP socket of
// inode 4242 and points the socket check at it.
func fakeSocketProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "1", "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := tcpTableHeader +
		"   0: 0100007F:1F90 0100007F:115B 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1\n"
	if err := os.WriteFile(filepath.Join(root, "1", "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "1", "net", "tcp6"), []byte(tcpTableHeader), 0o644); err != nil {
		t.Fatal(err)
	}

	oldRoot, oldInit, oldLinks := procRoot, socketCheckInitPID, readContainerFDLinks
	t.Cleanup(func() { procRoot, socketCheckInitPID, readContainerFDLinks = oldRoot, oldInit, oldLinks })
	procRoot = root
	socketCheckInitPID = func(context.Context, string) (int, error) { return 1, nil }
	readContainerFDLinks = func(context.Context, string, []string) (map[string]string, error) {
		t.Fatal("unexpected incus exec fallback")
		return nil, nil
	}
	return root
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
	fakeFDs(t, root, 10, "socket:[4242]", "socket:[4242]") // sh on the TCP socket
	fakeFDs(t, root, 11, "/dev/pts/0", "/dev/pts/0")       // interactive shell
	fakeFDs(t, root, 12, "pipe:[77]", "socket:[4242]")     // stdout only
	fakeFDs(t, root, 13, "socket:[4242]", "socket:[4242]") // not a shell
	fakeFDs(t, root, 14, "socket:[999]", "socket:[999]")   // unix socket, not TCP
	fakeFDs(t, root, 15, "socket:[4242]", "pipe:[1]")      // busybox sh, stdin only

	procs := []Process{
		{PID: 10, Name: "sh", Command: "sh"},
		{PID: 11, Name: "bash", Command: "bash"},
		{PID: 12, Name: "dash", Command: "dash"},
		{PID: 13, Name: "sleep", Command: "sleep 30"},
		{PID: 14, Name: "zsh", Command: "zsh"},
		{PID: 15, Name: "busybox", Command: "busybox sh"},
	}
	markSocketShells(t.Context(), "c", procs)

	want := map[int]bool{10: true, 12: true, 15: true}
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
	fakeFDs(t, root, 20, "socket:[4242]", "socket:[4242]")
	if err := os.WriteFile(filepath.Join(root, "20", "status"), []byte("Name:\tsh\nNSpid:\t20\t7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fdDir := filepath.Join(root, "20", "fd")
	if err := os.Chmod(fdDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) })

	var asked []string
	readContainerFDLinks = func(_ context.Context, name string, paths []string) (map[string]string, error) {
		if name != "c" {
			t.Errorf("container = %q, want c", name)
		}
		asked = paths
		return parseFDLinks("/proc/7/fd/0 socket:[4242]\n"), nil
	}

	procs := []Process{{PID: 20, Name: "sh", Command: "sh"}}
	markSocketShells(t.Context(), "c", procs)

	if len(asked) != 2 {
		t.Errorf("fallback paths = %v, want /proc/7/fd/0 and /proc/7/fd/1", asked)
	}
	if !procs[0].StdioTCPSocket {
		t.Error("shell on a TCP socket not marked through the container fallback")
	}
}

func TestMarkSocketShellsSkipsWithoutShellsOrSockets(t *testing.T) {
	root := fakeSocketProc(t)
	calls := 0
	socketCheckInitPID = func(context.Context, string) (int, error) { calls++; return 1, nil }
	fakeFDs(t, root, 11, "/dev/pts/0", "pipe:[1]")
	markSocketShells(t.Context(), "c", []Process{
		{PID: 13, Name: "sleep", Command: "sleep 1"},
		{PID: 11, Name: "bash", Command: "bash"},
	})
	if calls != 0 {
		t.Errorf("TCP tables read %d times without a shell on a socket, want 0", calls)
	}

	if err := os.WriteFile(filepath.Join(root, "1", "net", "tcp"), []byte(tcpTableHeader), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeFDs(t, root, 10, "socket:[4242]", "socket:[4242]")
	procs := []Process{{PID: 10, Name: "sh", Command: "sh"}}
	markSocketShells(t.Context(), "c", procs)
	if procs[0].StdioTCPSocket {
		t.Error("shell marked although the container has no TCP socket")
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

	d := NewDetector(0, 0)
	events := d.Analyze(MonitorSnapshot{Processes: ProcessStats{Available: true, Processes: []Process{
		{PID: 1, Command: "sh", Name: "sh", StdioTCPSocket: true},
	}}})
	if len(events) != 1 || events[0].Level != ThreatLevelCritical {
		t.Errorf("events = %+v, want one critical", events)
	}
}
