package monitor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/coipond/coi/internal/container"
)

// procRoot is the /proc the monitor reads host-side (sockets, network tables,
// cgroups of host PIDs); tests point it at a fake tree.
var procRoot = "/proc"

// fdScanTimeout bounds the incus exec fallback of the socket check: the
// collector waits for every source, so a hung exec would stall detection.
var fdScanTimeout = 5 * time.Second

// readContainerFDLinks resolves fd links from inside the container when the
// host may not read them (no CAP_SYS_PTRACE over the container's uids). It
// takes container-side paths and returns their link targets. It runs the
// container's own sh and find, so root in the container can blind it; the
// host-side argv patterns do not depend on it.
var readContainerFDLinks = readContainerFDLinksViaIncus

// markSocketShells sets StdioTCPSocket on every shell in processes whose fd 0
// or fd 1 is a TCP socket (an inode in the /proc/<pid>/net/tcp or tcp6 of the
// shell itself, so a shell in a nested network namespace counts too). Host
// /proc is read first; fds the host may not read are resolved with one incus
// exec. TCP tables are read only for shells with a socket on fd 0 or fd 1.
// Errors leave the processes unmarked: argv matching still runs.
func markSocketShells(ctx context.Context, containerName string, processes []Process) {
	sockets := map[int][]uint64{} // index in processes -> socket inodes on fd 0/1
	denied := map[string]int{}    // container-side fd path -> index in processes
	for i := range processes {
		if !isShellProcess(processes[i], strings.ToLower(processes[i].Command)) {
			continue
		}
		for _, fd := range []int{0, 1} {
			link, err := os.Readlink(fmt.Sprintf("%s/%d/fd/%d", procRoot, processes[i].PID, fd))
			if err == nil {
				if inode := socketInode(link); inode != 0 {
					sockets[i] = append(sockets[i], inode)
				}
				continue
			}
			if !errors.Is(err, fs.ErrPermission) {
				continue
			}
			if nsPID := containerPID(processes[i].PID); nsPID > 0 {
				denied[fmt.Sprintf("/proc/%d/fd/%d", nsPID, fd)] = i
			}
		}
	}

	if len(denied) > 0 {
		paths := make([]string, 0, len(denied))
		for p := range denied {
			paths = append(paths, p)
		}
		if links, err := readContainerFDLinks(ctx, containerName, paths); err == nil {
			for p, link := range links {
				if i, ok := denied[p]; ok {
					if inode := socketInode(link); inode != 0 {
						sockets[i] = append(sockets[i], inode)
					}
				}
			}
		}
	}

	byNetns := map[uint64]map[uint64]bool{} // netns key -> TCP socket inodes
	for i, fdInodes := range sockets {
		key, ok := netnsKey(processes[i].PID)
		inodes := byNetns[key]
		if !ok || inodes == nil {
			inodes = readTCPInodes(processes[i].PID)
			if ok {
				byNetns[key] = inodes
			}
		}
		for _, inode := range fdInodes {
			if inodes[inode] {
				processes[i].StdioTCPSocket = true
			}
		}
	}
}

// readTCPInodes reads the TCP socket inodes of a pid's netns; tests count
// calls.
var readTCPInodes = tcpSocketInodes

// netnsKey identifies the network namespace of host pid without ptrace
// rights: /proc/<pid>/net/tcp has one inode per namespace.
func netnsKey(pid int) (uint64, bool) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("%s/%d/net/tcp", procRoot, pid), &st); err != nil {
		return 0, false
	}
	return st.Ino, true
}

// tcpSocketInodes returns the socket inodes in the TCP tables of the network
// namespace of host pid (/proc/<pid>/net is readable without ptrace rights).
func tcpSocketInodes(pid int) map[uint64]bool {
	inodes := map[uint64]bool{}
	for _, table := range []string{"tcp", "tcp6"} {
		conns, _ := parseProcNetTCP(fmt.Sprintf("%s/%d/net/%s", procRoot, pid, table), table)
		for _, c := range conns {
			if c.Inode != 0 {
				inodes[c.Inode] = true
			}
		}
	}
	return inodes
}

// socketInode returns N from an fd link "socket:[N]", or 0.
func socketInode(link string) uint64 {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
	if err != nil {
		return 0
	}
	return inode
}

// containerPID returns the PID of host pid in the container's PID namespace,
// or 0.
func containerPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/status", procRoot, pid))
	if err != nil {
		return 0
	}
	_, _, _, nsPID := parseStatusFields(string(data))
	return nsPID
}

// readContainerFDLinksViaIncus reads the link targets of paths with one find
// run in the container. Paths that vanished are left out.
func readContainerFDLinksViaIncus(ctx context.Context, containerName string, paths []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, fdScanTimeout)
	defer cancel()
	args := []string{
		"exec", containerName, "--",
		"sh", "-c", `find "$@" -maxdepth 0 -lname 'socket:*' -printf '%p %l\n' 2>/dev/null; exit 0`, "coi-fdscan",
	}
	output, err := container.IncusOutputContext(ctx, append(args, paths...)...)
	if err != nil {
		return nil, err
	}
	return parseFDLinks(output), nil
}

// parseFDLinks parses "<path> <link>" lines.
func parseFDLinks(output string) map[string]string {
	links := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		path, link, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			links[path] = link
		}
	}
	return links
}
