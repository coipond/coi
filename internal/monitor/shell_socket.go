package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coipond/coi/internal/container"
)

// procRoot is the /proc the socket check reads; tests point it at a fake tree.
var procRoot = "/proc"

// fdScanTimeout bounds the incus exec fallback of the socket check: the
// collector waits for every source, so a hung exec would stall detection.
var fdScanTimeout = 5 * time.Second

// socketCheckInitPID resolves the container's init PID; tests replace it.
var socketCheckInitPID = GetContainerInitPID

// readContainerFDLinks resolves fd links from inside the container when the
// host may not read them (no CAP_SYS_PTRACE over the container's uids). It
// takes container-side paths and returns their link targets.
var readContainerFDLinks = readContainerFDLinksViaIncus

// markSocketShells sets StdioTCPSocket on every shell in processes whose fd 0
// or fd 1 is a TCP socket of the container (an inode in its /proc/net/tcp or
// tcp6). Host /proc is read first; fds the host may not read are resolved with
// one incus exec. The TCP tables are read only when a shell has a socket or an
// unreadable fd. Errors leave the processes unmarked: argv matching still
// runs.
func markSocketShells(ctx context.Context, containerName string, processes []Process) {
	var shells []int
	for i := range processes {
		if isShellProcess(processes[i], strings.ToLower(processes[i].Command)) {
			shells = append(shells, i)
		}
	}
	if len(shells) == 0 {
		return
	}

	sockets := map[int][]uint64{} // index in processes -> socket inodes on fd 0/1
	denied := map[string]int{}    // container-side fd path -> index in processes
	for _, i := range shells {
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
	if len(sockets) == 0 && len(denied) == 0 {
		return
	}

	pid, err := socketCheckInitPID(ctx, containerName)
	if err != nil || pid <= 0 {
		return
	}
	inodes := tcpSocketInodes(pid)
	if len(inodes) == 0 {
		return
	}
	for i, fdInodes := range sockets {
		for _, inode := range fdInodes {
			if inodes[inode] {
				processes[i].StdioTCPSocket = true
			}
		}
	}
	if len(denied) == 0 {
		return
	}

	paths := make([]string, 0, len(denied))
	for p := range denied {
		paths = append(paths, p)
	}
	links, err := readContainerFDLinks(ctx, containerName, paths)
	if err != nil {
		return
	}
	for p, link := range links {
		if i, ok := denied[p]; ok && inodes[socketInode(link)] {
			processes[i].StdioTCPSocket = true
		}
	}
}

// tcpSocketInodes returns the socket inodes in the TCP tables of the network
// namespace of host pid.
func tcpSocketInodes(pid int) map[uint64]bool {
	inodes := map[uint64]bool{}
	for _, table := range []string{"tcp", "tcp6"} {
		_ = readSocketInodes(fmt.Sprintf("%s/%d/net/%s", procRoot, pid, table), inodes)
	}
	return inodes
}

// readSocketInodes adds the inode column of a /proc/net/tcp[6] file to inodes.
func readSocketInodes(path string, inodes map[uint64]bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if inode, err := strconv.ParseUint(fields[9], 10, 64); err == nil && inode != 0 {
			inodes[inode] = true
		}
	}
	return scanner.Err()
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

// containerPID returns the PID of host pid in the container's PID namespace
// (the second NSpid entry of /proc/<pid>/status), or 0.
func containerPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/status", procRoot, pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "NSpid:" {
			continue
		}
		nsPID, _ := strconv.Atoi(fields[2])
		return nsPID
	}
	return 0
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
