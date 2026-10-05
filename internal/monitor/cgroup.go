package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// GetCgroupPath returns the cgroup v2 path for a container.
func GetCgroupPath(ctx context.Context, containerName string) (string, error) {
	for _, path := range wellKnownCgroupPaths(containerName) {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	// Fallback: derive path from the init PID via incus info.
	return findCgroupPathViaIncus(ctx, containerName)
}

// GetContainerInitPID returns the host PID of the container's init process.
// It first attempts a host-side read from the container's cgroup.procs files,
// which requires no subprocess. Only if that fails does it fall back to
// parsing `incus info` output.
//
// The cgroup path probe uses the well-known paths in GetCgroupPath (no incus
// subprocess). The incus fallback path is taken only when none of those paths
// exist — it calls incus info directly rather than going through GetCgroupPath
// to avoid the mutual recursion that would occur if GetCgroupPath's own
// fallback (findCgroupPathViaIncus) called back into GetContainerInitPID.
func GetContainerInitPID(ctx context.Context, containerName string) (int, error) {
	for _, cgroupPath := range wellKnownCgroupPaths(containerName) {
		if _, err := os.Stat(cgroupPath); err != nil {
			continue
		}
		if pid, err := initPIDFromCgroupProcs(cgroupPath); err == nil {
			return pid, nil
		}
	}
	// Fallback: parse PID from incus info output.
	return getInitPIDViaIncus(ctx, containerName)
}

// getInitPIDViaIncus calls incus info and parses the PID line. Kept separate
// from GetContainerInitPID so findCgroupPathViaIncus can call it without
// creating a call cycle through GetCgroupPath.
func getInitPIDViaIncus(ctx context.Context, containerName string) (int, error) {
	output, err := container.IncusOutputContext(ctx, "info", containerName)
	if err != nil {
		return 0, fmt.Errorf("failed to get container info: %w", err)
	}
	return parseInitPIDFromIncusInfo(output)
}

// wellKnownCgroupPaths returns the candidate cgroup v2 paths for a container
// in the order they should be probed. Shared with GetCgroupPath so both
// functions check exactly the same list without duplicating it.
//
// The .payload paths come FIRST: on an Incus/LXC layout that splits the
// instance into a monitor cgroup (the host-side forkstart process) and a
// payload cgroup (the container's own process tree), only the payload holds
// the container's processes. Probing .monitor first there would make
// GetCgroupPath read the monitor's tiny memory/IO (under-reporting the whole
// container) and make GetContainerInitPID return the monitor's PID instead of
// the container init. The .monitor paths stay in the list as a fallback for
// layouts where the monitor cgroup is itself the combined instance root, but
// after payload and the legacy single-hierarchy roots. Non-existent candidates
// are Stat-probed and skipped, so listing extra forms is always safe.
func wellKnownCgroupPaths(containerName string) []string {
	return []string{
		fmt.Sprintf("/sys/fs/cgroup/incus.payload/%s", containerName),
		fmt.Sprintf("/sys/fs/cgroup/lxc.payload/%s", containerName),
		fmt.Sprintf("/sys/fs/cgroup/lxc/%s", containerName),
		fmt.Sprintf("/sys/fs/cgroup/incus/%s", containerName),
		fmt.Sprintf("/sys/fs/cgroup/incus.monitor/%s", containerName),
		fmt.Sprintf("/sys/fs/cgroup/lxc.monitor/%s", containerName),
	}
}

// initPIDFromCgroupProcs walks all cgroup.procs files under cgroupPath and
// returns the minimum PID found. In cgroup v2 the container init process is
// started first and therefore has the lowest host PID among all processes in
// the container's cgroup hierarchy. Systemd-based containers move PID 1 into
// init.scope, so walking the full tree (rather than reading only the root
// cgroup.procs) is necessary.
func initPIDFromCgroupProcs(cgroupPath string) (int, error) {
	var minPID int
	err := filepath.WalkDir(cgroupPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // path is under /sys/fs/cgroup, a kernel-managed vfs where symlink TOCTOU is not possible
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(line))
			if err != nil || pid <= 0 {
				continue
			}
			if minPID == 0 || pid < minPID {
				minPID = pid
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if minPID == 0 {
		return 0, fmt.Errorf("no PIDs found in cgroup %s", cgroupPath)
	}
	return minPID, nil
}

// parseInitPIDFromIncusInfo extracts the container init PID from `incus info`
// output. Kept as a separate function so it can be unit-tested without a live
// Incus daemon; production callers use GetContainerInitPID.
func parseInitPIDFromIncusInfo(output string) (int, error) {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "PID:") || strings.HasPrefix(trimmed, "Pid:") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				pid, err := strconv.Atoi(parts[1])
				if err == nil && pid > 0 {
					return pid, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("could not find container PID in incus info output")
}

// findCgroupPathViaIncus derives the cgroup path from the init PID returned by
// incus info. It calls getInitPIDViaIncus directly to avoid the mutual
// recursion that would arise if it called GetContainerInitPID (which itself
// calls GetCgroupPath).
func findCgroupPathViaIncus(ctx context.Context, containerName string) (string, error) {
	pid, err := getInitPIDViaIncus(ctx, containerName)
	if err != nil {
		return "", err
	}

	// Read cgroup from /proc/<pid>/cgroup
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file: %w", err)
	}

	// Parse cgroup v2 format: 0::/path/to/cgroup
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			cgroupPath := strings.TrimPrefix(line, "0::")
			cgroupPath = strings.TrimSpace(cgroupPath)
			return filepath.Join("/sys/fs/cgroup", cgroupPath), nil
		}
	}

	return "", fmt.Errorf("could not parse cgroup path from %s", cgroupFile)
}

// stripSystemdScopeSuffix removes a single trailing systemd scope/service
// segment (e.g. "/init.scope") from a cgroup path, so reads hit the container's
// top-level cgroup, whose cgroup v2 counters (memory.current, cpu.stat,
// io.stat) aggregate the whole process tree. GetCgroupPath's incus-info
// fallback returns the init process's own sub-scope, which accounts for only
// systemd PID 1 — reading resource stats there under-reports the container by
// orders of magnitude (#top-mem).
//
// It strips exactly ONE leaf, which is all GetCgroupPath ever produces: either
// the container root itself, or "<root>/init.scope". It is NOT a general
// container-root resolver — a deeper path like "<root>/system.slice/foo.service"
// yields "<root>/system.slice", not the root. Callers rely on the ≤1-level
// contract. A path whose leaf is neither .scope nor .service is returned
// unchanged. collectProcessesViaHostProc uses the same strip so both views
// agree on the container root.
func stripSystemdScopeSuffix(cgroupPath string) string {
	base := filepath.Base(cgroupPath)
	if strings.HasSuffix(base, ".scope") || strings.HasSuffix(base, ".service") {
		return filepath.Dir(cgroupPath)
	}
	return cgroupPath
}

// CollectResourceStats reads resource usage from cgroup
func CollectResourceStats(ctx context.Context, containerName string) (ResourceStats, error) {
	rawPath, err := GetCgroupPath(ctx, containerName)
	if err != nil {
		return ResourceStats{}, fmt.Errorf("failed to get cgroup path: %w", err)
	}
	// Read from the container's top-level cgroup, not init.scope, so the v2
	// counters aggregate every process in the container (#top-mem).
	cgroupPath := stripSystemdScopeSuffix(rawPath)

	stats := ResourceStats{}

	// Read CPU stats
	cpuStats, err := readCPUStats(filepath.Join(cgroupPath, "cpu.stat"))
	if err != nil {
		return stats, fmt.Errorf("failed to read CPU stats: %w", err)
	}
	stats.CPUTimeSeconds = cpuStats.total / 1000000.0 // microseconds to seconds
	stats.UserCPUSeconds = cpuStats.user / 1000000.0
	stats.SysCPUSeconds = cpuStats.system / 1000000.0

	// Read memory stats
	memStats, err := readMemoryStats(filepath.Join(cgroupPath, "memory.current"), filepath.Join(cgroupPath, "memory.max"))
	if err != nil {
		return stats, fmt.Errorf("failed to read memory stats: %w", err)
	}
	stats.MemoryMB = memStats.current / 1024.0 / 1024.0
	if memStats.max > 0 && memStats.max != 9223372036854771712 { // max value indicates no limit
		stats.MemoryLimitMB = memStats.max / 1024.0 / 1024.0
	}

	// Read I/O stats from the container root, whose io.stat aggregates the
	// whole tree. (This previously read init.scope, which tracks no I/O, and
	// climbed one level to compensate — no longer needed now that cgroupPath is
	// already the container root. Climbing further would reach the grouping
	// cgroup shared by every container and over-count.)
	ioStats, err := readIOStats(filepath.Join(cgroupPath, "io.stat"))
	if err != nil {
		// I/O stats might not be available, don't fail
		stats.IOReadMB = 0
		stats.IOWriteMB = 0
	} else {
		stats.IOReadMB = ioStats.read / 1024.0 / 1024.0
		stats.IOWriteMB = ioStats.write / 1024.0 / 1024.0
	}

	return stats, nil
}

type cpuStats struct {
	total  float64
	user   float64
	system float64
}

func readCPUStats(path string) (cpuStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cpuStats{}, err
	}

	var stats cpuStats
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}

		switch fields[0] {
		case "usage_usec":
			stats.total = value
		case "user_usec":
			stats.user = value
		case "system_usec":
			stats.system = value
		}
	}

	return stats, nil
}

type memoryStats struct {
	current float64
	max     float64
}

func readMemoryStats(currentPath, maxPath string) (memoryStats, error) {
	var stats memoryStats

	// Read current memory usage
	data, err := os.ReadFile(currentPath)
	if err != nil {
		return stats, err
	}
	current, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
	if err != nil {
		return stats, err
	}
	stats.current = current

	// Read memory limit (optional)
	data, err = os.ReadFile(maxPath)
	if err == nil {
		if strings.TrimSpace(string(data)) != "max" {
			maxValue, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
			if err == nil {
				stats.max = maxValue
			}
		}
	}

	return stats, nil
}

type ioStats struct {
	read  float64
	write float64
}

func readIOStats(path string) (ioStats, error) {
	file, err := os.Open(path)
	if err != nil {
		return ioStats{}, err
	}
	defer file.Close()

	var stats ioStats
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Format: <major>:<minor> rbytes=X wbytes=Y ...
		for i := 1; i < len(fields); i++ {
			parts := strings.Split(fields[i], "=")
			if len(parts) != 2 {
				continue
			}

			value, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				continue
			}

			switch parts[0] {
			case "rbytes":
				stats.read += value
			case "wbytes":
				stats.write += value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return ioStats{}, err
	}

	return stats, nil
}
