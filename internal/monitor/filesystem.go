package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coipond/coi/internal/container"
	"golang.org/x/sys/unix"
)

// FilesystemMonitor tracks filesystem I/O statistics with delta calculation
type FilesystemMonitor struct {
	mu               sync.Mutex
	previousSnapshot ioSnapshot
	previousTime     time.Time
	diskSpaceFailing bool
	workspacePath    string
	// ioDevice is the io.stat device counted; "" counts the whole container.
	ioDevice         string
	ioDeviceResolved bool
}

type ioSnapshot struct {
	totalReadBytes  uint64
	totalWriteBytes uint64
}

// Collect's sources, replaced by tests.
var (
	filesystemIOStats   = collectIOStats
	collectDiskSpace    = CollectDiskSpace
	containerRootDevice = collectContainerRootDevice
)

// sysDevBlock links each block device's "major:minor" to its sysfs directory.
var sysDevBlock = "/sys/dev/block"

// rootDeviceExecTimeout bounds the stat of the container rootfs.
var rootDeviceExecTimeout = 10 * time.Second

// NewFilesystemMonitor creates a filesystem monitor for the workspace at
// workspacePath ("" counts the whole container's I/O).
func NewFilesystemMonitor(workspacePath string) *FilesystemMonitor {
	return &FilesystemMonitor{workspacePath: workspacePath}
}

// Collect gathers filesystem statistics and calculates read/write rates
func (fm *FilesystemMonitor) Collect(ctx context.Context, containerName string) (FilesystemStats, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if !fm.ioDeviceResolved {
		fm.ioDevice = workspaceIODevice(ctx, containerName, fm.workspacePath)
		fm.ioDeviceResolved = true
	}

	ioStat, err := filesystemIOStats(ctx, containerName, fm.ioDevice)
	if err != nil {
		return FilesystemStats{Available: false}, err
	}

	currentReadBytes := uint64(ioStat.read)
	currentWriteBytes := uint64(ioStat.write)

	// Collect disk space stats (non-fatal if fails)
	tmpUsed, tmpTotal, tmpPercent, diskErr := collectDiskSpace(ctx, containerName)
	diskSpaceErr := fm.diskSpaceTransition(diskErr)

	// Calculate delta and rate
	if !fm.previousTime.IsZero() {
		elapsed := time.Since(fm.previousTime)
		deltaReadBytes := counterDelta(currentReadBytes, fm.previousSnapshot.totalReadBytes)
		deltaWriteBytes := counterDelta(currentWriteBytes, fm.previousSnapshot.totalWriteBytes)

		if elapsed.Seconds() > 0 {
			readRateMBPerSec := float64(deltaReadBytes) / 1024 / 1024 / elapsed.Seconds()
			writeRateMBPerSec := float64(deltaWriteBytes) / 1024 / 1024 / elapsed.Seconds()

			stats := FilesystemStats{
				Available:         true,
				WorkspaceDevice:   fm.ioDevice,
				TotalReadMB:       float64(deltaReadBytes) / 1024 / 1024,
				ReadRateMBPerSec:  readRateMBPerSec,
				TotalWriteMB:      float64(deltaWriteBytes) / 1024 / 1024,
				WriteRateMBPerSec: writeRateMBPerSec,
				TmpUsedMB:         tmpUsed,
				TmpTotalMB:        tmpTotal,
				TmpUsedPercent:    tmpPercent,
				diskSpaceErr:      diskSpaceErr,
			}

			// Update snapshot
			fm.previousSnapshot.totalReadBytes = currentReadBytes
			fm.previousSnapshot.totalWriteBytes = currentWriteBytes
			fm.previousTime = time.Now()

			return stats, nil
		}
	}

	// First collection, just store baseline
	fm.previousSnapshot.totalReadBytes = currentReadBytes
	fm.previousSnapshot.totalWriteBytes = currentWriteBytes
	fm.previousTime = time.Now()

	return FilesystemStats{
		Available:         true,
		WorkspaceDevice:   fm.ioDevice,
		TotalReadMB:       0,
		ReadRateMBPerSec:  0,
		TotalWriteMB:      0,
		WriteRateMBPerSec: 0,
		TmpUsedMB:         tmpUsed,
		TmpTotalMB:        tmpTotal,
		TmpUsedPercent:    tmpPercent,
		diskSpaceErr:      diskSpaceErr,
	}, nil
}

// workspaceIODevice returns the io.stat device ("major:minor") of the block
// device backing workspacePath, or "" to count the whole container: when the
// workspace shares the container rootfs device, has no block device of its own
// (major 0: zfs, btrfs, tmpfs) or a device cannot be read.
func workspaceIODevice(ctx context.Context, containerName, workspacePath string) string {
	if workspacePath == "" {
		return ""
	}
	var st unix.Stat_t
	if err := unix.Stat(workspacePath, &st); err != nil {
		return ""
	}
	rootDev, err := containerRootDevice(ctx, containerName)
	if err != nil {
		return ""
	}
	return ioDevice(st.Dev, rootDev)
}

// maxDeviceDepth bounds the walk down a device stack (dm, md, loop).
const maxDeviceDepth = 8

// ioDevice returns the io.stat disk of workspaceDev, or "" when the two
// devices' stacks share a lowest disk (I/O on a stacked device is charged
// again on each disk below it) or a level of either stack is unknown, as for
// a zfs or btrfs pool (major 0).
func ioDevice(workspaceDev, rootDev uint64) string {
	disk, _, ok := diskOf(workspaceDev)
	workspaceDisks, rootDisks := map[uint64]bool{}, map[uint64]bool{}
	if !ok || !lowestDisks(workspaceDev, workspaceDisks, 0) || !lowestDisks(rootDev, rootDisks, 0) {
		return ""
	}
	for d := range workspaceDisks {
		if rootDisks[d] {
			return ""
		}
	}
	return deviceName(disk)
}

// deviceName formats dev as io.stat and sysfs name it: "major:minor".
func deviceName(dev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
}

// readDevice reads a sysfs "dev" file ("major:minor").
func readDevice(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	majorText, minorText, found := strings.Cut(strings.TrimSpace(string(data)), ":")
	major, majorErr := strconv.ParseUint(majorText, 10, 32)
	minor, minorErr := strconv.ParseUint(minorText, 10, 32)
	if !found || majorErr != nil || minorErr != nil {
		return 0, false
	}
	return unix.Mkdev(uint32(major), uint32(minor)), true
}

// diskOf returns the disk holding dev and its sysfs directory; false when
// sysfs does not know dev. io.stat names whole disks, never partitions.
func diskOf(dev uint64) (uint64, string, bool) {
	dir, err := filepath.EvalSymlinks(filepath.Join(sysDevBlock, deviceName(dev)))
	if err != nil {
		return 0, "", false
	}
	if _, err := os.Stat(filepath.Join(dir, "partition")); err != nil {
		return dev, dir, true
	}
	dir = filepath.Dir(dir)
	disk, ok := readDevice(filepath.Join(dir, "dev"))
	return disk, dir, ok
}

// lowestDisks adds the disks at the bottom of dev's stack to disks: below a
// dm or md device its slaves, below a loop device the device of its backing
// file. It returns false when a level is unknown.
func lowestDisks(dev uint64, disks map[uint64]bool, depth int) bool {
	if depth > maxDeviceDepth {
		return false
	}
	disk, dir, ok := diskOf(dev)
	if !ok {
		return false
	}
	if backing, err := os.ReadFile(filepath.Join(dir, "loop", "backing_file")); err == nil {
		var st unix.Stat_t
		if err := unix.Stat(strings.TrimSpace(string(backing)), &st); err != nil {
			return false
		}
		return lowestDisks(st.Dev, disks, depth+1)
	}
	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil || len(slaves) == 0 {
		disks[disk] = true
		return true
	}
	for _, slave := range slaves {
		slaveDev, ok := readDevice(filepath.Join(dir, "slaves", slave.Name(), "dev"))
		if !ok || !lowestDisks(slaveDev, disks, depth+1) {
			return false
		}
	}
	return true
}

// collectContainerRootDevice returns the device number of the container's
// rootfs. Device numbers are not namespaced, so it compares to a host stat.
func collectContainerRootDevice(ctx context.Context, containerName string) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, rootDeviceExecTimeout)
	defer cancel()
	output, err := container.IncusOutputContext(ctx, "exec", containerName, "--", "stat", "-c", "%d", "/")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(output), 10, 64)
}

// diskSpaceTransition returns err only when disk space collection starts
// failing, so a persistent failure is reported once, not on every poll.
func (fm *FilesystemMonitor) diskSpaceTransition(err error) error {
	wasFailing := fm.diskSpaceFailing
	fm.diskSpaceFailing = err != nil
	if err == nil || wasFailing {
		return nil
	}
	return err
}

// counterDelta returns current - previous for a monotonic cumulative counter,
// clamped to 0 when the counter appears to have gone backwards. A cgroup io
// counter reads lower than the prior sample when CollectResourceStats hits its
// io-error branch (IOReadMB/IOWriteMB fall back to 0 while the rest of the
// sample is valid) or when the container's cgroup is momentarily
// unavailable/reset. Without this clamp the unsigned subtraction underflows to
// ~2^64, yielding a spurious multi-terabyte "read"/"write" in a single interval
// that trips DetectLargeReads and freezes a perfectly healthy container. Mirrors
// the negative-delta clamp used for the `coi top` rate counters.
func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

// DetectLargeReads checks if filesystem read activity exceeds thresholds
func DetectLargeReads(stats FilesystemStats, thresholdMB float64, rateThresholdMBPerSec float64) *FilesystemThreat {
	// Check if read amount exceeds threshold
	if stats.TotalReadMB > thresholdMB {
		return &FilesystemThreat{
			ReadBytesMB: stats.TotalReadMB,
			ReadRate:    stats.ReadRateMBPerSec,
			Threshold:   thresholdMB,
			Duration:    "current interval",
		}
	}

	// Check if sustained read rate exceeds threshold
	if rateThresholdMBPerSec > 0 && stats.ReadRateMBPerSec > rateThresholdMBPerSec {
		return &FilesystemThreat{
			ReadBytesMB: stats.TotalReadMB,
			ReadRate:    stats.ReadRateMBPerSec,
			Threshold:   rateThresholdMBPerSec,
			Duration:    "sustained",
		}
	}

	return nil
}

// FilesystemWriteThreat represents suspicious write activity (potential data exfiltration)
type FilesystemWriteThreat struct {
	WriteBytesMB float64 `json:"write_bytes_mb"`
	WriteRate    float64 `json:"write_rate_mb_per_sec"`
	Threshold    float64 `json:"threshold_mb"`
	Duration     string  `json:"duration"`
}

// DetectLargeWrites checks if filesystem write activity exceeds thresholds
// Large writes can indicate data exfiltration (tar, dd, cp of sensitive data)
func DetectLargeWrites(stats FilesystemStats, thresholdMB float64, rateThresholdMBPerSec float64) *FilesystemWriteThreat {
	// Check if write amount exceeds threshold
	if stats.TotalWriteMB > thresholdMB {
		return &FilesystemWriteThreat{
			WriteBytesMB: stats.TotalWriteMB,
			WriteRate:    stats.WriteRateMBPerSec,
			Threshold:    thresholdMB,
			Duration:     "current interval",
		}
	}

	// Check if sustained write rate exceeds threshold
	if rateThresholdMBPerSec > 0 && stats.WriteRateMBPerSec > rateThresholdMBPerSec {
		return &FilesystemWriteThreat{
			WriteBytesMB: stats.TotalWriteMB,
			WriteRate:    stats.WriteRateMBPerSec,
			Threshold:    rateThresholdMBPerSec,
			Duration:     "sustained",
		}
	}

	return nil
}

// CollectDiskSpace gathers disk space stats for /tmp in the container.
// It first attempts a host-side syscall.Statfs via /proc/<initPID>/root/tmp,
// which avoids running code inside the container but requires the monitor to
// have read access to the container's root fs (typically root or same UID).
// If that fails, it falls back to incus exec df -BM /tmp.
func CollectDiskSpace(ctx context.Context, containerName string) (tmpUsedMB, tmpTotalMB, tmpUsedPercent float64, err error) {
	if used, total, pct, statErr := collectDiskSpaceViaStatfs(ctx, containerName); statErr == nil {
		return used, total, pct, nil
	}
	return collectDiskSpaceViaIncusExec(ctx, containerName)
}

// collectDiskSpaceViaStatfs reads /tmp disk usage from the host side using
// /proc/<initPID>/root/tmp. This requires the monitor process to have
// dereference permission on the container's /proc/<pid>/root (root or same UID).
func collectDiskSpaceViaStatfs(ctx context.Context, containerName string) (tmpUsedMB, tmpTotalMB, tmpUsedPercent float64, err error) {
	initPID, err := GetContainerInitPID(ctx, containerName)
	if err != nil {
		return 0, 0, 0, err
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(fmt.Sprintf("/proc/%d/root/tmp", initPID), &stat); err != nil {
		return 0, 0, 0, err
	}

	if stat.Bsize <= 0 {
		return 0, 0, 0, fmt.Errorf("statfs returned unexpected Bsize %d", stat.Bsize)
	}
	bsize := uint64(stat.Bsize) //nolint:gosec // checked positive above
	totalBytes := stat.Blocks * bsize
	freeBytes := stat.Bfree * bsize
	if freeBytes > totalBytes {
		// Should not happen on a well-formed filesystem, but guard against
		// uint underflow producing a wildly incorrect used-space value.
		return 0, 0, 0, fmt.Errorf("statfs: freeBytes (%d) > totalBytes (%d)", freeBytes, totalBytes)
	}
	usedBytes := totalBytes - freeBytes

	total := float64(totalBytes) / 1024 / 1024
	used := float64(usedBytes) / 1024 / 1024
	var pct float64
	if totalBytes > 0 {
		pct = float64(usedBytes) / float64(totalBytes) * 100
	}
	return used, total, pct, nil
}

// diskSpaceExecTimeout bounds the df fallback: the collector waits for every
// source, so a hung incus exec would stall all detection for the container.
var diskSpaceExecTimeout = 10 * time.Second

// collectDiskSpaceViaIncusExec falls back to running df inside the container.
func collectDiskSpaceViaIncusExec(ctx context.Context, containerName string) (tmpUsedMB, tmpTotalMB, tmpUsedPercent float64, err error) {
	ctx, cancel := context.WithTimeout(ctx, diskSpaceExecTimeout)
	defer cancel()
	output, err := container.IncusOutputContext(ctx, "exec", containerName, "--", "df", "-BM", "/tmp")
	if err != nil {
		if ctx.Err() != nil {
			return 0, 0, 0, fmt.Errorf("df /tmp: %w", ctx.Err())
		}
		return 0, 0, 0, err
	}
	used, total, pct := parseDfBMOutput(output)
	if total <= 0 {
		return 0, 0, 0, fmt.Errorf("df /tmp: unexpected output %q", output)
	}
	return used, total, pct, nil
}

// parseDfBMOutput parses the output of `df -BM <path>`.
// Format: Filesystem 1M-blocks Used Available Use% Mounted on
// Example: tmpfs        2048M  100M   1948M   5% /tmp
// Kept separate so it can be unit-tested without a live container.
func parseDfBMOutput(output string) (usedMB, totalMB, usedPercent float64) {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return
	}
	totalStr := strings.TrimSuffix(fields[1], "M")
	usedStr := strings.TrimSuffix(fields[2], "M")
	pctStr := strings.TrimSuffix(fields[4], "%")
	totalMB, _ = strconv.ParseFloat(totalStr, 64)
	usedMB, _ = strconv.ParseFloat(usedStr, 64)
	usedPercent, _ = strconv.ParseFloat(pctStr, 64)
	return
}
