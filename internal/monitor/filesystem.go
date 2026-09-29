package monitor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mensfeld/coi/internal/container"
)

// FilesystemMonitor tracks filesystem I/O statistics with delta calculation
type FilesystemMonitor struct {
	mu               sync.Mutex
	previousSnapshot ioSnapshot
	previousTime     time.Time
}

type ioSnapshot struct {
	totalReadBytes  uint64
	totalWriteBytes uint64
}

// NewFilesystemMonitor creates a new filesystem monitor
func NewFilesystemMonitor() *FilesystemMonitor {
	return &FilesystemMonitor{}
}

// Collect gathers filesystem statistics and calculates read/write rates
func (fm *FilesystemMonitor) Collect(ctx context.Context, containerName string) (FilesystemStats, error) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Get current resource stats (includes I/O)
	resourceStats, err := CollectResourceStats(ctx, containerName)
	if err != nil {
		return FilesystemStats{Available: false}, err
	}

	// Convert to bytes (resourceStats is in MB)
	currentReadBytes := uint64(resourceStats.IOReadMB * 1024 * 1024)
	currentWriteBytes := uint64(resourceStats.IOWriteMB * 1024 * 1024)

	// Collect disk space stats (non-fatal if fails)
	tmpUsed, tmpTotal, tmpPercent, _ := CollectDiskSpace(ctx, containerName)

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
				TotalReadMB:       float64(deltaReadBytes) / 1024 / 1024,
				ReadRateMBPerSec:  readRateMBPerSec,
				TotalWriteMB:      float64(deltaWriteBytes) / 1024 / 1024,
				WriteRateMBPerSec: writeRateMBPerSec,
				TmpUsedMB:         tmpUsed,
				TmpTotalMB:        tmpTotal,
				TmpUsedPercent:    tmpPercent,
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
		TotalReadMB:       0,
		ReadRateMBPerSec:  0,
		TotalWriteMB:      0,
		WriteRateMBPerSec: 0,
		TmpUsedMB:         tmpUsed,
		TmpTotalMB:        tmpTotal,
		TmpUsedPercent:    tmpPercent,
	}, nil
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

// collectDiskSpaceViaIncusExec falls back to running df inside the container.
func collectDiskSpaceViaIncusExec(ctx context.Context, containerName string) (tmpUsedMB, tmpTotalMB, tmpUsedPercent float64, err error) {
	output, err := container.IncusOutputContext(ctx, "exec", containerName, "--", "df", "-BM", "/tmp")
	if err != nil {
		return 0, 0, 0, err
	}
	used, total, pct := parseDfBMOutput(output)
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
