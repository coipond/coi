package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Collector orchestrates data collection from multiple sources
type Collector struct {
	containerName     string
	containerIP       string
	workspacePath     string
	allowedCIDRs      []string
	allowedCIDRsFn    func() []string
	permitted         PermittedDestinationFunc
	filesystemMonitor *FilesystemMonitor
}

// SetAllowedCIDRsProvider supplies a function that returns the CURRENT allowlist
// CIDRs, consulted on every collection. In allowlist mode this reads the live nft
// set (the firewall's source of truth), so the monitor decides "is this connection
// allowed?" against exactly what the firewall enforces — even as a rotating
// frontend's addresses change — instead of a frozen, independently-resolved
// snapshot that drifts and flags legitimate traffic. The static allowedCIDRs
// remain the fallback: if the provider returns nothing (read failed, sets absent),
// the collector uses them, so it is never worse than before.
func (c *Collector) SetAllowedCIDRsProvider(fn func() []string) {
	c.allowedCIDRsFn = fn
}

// SetPermittedDestination supplies the firewall-permit check (see
// DaemonConfig.PermittedDestination).
func (c *Collector) SetPermittedDestination(fn PermittedDestinationFunc) {
	c.permitted = fn
}

// currentAllowedCIDRs returns the live allowlist when a provider is set and yields
// entries, otherwise the static snapshot captured at daemon start.
func (c *Collector) currentAllowedCIDRs() []string {
	if c.allowedCIDRsFn != nil {
		if live := c.allowedCIDRsFn(); len(live) > 0 {
			return live
		}
	}
	return c.allowedCIDRs
}

// NewCollector creates a new data collector
func NewCollector(containerName, containerIP, workspacePath string, allowedCIDRs []string) *Collector {
	return &Collector{
		containerName:     containerName,
		containerIP:       containerIP,
		workspacePath:     workspacePath,
		allowedCIDRs:      allowedCIDRs,
		filesystemMonitor: NewFilesystemMonitor(),
	}
}

// Collect gathers a complete snapshot of container metrics
func (c *Collector) Collect(ctx context.Context) (MonitorSnapshot, error) {
	snapshot := MonitorSnapshot{
		Timestamp:     time.Now(),
		ContainerName: c.containerName,
		ContainerIP:   c.containerIP,
		Errors:        make([]string, 0),
	}

	// Use a WaitGroup to collect data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Collect network stats
	wg.Add(1)
	go func() {
		defer wg.Done()
		networkStats, err := CollectNetworkStats(ctx, c.containerName, c.containerIP, c.currentAllowedCIDRs(), c.permitted)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("network: %v", err))
			snapshot.Network = NetworkStats{ActiveConnections: 0}
		} else {
			snapshot.Network = networkStats
		}
	}()

	// Collect process stats
	wg.Add(1)
	go func() {
		defer wg.Done()
		processStats, err := CollectProcessStats(ctx, c.containerName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("process: %v", err))
			snapshot.Processes = ProcessStats{Available: false}
		} else {
			snapshot.Processes = processStats
		}
	}()

	// Collect filesystem stats
	wg.Add(1)
	go func() {
		defer wg.Done()
		filesystemStats, err := c.filesystemMonitor.Collect(ctx, c.containerName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("filesystem: %v", err))
			snapshot.Filesystem = FilesystemStats{Available: false}
		} else {
			snapshot.Filesystem = filesystemStats
			snapshot.Filesystem.WorkspacePath = c.workspacePath
		}
	}()

	// Collect resource stats
	wg.Add(1)
	go func() {
		defer wg.Done()
		resourceStats, err := CollectResourceStats(ctx, c.containerName)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("resources: %v", err))
			snapshot.Resources = ResourceStats{}
		} else {
			snapshot.Resources = resourceStats
		}
	}()

	// Wait for all collectors to finish
	wg.Wait()

	return snapshot, nil
}
