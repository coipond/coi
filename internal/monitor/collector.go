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
	gateway           func() string
	filesystemMonitor *FilesystemMonitor
	// permittedFlows holds the flows the previous poll did not flag, keyed by
	// flowKey. Collect runs one poll at a time.
	permittedFlows map[string]bool
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

// SetGateway supplies the container's bridge gateway (see
// DaemonConfig.Gateway).
func (c *Collector) SetGateway(fn func() string) {
	c.gateway = fn
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

// keepPermittedFlows clears the allowlist flag on a flow the previous poll did
// not flag. Its address can leave the dynamic nft set (element timeout) while
// the firewall keeps the flow open (ct state established), so that is not a
// violation. A new flow to the same address has a new key and is still flagged.
func (c *Collector) keepPermittedFlows(stats *NetworkStats) {
	permitted := make(map[string]bool, len(stats.Connections))
	for i := range stats.Connections {
		conn := &stats.Connections[i]
		key := flowKey(*conn)
		if conn.Suspicious && conn.SuspectReason == reasonNotInAllowlist && c.permittedFlows[key] {
			conn.Suspicious = false
			conn.SuspectReason = ""
			stats.SuspiciousCount--
		}
		if !conn.Suspicious {
			permitted[key] = true
		}
	}
	c.permittedFlows = permitted
}

// flowKey identifies one socket's flow by protocol and both endpoints.
func flowKey(conn Connection) string {
	return conn.Protocol + " " + conn.LocalAddr + " " + conn.RemoteAddr
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
		networkStats, err := CollectNetworkStats(ctx, c.containerName, c.containerIP, c.currentAllowedCIDRs(), c.permitted, c.gateway)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			snapshot.Errors = append(snapshot.Errors, fmt.Sprintf("network: %v", err))
			snapshot.Network = NetworkStats{ActiveConnections: 0}
		} else {
			c.keepPermittedFlows(&networkStats)
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
