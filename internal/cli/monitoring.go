package cli

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/nftmonitor"
	"github.com/coipond/coi/internal/session"
)

// startSessionMonitoring starts the security monitoring daemons
// (process/filesystem + nft network) for a container and returns a teardown
// that stops them. It is the single implementation shared by the shell and
// run pipelines so the two paths cannot drift: an arbitrary command or run
// script deserves exactly the same watchers as an agent session.
//
//   - Honors [monitoring] enabled and [monitoring.nft] enabled.
//   - Skips nft monitoring cleanly under [network] use_sudo = false (it needs
//     sudo nft) instead of attempting sudo and warning on failure.
//   - In allowlist mode the allowed domains are resolved ONCE and the CIDRs
//     shared by both daemons (each starter previously re-resolved the full
//     list with a fresh cache — two redundant DNS sweeps per launch).
//   - The teardown stops both daemons concurrently: each Stop blocks on
//     in-flight collection (up to seconds), which short `coi run` commands
//     would otherwise pay twice, serially, on every invocation.
//
// Returns nil when monitoring is disabled.
func (a *App) startSessionMonitoring(ctx context.Context, containerName, workspacePath string, log *logger.SessionLogger, mon *monitor.MonitorDaemon, nft *nftmonitor.NFTMonitorDaemon) session.Teardown {
	if !config.BoolVal(a.cfg.Monitoring.Enabled) {
		return nil
	}

	var allowedCIDRs []string
	if a.cfg.Network.Mode == config.NetworkModeAllowlist {
		allowedCIDRs = resolveDomainsToHostCIDRs(a.cfg.Network.AllowedDomains)
		if len(allowedCIDRs) == 0 {
			// Both monitors read an empty list as "not allowlist mode" and switch
			// their allowlist and private-network checks off. Domains that failed to
			// resolve at start must not do that: keep the list non-empty with an
			// address no connection can have.
			allowedCIDRs = []string{"255.255.255.255/32"}
		}
	}

	nftEnabled := config.BoolVal(a.cfg.Monitoring.NFT.Enabled) && a.cfg.Network.SudoAllowed()
	permitted, stopPermits := a.startEgressPermits(ctx, containerName, nftEnabled)

	if err := startMonitoringDaemon(ctx, containerName, workspacePath, a.cfg, allowedCIDRs, permitted, log, mon); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to start monitoring daemon: %v\n", err)
	}

	if config.BoolVal(a.cfg.Monitoring.NFT.Enabled) {
		if !nftEnabled {
			fmt.Fprintf(os.Stderr, "NFT network monitoring skipped: [network] use_sudo = false\n")
		} else if err := startNFTMonitoringDaemon(ctx, containerName, a.cfg, allowedCIDRs, permitted, log, nft); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to start NFT monitoring: %v\n", err)
		}
	}

	return func() {
		stopPermits()
		var wg sync.WaitGroup
		if *mon != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := (*mon).Stop(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to stop monitoring daemon: %v\n", err)
				}
			}()
		}
		if *nft != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := (*nft).Stop(); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to stop NFT monitoring: %v\n", err)
				}
			}()
		}
		wg.Wait()
	}
}

// startEgressPermits returns the check both monitors share for "does the
// firewall deliberately permit this destination?", so a configured LAN service
// (also one added later with `coi hosts add`) is not reported as a
// private-network leak and auto-paused, while other ports on that host are. It is
// built only where a monitor consults it: the process monitor in allowlist mode,
// the nft monitor in either enforcing mode. The rules are refreshed in the
// background until the returned stop is called.
func (a *App) startEgressPermits(ctx context.Context, containerName string, nftEnabled bool) (func(proto, ip string, port int) bool, func()) {
	mode := a.cfg.Network.Mode
	needed := mode == config.NetworkModeAllowlist || (mode == config.NetworkModeRestricted && nftEnabled)
	if !needed {
		return nil, func() {}
	}
	containerIP, err := network.GetContainerIP(containerName)
	if err != nil || containerIP == "" {
		return nil, func() {}
	}
	permits := network.NewEgressPermits(containerIP, a.cfg.Network.Hosts, a.cfg.Network.AllowedPorts)
	pctx, cancel := context.WithCancel(ctx)
	permits.Start(pctx, 5*time.Second)
	return permits.Permits, cancel
}
