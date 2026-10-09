package cli

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/monitor"
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
		allowedCIDRs = append(resolveDomainsToHostCIDRs(a.cfg.Network.AllowedDomains),
			hostEntryCIDRs(a.cfg.Network.Hosts)...)
	}

	if err := startMonitoringDaemon(ctx, containerName, workspacePath, a.cfg, allowedCIDRs, log, mon); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to start monitoring daemon: %v\n", err)
	}

	if config.BoolVal(a.cfg.Monitoring.NFT.Enabled) {
		if !a.cfg.Network.SudoAllowed() {
			fmt.Fprintf(os.Stderr, "NFT network monitoring skipped: [network] use_sudo = false\n")
		} else if err := startNFTMonitoringDaemon(ctx, containerName, a.cfg, allowedCIDRs, log, nft); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to start NFT monitoring: %v\n", err)
		}
	}

	return func() {
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
