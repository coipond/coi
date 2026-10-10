// Package monitor watches running containers for security threats (reverse
// shells, environment scanning, suspicious network and filesystem activity),
// responds to them, and records events in an audit log.
package monitor

import (
	"context"
	"fmt"
	"time"
)

// Daemon runs the monitoring loop in the background
type Daemon struct {
	ctx          context.Context
	cancel       context.CancelFunc
	config       DaemonConfig
	collector    *Collector
	detector     *Detector
	responder    *Responder
	auditLog     *AuditLog
	logThreatCh  chan ThreatEvent
	procThreatCh chan ThreatEvent
	fileThreatCh chan ThreatEvent
	done         chan struct{}
}

// StartDaemon creates and starts a monitoring daemon
func StartDaemon(ctx context.Context, cfg DaemonConfig) (*Daemon, error) {
	// Create audit log
	auditLog, err := NewAuditLog(cfg.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	// Create daemon context
	daemonCtx, cancel := context.WithCancel(ctx)

	// Create components
	collector := NewCollector(cfg.ContainerName, "", cfg.WorkspacePath, cfg.AllowedCIDRs)
	collector.SetAllowedCIDRsProvider(cfg.AllowedCIDRsProvider)
	collector.SetPermittedDestination(cfg.PermittedDestination)
	detector := NewDetector(cfg.FileReadThresholdMB, cfg.FileReadRateMBPerSec).
		WithProcessCountThreshold(cfg.ProcessCountThreshold).
		WithProcessSpawnRateThreshold(cfg.ProcessSpawnRateThreshold).
		WithReverseShellOneLinerPolicy(cfg.ReverseShellOneLinerPolicy)
	responder := NewResponder(cfg.ContainerName, cfg.AutoPauseOnHigh, cfg.AutoKillOnCritical,
		auditLog, cfg.OnThreat)
	responder.SetForensicsOnKill(cfg.ForensicsOnKill)

	// Set action callback for pause/kill notifications
	if cfg.OnAction != nil {
		responder.SetOnAction(cfg.OnAction)
	}
	// Route the responder's non-fatal cleanup warnings to the session log
	// instead of the user's attached terminal (issue #372 class).
	responder.SetOnError(cfg.OnError)

	logThreatCh := make(chan ThreatEvent, 32)
	logWatcher := NewLogWatcher(cfg.ContainerName, func(t ThreatEvent) {
		select {
		case logThreatCh <- t:
		default: // drop if buffer full rather than blocking
		}
	}, cfg.OnError)

	procThreatCh := make(chan ThreatEvent, 32)
	procWatcher := NewProcEventWatcher(cfg.ContainerName, func(t ThreatEvent) {
		select {
		case procThreatCh <- t:
		default: // drop if buffer full rather than blocking
		}
	}, cfg.OnError, cfg.GTFOBinsDir, cfg.SigmaDir)

	fileThreatCh := make(chan ThreatEvent, 32)
	fileWatcher := NewFileWatcher(cfg.ContainerName, func(t ThreatEvent) {
		select {
		case fileThreatCh <- t:
		default: // drop if buffer full rather than blocking
		}
	}, cfg.OnError)

	daemon := &Daemon{
		ctx:          daemonCtx,
		cancel:       cancel,
		config:       cfg,
		collector:    collector,
		detector:     detector,
		responder:    responder,
		auditLog:     auditLog,
		logThreatCh:  logThreatCh,
		procThreatCh: procThreatCh,
		fileThreatCh: fileThreatCh,
		done:         make(chan struct{}),
	}

	go logWatcher.Run(daemonCtx)
	go procWatcher.Run(daemonCtx)
	go fileWatcher.Run(daemonCtx)

	// Start monitoring loop in background
	go daemon.run()

	return daemon, nil
}

// run is the main monitoring loop
func (d *Daemon) run() {
	defer close(d.done)
	defer d.auditLog.Close()

	ticker := time.NewTicker(d.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Collect snapshot
			snapshot, err := d.collector.Collect(d.ctx)
			if err != nil {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("collection failed: %w", err))
				}
				continue
			}

			// Surface any per-source collection errors so they appear in logs.
			for _, collErr := range snapshot.Errors {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("collection: %s", collErr))
				}
			}

			// Detect threats
			threats := d.detector.Analyze(snapshot)
			snapshot.Threats = threats

			// Log snapshot to audit log
			if err := d.auditLog.WriteSnapshot(snapshot); err != nil {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("audit log write failed: %w", err))
				}
			}

			// Handle threats
			for _, threat := range threats {
				if err := d.responder.Handle(d.ctx, threat); err != nil {
					if d.config.OnError != nil {
						d.config.OnError(fmt.Errorf("threat response failed: %w", err))
					}
				}

				// If container was killed, stop monitoring
				if threat.Action == "killed" {
					return
				}
			}

		case threat := <-d.logThreatCh:
			if err := d.responder.Handle(d.ctx, threat); err != nil {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("log threat response: %w", err))
				}
			}

		case threat := <-d.procThreatCh:
			if err := d.responder.Handle(d.ctx, threat); err != nil {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("proc event threat response: %w", err))
				}
			}

		case threat := <-d.fileThreatCh:
			if err := d.responder.Handle(d.ctx, threat); err != nil {
				if d.config.OnError != nil {
					d.config.OnError(fmt.Errorf("file threat response: %w", err))
				}
			}

		case <-d.ctx.Done():
			return
		}
	}
}

// Stop gracefully stops the monitoring daemon
func (d *Daemon) Stop() error {
	d.cancel()

	// Wait for daemon to finish (with timeout)
	select {
	case <-d.done:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("daemon shutdown timeout")
	}
}
