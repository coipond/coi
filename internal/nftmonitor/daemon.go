//go:build linux
// +build linux

package nftmonitor

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/mensfeld/coi/internal/monitor"
)

// Daemon orchestrates nftables-based network monitoring
type Daemon struct {
	config      *Config
	ruleManager *RuleManager
	logReader   *LogReader
	detector    *NetworkDetector
	responder   *monitor.Responder
	auditLog    *monitor.AuditLog
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
}

// StartDaemon starts the nftables monitoring daemon
func StartDaemon(ctx context.Context, cfg Config) (*Daemon, error) {
	// Create audit log
	auditLog, err := monitor.NewAuditLog(cfg.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit log: %w", err)
	}

	// Create responder (convert OnThreat callback)
	responder := monitor.NewResponder(
		cfg.ContainerName,
		true, // autoPauseOnHigh
		true, // autoKillOnCritical
		auditLog,
		func(threat monitor.ThreatEvent) {
			if cfg.OnThreat != nil {
				// Convert monitor.ThreatEvent to nftmonitor.ThreatEvent
				cfg.OnThreat(ThreatEvent{
					Timestamp:   threat.Timestamp,
					Level:       ThreatLevel(threat.Level),
					Category:    threat.Category,
					Title:       threat.Title,
					Description: threat.Description,
					Evidence:    nil, // Evidence is not consumed by the callback
				})
			}
		},
	)
	responder.SetForensicsOnKill(cfg.ForensicsOnKill)

	// Set action callback for pause/kill notifications
	if cfg.OnAction != nil {
		responder.SetOnAction(cfg.OnAction)
	}
	// Route the responder's non-fatal cleanup warnings to the session log
	// instead of the user's attached terminal (issue #372 class).
	responder.SetOnError(cfg.OnError)

	// Create daemon context
	daemonCtx, cancel := context.WithCancel(ctx)

	daemon := &Daemon{
		config:      &cfg,
		ruleManager: NewRuleManager(&cfg),
		detector:    NewNetworkDetector(&cfg),
		responder:   responder,
		auditLog:    auditLog,
		ctx:         daemonCtx,
		cancel:      cancel,
		running:     false,
	}

	// Create log reader
	logReader, err := NewLogReader(&cfg)
	if err != nil {
		cancel()
		auditLog.Close()
		return nil, fmt.Errorf("failed to create log reader: %w", err)
	}
	daemon.logReader = logReader

	// Add nftables rules
	if err := daemon.ruleManager.AddRules(); err != nil {
		cancel()
		auditLog.Close()
		return nil, fmt.Errorf("failed to add nftables rules: %w", err)
	}

	// Start monitoring goroutines
	daemon.start()

	return daemon, nil
}

// start begins the monitoring loops
func (d *Daemon) start() {
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	// Start log reader
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if err := d.logReader.Start(d.ctx); err != nil {
			if d.ctx.Err() == nil && d.config.OnError != nil {
				d.config.OnError(fmt.Errorf("log reader error: %w", err))
			}
		}
	}()

	// Start event processor
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.processEvents()
	}()
}

// processEvents processes network events and detects threats
func (d *Daemon) processEvents() {
	debugf("Daemon.processEvents started")
	for {
		select {
		case <-d.ctx.Done():
			debugf("Daemon.processEvents context done")
			return
		case event := <-d.logReader.Events():
			if event == nil {
				debugf("Received nil event, skipping")
				continue
			}

			debugf("Daemon received event: DstIP=%s DstPort=%d", event.DstIP, event.DstPort)

			// Analyze event for threats
			if threat := d.detector.Analyze(event); threat != nil {
				debugf("THREAT DETECTED: Level=%s Title=%s", threat.Level, threat.Title)

				// Convert to monitor.ThreatEvent
				monitorThreat := monitor.ThreatEvent{
					ID:          uuid.New().String(),
					Timestamp:   threat.Timestamp,
					Level:       monitor.ThreatLevel(threat.Level),
					Category:    threat.Category,
					Title:       threat.Title,
					Description: threat.Description,
					Evidence:    monitor.Evidence{Network: nftEventToNetworkThreat(threat.Evidence)},
					Action:      "pending",
				}

				// Handle threat (logging, alerting, response)
				debugf("Calling responder.Handle for threat")
				if err := d.responder.Handle(d.ctx, monitorThreat); err != nil {
					if d.config.OnError != nil {
						d.config.OnError(fmt.Errorf("error handling threat: %w", err))
					}
					debugf("Responder error: %v", err)
				} else {
					debugf("Responder.Handle completed successfully")
				}
			} else {
				debugf("No threat detected for event to %s:%d", event.DstIP, event.DstPort)
			}
		}
	}
}

// nftEventToNetworkThreat converts a nftmonitor NetworkEvent to a monitor NetworkThreat
func nftEventToNetworkThreat(event *NetworkEvent) *monitor.NetworkThreat {
	if event == nil {
		return nil
	}
	return &monitor.NetworkThreat{
		Connection: monitor.Connection{
			Protocol:   event.Protocol,
			LocalAddr:  fmt.Sprintf("%s:%d", event.SrcIP, event.SrcPort),
			RemoteAddr: fmt.Sprintf("%s:%d", event.DstIP, event.DstPort),
		},
		Reason:     fmt.Sprintf("%s connection to %s:%d", event.Protocol, event.DstIP, event.DstPort),
		RemoteHost: event.DstIP,
	}
}

// Stop stops the daemon and cleans up resources
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	d.mu.Unlock()

	// Cancel context to stop goroutines
	d.cancel()

	// Wait for goroutines to finish
	d.wg.Wait()

	// Close log reader
	if d.logReader != nil {
		d.logReader.Close()
	}

	// Remove nftables rules
	var ruleErr error
	if d.ruleManager != nil {
		ruleErr = d.ruleManager.RemoveRules()
	}

	// Close audit log
	var auditErr error
	if d.auditLog != nil {
		auditErr = d.auditLog.Close()
	}

	// Return first error if any
	if ruleErr != nil {
		return fmt.Errorf("failed to remove nftables rules: %w", ruleErr)
	}
	if auditErr != nil {
		return fmt.Errorf("failed to close audit log: %w", auditErr)
	}

	return nil
}

// IsRunning returns whether the daemon is running
func (d *Daemon) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}
