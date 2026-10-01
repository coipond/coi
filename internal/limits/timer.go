package limits

import (
	"context"
	"strings"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/logger"
)

// TimeoutMonitor monitors a container's runtime and stops it when max duration is reached
type TimeoutMonitor struct {
	ContainerName string
	MaxDuration   time.Duration
	AutoStop      bool
	StopGraceful  bool
	Project       string
	Logger        *logger.SessionLogger

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// NewTimeoutMonitor creates a new timeout monitor.
// The monitor's internal context is derived from ctx, so cancelling ctx also
// stops the monitor (in addition to calling Stop explicitly).
func NewTimeoutMonitor(ctx context.Context, containerName string, maxDuration time.Duration, autoStop, stopGraceful bool, project string, log *logger.SessionLogger) *TimeoutMonitor {
	monCtx, cancel := context.WithCancel(ctx)
	return &TimeoutMonitor{
		ContainerName: containerName,
		MaxDuration:   maxDuration,
		AutoStop:      autoStop,
		StopGraceful:  stopGraceful,
		Project:       project,
		Logger:        log,
		ctx:           monCtx,
		cancel:        cancel,
		done:          make(chan struct{}),
	}
}

// Start starts the timeout monitor in a background goroutine
// Returns immediately - the monitor runs in the background
func (tm *TimeoutMonitor) Start() {
	if tm.MaxDuration == 0 {
		// No limit configured
		close(tm.done)
		return
	}

	tm.Logger.Printf("[limits] Container will auto-stop after %s", tm.MaxDuration)

	go tm.run()
}

// run is the main monitoring loop (runs in background goroutine)
func (tm *TimeoutMonitor) run() {
	defer close(tm.done)

	// Create a timer for the max duration
	timer := time.NewTimer(tm.MaxDuration)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Timer expired - stop container if auto-stop is enabled
		if tm.AutoStop {
			tm.handleTimeout()
		} else {
			tm.Logger.Printf("[limits] Runtime limit reached (%s) but auto_stop is disabled", tm.MaxDuration)
		}
	case <-tm.ctx.Done():
		// Monitor was cancelled before timeout
		return
	}
}

// handleTimeout handles the timeout event by stopping the container
func (tm *TimeoutMonitor) handleTimeout() {
	stopType := "gracefully"
	if !tm.StopGraceful {
		stopType = "forcefully"
	}
	tm.Logger.Printf("[limits] Runtime limit reached (%s), stopping container %s...", tm.MaxDuration, stopType)

	mgr := container.NewManager(tm.ContainerName)

	if tm.StopGraceful {
		// Graceful: try non-force first, escalate to force if needed
		// StopGraceful=true means graceful shutdown (force=false)
		if err := tm.stopContainerQuietly(false); err != nil {
			tm.Logger.Errorf("[limits] Graceful stop failed: %v, forcing...", err)
			if ferr := tm.stopContainerQuietly(true); ferr != nil {
				tm.Logger.Errorf("[limits] Force stop after graceful failure also failed: %v", ferr)
			}
		}

		// Verify the container actually stopped, force again if it is still
		// running. A failed status check is treated as "state unknown" and we
		// force to be safe rather than assume it stopped.
		time.Sleep(5 * time.Second)
		running, rerr := mgr.Running()
		if rerr != nil {
			tm.Logger.Errorf("[limits] Could not determine container state after graceful stop: %v, forcing...", rerr)
		}
		if running || rerr != nil {
			tm.Logger.Println("[limits] Container still running after graceful stop, forcing...")
			if ferr := tm.stopContainerQuietly(true); ferr != nil {
				tm.Logger.Errorf("[limits] Final force stop failed: %v", ferr)
			}
		}
	} else {
		// StopGraceful=false means force stop immediately (force=true)
		if err := tm.stopContainerQuietly(true); err != nil {
			tm.Logger.Errorf("[limits] Error force-stopping container: %v", err)
			return
		}
	}

	// Only claim success if the container is confirmed stopped, so the log does
	// not report enforcement that did not happen.
	if running, rerr := mgr.Running(); rerr == nil && running {
		tm.Logger.Errorf("[limits] Container still running after stop attempts; runtime limit may not be enforced")
		return
	}
	tm.Logger.Println("[limits] Container stopped due to runtime limit")
}

// stopContainerQuietly stops the container without streaming the incus
// subprocess output to the terminal. handleTimeout runs in a background
// goroutine while the AI tool session is attached, so container.Manager.Stop
// (which wires the incus subprocess stdio to os.Stdout/os.Stderr) would corrupt
// the user's TUI (issue #372 class). We capture the subprocess output and send
// it to the session log instead. A fresh timeout context is used so the stop
// completes even if the session's context is being cancelled concurrently.
func (tm *TimeoutMonitor) stopContainerQuietly(force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := container.StopContainerQuiet(ctx, tm.ContainerName, force)
	if s := strings.TrimSpace(out); s != "" {
		tm.Logger.Printf("[limits] incus stop output: %s", s)
	}
	return err
}

// Stop stops the timeout monitor
// This should be called when the session ends normally (before timeout)
func (tm *TimeoutMonitor) Stop() {
	tm.cancel()
	// Wait for the background goroutine to finish
	<-tm.done
}
