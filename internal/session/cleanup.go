package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/tool"
)

// CleanupOptions contains options for cleaning up a session
type CleanupOptions struct {
	ContainerName  string
	SessionID      string    // Coi session ID for saving tool config data
	Persistent     bool      // If true, stop but don't delete container
	ProfileName    string    // Profile used for this session (saved in metadata for --resume)
	SessionsDir    string    // e.g., ~/.coi/sessions-claude
	SaveSession    bool      // Whether to save tool config directory
	Workspace      string    // Workspace directory path
	Tool           tool.Tool // AI coding tool being used
	NetworkManager network.NetworkManager
	SessionLogger  *logger.SessionLogger
	Logger         func(string)
	// ShutdownTimeout is how long (seconds) to wait for an in-progress guest
	// shutdown (`close`/poweroff) to finish before forcing the stop; <=0
	// uses config.DefaultShutdownTimeoutSeconds (callers should pass
	// cfg.Container.ShutdownTimeoutSeconds()).
	ShutdownTimeout int
}

// guestProber is the manager slice the shutdown-detection helpers need;
// narrow so unit tests can fake it.
type guestProber interface {
	ExecCommand(command string, opts container.ExecCommandOptions) (string, error)
	Running() (bool, error)
}

// probeExecTimeout bounds one guest probe: cleanup must never hang, and the
// exec transport CAN wedge against a dying (or responder-frozen) container.
const probeExecTimeout = 10 * time.Second

// Synthetic states probeGuestState derives from the probe's failure shape,
// distinct from anything `systemctl is-system-running` prints itself.
const (
	guestStateBusDown   = "coi:bus-down"   // guest answered: its D-Bus is gone (systemd tearing down)
	guestStateNoSystemd = "coi:no-systemd" // systemctl missing: this image can never answer
	guestStateNoAnswer  = "coi:no-answer"  // transport error or timeout: no evidence either way
	// guestStateShutdownRequested: the guest itself says a shutdown was asked
	// for — the coi power wrappers (close/stop/poweroff/...) left a fresh
	// marker, or a poweroff/halt/reboot job is queued in systemd.
	guestStateShutdownRequested = "coi:shutdown-requested"
)

// ShutdownMarkerPath is the marker the image's power wrappers (close, stop,
// poweroff, halt, reboot, shutdown) touch right before `systemctl --force
// poweroff`. It lives on /run (tmpfs, cleared every boot). Keep in sync with
// internal/image/build.sh.
const ShutdownMarkerPath = "/run/coi-shutdown-requested"

// guestProbeScript asks the guest everything the shutdown detector needs in ONE
// exec: systemd's manager state, whether a coi power wrapper just requested a
// shutdown (marker younger than a minute, so a stale one from a failed
// poweroff can't misfire), whether a poweroff-type job is queued (a graceful
// `systemctl poweroff`), and whether this image's wrappers write the marker at
// all. Only on an image whose wrappers write the marker is a single healthy
// answer trustworthy: every `close` there leaves positive evidence BEFORE the
// session ends, so "healthy, no marker, no queued job" can only be an exit.
const guestProbeScript = `systemctl is-system-running
[ -n "$(find ` + ShutdownMarkerPath + ` -newermt '60 seconds ago' 2>/dev/null)" ] && echo coi:marker
systemctl list-jobs --no-legend --no-pager 2>/dev/null | grep -Eq '(poweroff|halt|reboot|kexec)\.target' && echo coi:queued
grep -qs ` + ShutdownMarkerPath + ` /usr/local/libexec/coi-power && echo coi:marker-capable
systemctl is-system-running >/dev/null 2>&1`

// guestProbe is one answer from the guest.
type guestProbe struct {
	state string
	// markerCapable: the image's power wrappers write ShutdownMarkerPath, so a
	// single healthy answer already rules out a close.
	markerCapable bool
}

// probeGuestState runs guestProbeScript in the guest with a hard deadline and
// returns systemd's manager state ("stopping", "running", "degraded", ...) or
// one of the synthetic coi: states above. The script's exit status is
// is-system-running's, which is non-zero for every state except "running", so
// classification uses stdout first and the stderr of the ExitError second (the
// #588/#590 lesson: an incus-level failure and an in-guest failure arrive as
// the same error shape and MUST be told apart before deciding a container's
// fate).
func probeGuestState(mgr guestProber) guestProbe {
	type result struct {
		out string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := mgr.ExecCommand(guestProbeScript, container.ExecCommandOptions{Capture: true})
		ch <- result{out, err}
	}()
	select {
	case r := <-ch:
		return classifyGuestProbe(r.out, r.err)
	case <-time.After(probeExecTimeout):
		// Abandon the wedged exec goroutine; the process is exiting soon
		// anyway, and blocking teardown forever is the one forbidden outcome.
		return guestProbe{state: guestStateNoAnswer}
	}
}

// classifyGuestProbe turns the probe's output into a guestProbe.
func classifyGuestProbe(out string, err error) guestProbe {
	var p guestProbe
	state := ""
	requested := false
	for _, line := range strings.Split(out, "\n") {
		switch line = strings.TrimSpace(line); line {
		case "":
		case "coi:marker", "coi:queued":
			requested = true
		case "coi:marker-capable":
			p.markerCapable = true
		default:
			if state == "" {
				state = line
			}
		}
	}
	switch {
	case requested:
		p.state = guestStateShutdownRequested
		return p
	case state != "":
		p.state = state
		return p
	}
	var exitErr *container.ExitError
	if errors.As(err, &exitErr) {
		switch stderr := exitErr.Stderr; {
		case strings.Contains(stderr, "Failed to connect to bus"):
			// systemctl ran but systemd's bus is gone — on a container
			// that still reports Running, that IS the shutdown tail.
			p.state = guestStateBusDown
			return p
		case strings.Contains(stderr, "command not found"):
			p.state = guestStateNoSystemd
			return p
		}
	}
	p.state = guestStateNoAnswer
	return p
}

// Shutdown-detection timing. A `close`/poweroff transitions the container to
// stopped within seconds; a normal `exit` never does. We OBSERVE that from
// outside incus (Running()) rather than predict it from a racy in-guest probe.
const (
	shutdownProbeInterval = 500 * time.Millisecond
	// shutdownDetectWindow bounds how long we observe the container before
	// concluding a normal exit. It must outlast a `close`'s stop time (the guest
	// exec transport can go dark mid-`--force poweroff` while incus still reports
	// Running for a few seconds) without hanging teardown indefinitely.
	shutdownDetectWindow = 10 * time.Second
	// healthyConfirmChecks is how many consecutive healthy systemd answers rule
	// out a normal exit on an image whose power wrappers do NOT leave a marker.
	// A `close` briefly passes through a healthy "running" answer in the window
	// between the poweroff being requested and systemd flipping to "stopping",
	// so there a SINGLE healthy probe cannot be trusted — that single-probe
	// trust was the issue #616 misdetection ("Container kept running" printed
	// over a container that was actually powering off). On a marker-capable
	// image the close leaves positive evidence first, so one answer suffices.
	healthyConfirmChecks = 3
)

// guestShutdownInProgress reports whether the session ended because the container
// is shutting down (`close`/poweroff) rather than the user leaving the shell
// (`exit`). See shutdownInProgress; this is the production entry point.
func guestShutdownInProgress(mgr guestProber) bool {
	return shutdownInProgress(mgr, shutdownProbeInterval, shutdownDetectWindow, healthyConfirmChecks)
}

// shutdownInProgress decides shutdown-vs-exit from the OUTSIDE container state as
// the reliable signal, using the in-guest probe only as an accelerator that can
// ADD a positive detection but never veto one. Each poll, in order:
//
//   - container observed stopped (incus) -> shutdown (definitive; wins)
//   - guest reports a requested shutdown (coi wrapper marker / queued poweroff
//     job), systemd stopping, or bus down -> shutdown (fast positive)
//   - guest healthy N polls in a row -> normal exit (N in a row rules out the
//     brief pre-"stopping" window a close passes through; N is 1 on images
//     whose power wrappers leave a marker, since a close there is always
//     positively signalled before the session ends)
//   - image has no systemd -> normal exit (a close needs systemctl to fire)
//   - offline/unknown/no-answer -> ambiguous; keep observing
//
// If the container is still running with no positive signal when the window
// elapses, it was a normal exit. The function never returns true without
// positive evidence (an observed stop, or the guest itself saying it is
// shutting down), so it can never force-stop a container the user meant to keep.
func shutdownInProgress(mgr guestProber, interval, window time.Duration, healthyToExit int) bool {
	deadline := time.Now().Add(window)
	healthy := 0
	for {
		// Definitive, from outside incus: the container actually stopped. Checked
		// first each poll so a stop observed at any point wins immediately.
		if running, err := mgr.Running(); err == nil && !running {
			return true
		}

		probe := probeGuestState(mgr)
		switch probe.state {
		case "stopping", guestStateBusDown, guestStateShutdownRequested:
			return true
		case "running", "degraded", "maintenance", "initializing", "starting":
			healthy++
			if healthy >= healthyToExit || probe.markerCapable {
				return false
			}
		case guestStateNoSystemd:
			// This image can never answer, and a `close` needs systemctl to fire
			// in the first place — treat as a normal exit (the outside-state check
			// above still catches an externally-stopped container).
			return false
		default: // "offline", "unknown", coi:no-answer, anything unforeseen
			healthy = 0 // ambiguous — a healthy streak must be consecutive
		}

		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

// containerRunning reports the container's state and whether it could be
// determined at all. A daemon hiccup must not read as "stopped" — that is
// what would route an ephemeral cleanup into force-delete of a live
// container, or print "kept (stopped)" over a running one.
func containerRunning(mgr guestProber) (running, ok bool) {
	var err error
	for i := 0; i < 3; i++ {
		if running, err = mgr.Running(); err == nil {
			return running, true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false, false
}

// waitForStopped polls until the container verifiably stops (an error-free
// "not running" answer — daemon errors don't count), the timeout elapses, or
// the user interrupts. Ctrl+C must not be a no-op here: this wait can hold
// the terminal for the whole graceful-shutdown window, and the shell's own
// signal plumbing is already disarmed by the time the deferred teardown runs.
func waitForStopped(mgr guestProber, timeout time.Duration) (stopped, interrupted bool) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if running, err := mgr.Running(); err == nil && !running {
			return true, false
		}
		select {
		case <-sig:
			return false, true
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false, false
}

// Cleanup stops and deletes a container, optionally saving session data
func Cleanup(opts CleanupOptions) error {
	// Default logger
	if opts.Logger == nil {
		opts.Logger = func(msg string) {
			fmt.Fprintf(os.Stderr, "[cleanup] %s\n", msg)
		}
	}

	// Clear host-side immutable bits early, before any container operations.
	// This ensures immutable bits are cleared even if the container is already
	// stopped/deleted, and must happen before container deletion so the host
	// files are writable again.
	if opts.ContainerName != "" {
		RemoveImmutable(opts.ContainerName, opts.Logger)
	}

	if opts.ContainerName == "" {
		opts.Logger("No container to clean up")
		return nil
	}

	mgr := container.NewManager(opts.ContainerName)

	// Check if container exists
	// Containers are always launched as non-ephemeral, so they should exist even when stopped
	exists, err := mgr.Exists()
	if err != nil {
		opts.Logger(fmt.Sprintf("Warning: Could not check container existence: %v", err))
	}

	// Save session data immediately — no pre-delay regardless of persistence mode.
	// saveSessionData handles the mid-shutdown race internally: on a transient SFTP
	// error it waits for the container to fully stop, then retries using incus's
	// direct file-access path (no SFTP) so the save succeeds in every exit scenario.
	saveFailed := false
	if opts.SaveSession && exists && opts.SessionID != "" && opts.SessionsDir != "" && opts.Tool != nil && opts.Tool.ConfigDirName() != "" {
		if err := saveSessionData(mgr, opts.ContainerName, opts.SessionID, opts.Persistent, opts.ProfileName, opts.Workspace, opts.SessionsDir, opts.Tool, opts.Logger); err != nil {
			opts.Logger(fmt.Sprintf("Warning: Failed to save session data: %v", err))
			saveFailed = true
		}
	}

	// Determine the container's end state. `close`/poweroff powers the guest
	// off, but the shell dies at the START of that shutdown, so "running
	// right now" is ambiguous: ask the guest's systemd whether a shutdown is
	// in flight instead of guessing from a fixed wait. The old fixed ~5s
	// poll mislabeled any slower shutdown as a normal `exit`, leaking
	// ephemeral containers and printing "kept running" over a stopping one.
	running := false
	if exists {
		var known bool
		running, known = containerRunning(mgr)
		switch {
		case !known:
			// Incus can't answer right now: fail safe. Claim nothing about
			// the state and do nothing destructive.
			opts.Logger("Warning: could not determine container state (incus unreachable) - leaving the container untouched")
			running = true
		case running && guestShutdownInProgress(mgr):
			timeout := opts.ShutdownTimeout
			if timeout <= 0 {
				timeout = config.DefaultShutdownTimeoutSeconds
			}
			opts.Logger("Container is shutting down, waiting for it to stop...")
			stopped, interrupted := waitForStopped(mgr, time.Duration(timeout)*time.Second)
			if !stopped {
				// The shutdown is positively known at this point — finish the
				// job rather than relapse into "kept running" (stock systemd
				// units get 90s stop budgets, longer than our default window;
				// this is the same escalation `coi shutdown` applies after
				// its graceful window).
				if interrupted {
					opts.Logger("Interrupted - forcing the stop...")
				} else {
					opts.Logger(fmt.Sprintf("Still shutting down after %ds - forcing the stop...", timeout))
				}
				if err := mgr.Stop(true); err != nil {
					opts.Logger(fmt.Sprintf("Warning: force stop failed: %v", err))
				}
			}
			// Re-read the final state; if incus can't answer, the shutdown we
			// positively detected is the best evidence — treat as stopped.
			if r, ok := containerRunning(mgr); ok {
				running = r
			} else {
				running = false
			}
		}
	}

	// Handle container based on persistence mode
	if opts.Persistent {
		// Persistent mode: keep the container — and report its ACTUAL state,
		// so a `close` doesn't get answered with "use 'coi attach'".
		switch {
		case !exists:
			opts.Logger("Container no longer exists - nothing to keep")
		case running:
			opts.Logger("Container kept running - use 'coi attach' to reconnect, 'coi shutdown' to stop, or 'coi kill' to force stop")
		default:
			opts.Logger("Container kept (stopped) - run 'coi shell' in this workspace to start it again")
		}
	} else {
		// Non-persistent mode: behavior depends on how user exited.
		// - Container still running (user typed 'exit' or detached): keep it running.
		// - Container stopped or shutting down (user ran 'close'/'sudo poweroff'): delete it.
		if exists {
			if running {
				// Container still running - user exited normally, keep it for potential re-attach.
				opts.Logger("Container kept running - use 'coi attach' to reconnect, 'coi shutdown' to stop, or 'coi kill' to force stop")
			} else {
				// Container stopped (user ran 'sudo poweroff') - delete it.
				opts.Logger("Container was stopped, removing...")

				// Clean up network FIRST while container still exists
				// This ensures we can get the container IP to remove firewall rules
				if opts.NetworkManager != nil {
					if err := opts.NetworkManager.Teardown(context.Background(), opts.ContainerName); err != nil {
						opts.Logger(fmt.Sprintf("Warning: Failed to cleanup network: %v", err))
					}
				}

				// Now delete container
				if err := mgr.Delete(true); err != nil {
					opts.Logger(fmt.Sprintf("Warning: Failed to delete container: %v", err))
				} else if saveFailed {
					// Don't claim the data is safe when the save above failed —
					// with the container gone it is unrecoverable.
					opts.Logger("Container removed (session data could NOT be saved - see the warning above)")
				} else {
					opts.Logger("Container removed (session data saved for --resume)")
				}
			}
		} else {
			opts.Logger("Container was already removed")
			// The container was deleted out from under us — typically the threat
			// responder auto-killed it (it stops+deletes the container itself), or
			// it was removed externally. The block above (which runs Teardown) is
			// skipped in that case, so without this backstop the per-IP nft rules
			// would be orphaned until the next `coi clean --orphans`. Teardown uses
			// the cached setup-time IP and is idempotent, so it is safe to run here
			// even if the responder already cleaned up. (Fixes the intermittent
			// auto-kill nft-rule-cleanup flake.)
			if opts.NetworkManager != nil {
				if err := opts.NetworkManager.Teardown(context.Background(), opts.ContainerName); err != nil {
					opts.Logger(fmt.Sprintf("Warning: Failed to cleanup network after external removal: %v", err))
				}
			}
		}
	}

	if opts.SessionLogger != nil {
		if err := opts.SessionLogger.Close(); err != nil && opts.Logger != nil {
			opts.Logger(fmt.Sprintf("Warning: failed to close session log: %v", err))
		}
	}

	return nil
}

// saveSessionData saves the tool config directory from the container
func saveSessionData(mgr container.ContainerManager, containerName string, sessionID string, persistent bool, profileName string, workspace string, sessionsDir string, t tool.Tool, logger func(string)) error {
	// Determine home directory
	// For coi images, we always use /home/code
	// For other images, we use /root
	// Since we currently only support coi images, always use /home/code
	homeDir := "/home/" + container.CodeUser

	configDirName := t.ConfigDirName()
	stateDir := filepath.Join(homeDir, configDirName)

	// Create local session directory
	localSessionDir := filepath.Join(sessionsDir, sessionID)
	if err := os.MkdirAll(localSessionDir, 0o755); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	logger(fmt.Sprintf("Saving session data to %s", localSessionDir))

	// Pull into a fresh sibling first and only replace the previous copy once
	// the new one is complete: deleting the old copy up front lost the only
	// backup whenever the pull then failed.
	localConfigDir := filepath.Join(localSessionDir, configDirName)
	stagingDir := localConfigDir + ".coi-new"
	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("failed to clear staging directory: %w", err)
	}

	// Fast path: one tar stream from the running container (seconds faster
	// than a file-by-file SFTP walk of a busy config dir). It needs a running
	// container; anything else falls back to `incus file pull` below.
	pulled := false
	if tp, ok := mgr.(tarPuller); ok {
		if err := tp.PullDirectoryTar(stateDir, stagingDir); err == nil {
			pulled = true
		} else {
			_ = os.RemoveAll(stagingDir)
			if !strings.Contains(strings.ToLower(err.Error()), "no such file") {
				logger(fmt.Sprintf("Fast session save unavailable (%v); using file pull", err))
			}
		}
	}

	// Pull config directory from container.
	//
	// On the normal exit path the container is running and SFTP is healthy —
	// the first attempt succeeds immediately.
	//
	// On the poweroff path, cleanup may start while the container's SFTP subsystem
	// is still mid-teardown (sshd killed by init, container not yet fully stopped).
	// On a transient SFTP/connection error we wait up to 5 s for the container to
	// fully stop, then retry. Once stopped, incus switches to direct file access
	// (no SFTP), so the retry reliably succeeds.
	var pullErr error
	for attempt := 0; attempt < 3 && !pulled; attempt++ {
		if attempt > 0 {
			// SFTP failed — wait for the container to fully stop so incus
			// uses direct file access (not SFTP) on the next attempt.
			waitForStopped(mgr, 5*time.Second)
			_ = os.RemoveAll(stagingDir)
		}
		pullErr = mgr.PullDirectory(stateDir, stagingDir)
		if pullErr == nil {
			pulled = true
			break
		}
		msg := strings.ToLower(pullErr.Error())
		if strings.Contains(msg, "does not exist") ||
			strings.Contains(msg, "not found") ||
			strings.Contains(msg, "no such file") {
			logger(fmt.Sprintf("No %s directory found in container", configDirName))
			return nil
		}
		if !strings.Contains(msg, "sftp") &&
			!strings.Contains(msg, "unexpected eof") &&
			!strings.Contains(msg, "bad file descriptor") &&
			!strings.Contains(msg, "server unexpectedly closed") &&
			!strings.Contains(msg, "error receiving version packet") {
			break
		}
	}
	if !pulled {
		_ = os.RemoveAll(stagingDir)
		return fmt.Errorf("failed to pull %s directory: %w", configDirName, pullErr)
	}

	// Swap the new copy in.
	if _, err := os.Stat(localConfigDir); err == nil {
		logger("Removing old session data before saving new state")
		if err := os.RemoveAll(localConfigDir); err != nil {
			return fmt.Errorf("failed to remove old %s directory: %w", configDirName, err)
		}
	}
	if err := os.Rename(stagingDir, localConfigDir); err != nil {
		return fmt.Errorf("failed to store pulled %s directory: %w", configDirName, err)
	}

	// Save metadata
	metadata := SessionMetadata{
		SessionID:     sessionID,
		ContainerName: containerName,
		Persistent:    persistent,
		ProfileName:   profileName,
		Workspace:     workspace,
		SavedAt:       getCurrentTime(),
	}

	metadataPath := filepath.Join(localSessionDir, "metadata.json")
	if err := saveMetadata(metadataPath, metadata); err != nil {
		// Non-fatal - session data is already saved
		logger(fmt.Sprintf("Warning: Failed to save metadata: %v", err))
	}

	logger("Session data saved successfully")
	return nil
}

// tarPuller is implemented by *container.Manager: a one-stream directory pull
// from a running container (see PullDirectoryTar).
type tarPuller interface {
	PullDirectoryTar(containerPath, localPath string) error
}

// SessionMetadata contains information about a saved session
type SessionMetadata struct {
	SessionID     string `json:"session_id"`
	ContainerName string `json:"container_name"`
	Persistent    bool   `json:"persistent"`
	ProfileName   string `json:"profile_name"`
	Workspace     string `json:"workspace"`
	SavedAt       string `json:"saved_at"`
}

// saveMetadata saves session metadata to a JSON file
func saveMetadata(path string, metadata SessionMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// getCurrentTime returns current time in RFC3339 format
func getCurrentTime() string {
	return time.Now().Format(time.RFC3339)
}

// SaveMetadataEarly saves session metadata at session start so coi list can show correct status
func SaveMetadataEarly(sessionsDir, sessionID, containerName, workspace string, persistent bool, profileName string) error {
	// Create session directory if it doesn't exist
	sessionDir := filepath.Join(sessionsDir, sessionID)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	metadata := SessionMetadata{
		SessionID:     sessionID,
		ContainerName: containerName,
		Persistent:    persistent,
		ProfileName:   profileName,
		Workspace:     workspace,
		SavedAt:       getCurrentTime(),
	}

	metadataPath := filepath.Join(sessionDir, "metadata.json")
	return saveMetadata(metadataPath, metadata)
}

// SessionExists checks if a session with the given ID exists and is valid
func SessionExists(sessionsDir, sessionID string) bool {
	metadataPath := filepath.Join(sessionsDir, sessionID, "metadata.json")
	info, err := os.Stat(metadataPath)
	return err == nil && !info.IsDir()
}

// ListSavedSessions lists all saved sessions in the sessions directory
func ListSavedSessions(sessionsDir string) ([]string, error) {
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var sessions []string
	for _, entry := range entries {
		if entry.IsDir() {
			// Check if it contains a metadata.json file (tool-agnostic indicator)
			metadataPath := filepath.Join(sessionsDir, entry.Name(), "metadata.json")
			if info, err := os.Stat(metadataPath); err == nil && !info.IsDir() {
				sessions = append(sessions, entry.Name())
			}
		}
	}

	return sessions, nil
}

// GetLatestSession returns the most recently saved session ID
func GetLatestSession(sessionsDir string) (string, error) {
	sessions, err := ListSavedSessions(sessionsDir)
	if err != nil {
		return "", err
	}

	if len(sessions) == 0 {
		return "", fmt.Errorf("no saved sessions found")
	}

	// Find the most recent session by reading metadata
	var latestSession string
	var latestTime time.Time

	for _, sessionID := range sessions {
		metadataPath := filepath.Join(sessionsDir, sessionID, "metadata.json")
		metadata, err := LoadSessionMetadata(metadataPath)
		if err != nil {
			continue // Skip sessions without valid metadata
		}

		savedTime, err := time.Parse(time.RFC3339, metadata.SavedAt)
		if err != nil {
			continue
		}

		if latestSession == "" || savedTime.After(latestTime) {
			latestSession = sessionID
			latestTime = savedTime
		}
	}

	if latestSession == "" {
		return "", fmt.Errorf("no valid sessions found")
	}

	return latestSession, nil
}

// GetLatestSessionForWorkspace returns the most recent session ID for a specific workspace
func GetLatestSessionForWorkspace(sessionsDir, workspacePath, sessionName string) (string, error) {
	sessions, err := ListSavedSessions(sessionsDir)
	if err != nil {
		return "", err
	}

	if len(sessions) == 0 {
		return "", fmt.Errorf("no saved sessions found")
	}

	// Get the identity hash to match against. Saved sessions embed it in
	// their container name, so sessions saved under one session_name match
	// from ANY workspace — that is what lets --resume continue a named
	// session after the workspace moved. Sessions saved BEFORE a name was
	// adopted are path-keyed, so this workspace's path hash is a FALLBACK,
	// consulted only when NO session matches the named identity: adding
	// session_name must not orphan history, but a newer path-keyed session
	// (this path's pre-adoption life, or an unrelated project that once used
	// the path) must never shadow the named session's own history.
	identityHash := IdentityHash(workspacePath, sessionName)
	legacyHash := ""
	if sessionName != "" {
		legacyHash = WorkspaceHash(workspacePath)
	}

	// Find the most recent session for this identity, tracking the legacy
	// path-keyed candidate separately so it can never outrank a named match.
	var latestSession, latestLegacy string
	var latestTime, latestLegacyTime time.Time

	for _, sessionID := range sessions {
		metadataPath := filepath.Join(sessionsDir, sessionID, "metadata.json")
		metadata, err := LoadSessionMetadata(metadataPath)
		if err != nil {
			continue // Skip sessions without valid metadata
		}

		// Extract workspace hash from container name (format: claude-<hash>-<slot>)
		sessionHash, _, err := ParseContainerName(metadata.ContainerName)
		if err != nil {
			continue
		}

		savedTime, err := time.Parse(time.RFC3339, metadata.SavedAt)
		if err != nil {
			continue
		}

		switch sessionHash {
		case identityHash:
			if latestSession == "" || savedTime.After(latestTime) {
				latestSession = sessionID
				latestTime = savedTime
			}
		case legacyHash:
			if legacyHash != "" && (latestLegacy == "" || savedTime.After(latestLegacyTime)) {
				latestLegacy = sessionID
				latestLegacyTime = savedTime
			}
		}
	}

	if latestSession == "" {
		latestSession = latestLegacy
	}

	if latestSession == "" {
		return "", fmt.Errorf("no saved sessions found for workspace %s", workspacePath)
	}

	return latestSession, nil
}

// LoadSessionMetadata loads session metadata from a JSON file
func LoadSessionMetadata(path string) (*SessionMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var metadata SessionMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	if metadata.SessionID == "" {
		return nil, fmt.Errorf("invalid metadata: missing session_id")
	}

	return &metadata, nil
}
