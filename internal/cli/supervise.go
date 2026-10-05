package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/limits"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/nftmonitor"
	"github.com/spf13/cobra"
)

// A shell session's security monitor, nft network monitor and runtime-limit
// timer must keep running for as long as the container does. They used to
// live inside the `coi shell` process and stop with its teardown — which runs
// as soon as `coi shell --background` returns, or when the user detaches or
// exits the agent while the container is kept running — leaving the agent
// unmonitored and its max_duration unenforced. `coi shell` now hands them to a
// per-container supervisor process (`coi supervise`, detached with setsid)
// that lives until the container stops or is deleted.

// supervisorPollInterval is how often the supervisor checks whether its
// container still exists.
const supervisorPollInterval = 2 * time.Second

// supervisorMaxQueryFailure is how long the supervisor keeps going while incus
// can't tell it the container's state: long enough to ride out a daemon
// restart, short enough not to leave a stray process behind forever.
const supervisorMaxQueryFailure = 5 * time.Minute

// supervisorState is what `coi shell` hands its supervisor: only the config
// sections the supervised services read. Tool, credential and environment
// settings are deliberately left out — they can hold secrets, and the
// supervisor doesn't need them.
type supervisorState struct {
	ContainerName string                  `json:"container_name"`
	WorkspacePath string                  `json:"workspace_path"`
	Incus         config.IncusConfig      `json:"incus"`
	Network       config.NetworkConfig    `json:"network"`
	Monitoring    config.MonitoringConfig `json:"monitoring"`
	Detection     config.DetectionConfig  `json:"detection"`
	Runtime       config.RuntimeLimits    `json:"runtime"`
}

// needsSupervisor reports whether a session has anything for a supervisor to
// run: security monitoring or a runtime limit.
func needsSupervisor(cfg *config.Config, runtime config.RuntimeLimits) bool {
	if config.BoolVal(cfg.Monitoring.Enabled) {
		return true
	}
	d, err := limits.ParseDuration(runtime.MaxDuration)
	return err == nil && d > 0
}

// supervisorPaths returns the state and lock file paths for a container.
func supervisorPaths(containerName string) (statePath, lockPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(home, ".coi", "run")
	return filepath.Join(dir, containerName+".supervisor.json"),
		filepath.Join(dir, containerName+".supervisor.lock"), nil
}

// lockSupervisor takes the container's supervisor lock without blocking. It
// returns (nil, nil) when another supervisor already holds it. The lock is
// released when the returned file is closed (or the process exits).
func lockSupervisor(lockPath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}

// startSessionSupervisor starts the container's supervisor unless one is
// already running for it (a re-attach keeps the existing one, so its runtime
// limit keeps counting from the original start). alreadyRunning reports the
// latter.
func startSessionSupervisor(state supervisorState, log *logger.SessionLogger) (alreadyRunning bool, err error) {
	statePath, lockPath, err := supervisorPaths(state.ContainerName)
	if err != nil {
		return false, err
	}
	held, err := lockSupervisor(lockPath)
	if err != nil {
		return false, fmt.Errorf("supervisor lock: %w", err)
	}
	if held == nil {
		log.Printf("[supervisor] already running for %s", state.ContainerName)
		return true, nil
	}
	// Probe only: the supervisor takes the lock itself.
	_ = held.Close()

	data, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		return false, err
	}

	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	cmd := exec.Command(exe, "supervise", "--state", statePath) //nolint:gosec // our own binary
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Dir = "/"
	// The supervisor writes its diagnostics to the session log itself; its
	// stdout/stderr only carry a startup failure, so send them there too.
	if out, err := os.OpenFile(log.ErrPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		cmd.Stdout, cmd.Stderr = out, out
		defer out.Close()
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start supervisor: %w", err)
	}
	_ = cmd.Process.Release()
	log.Printf("[supervisor] started for %s", state.ContainerName)
	return false, nil
}

// supervisorNotice is the line coi shell prints once the session supervisor
// owns the monitoring and runtime limit. The monitors used to announce
// themselves on the terminal from inside coi shell; the supervisor writes to
// the session log instead, so this says what it covers, that it outlives this
// command, and where to look. It never uses the [limits] prefix: runtime-limit
// diagnostics are kept off the terminal (#372).
func supervisorNotice(monitoring bool, maxDuration string, alreadyRunning bool, logPath string) string {
	var covers []string
	if monitoring {
		covers = append(covers, "security monitoring")
	}
	if d, err := limits.ParseDuration(maxDuration); err == nil && d > 0 {
		covers = append(covers, "the "+maxDuration+" max_duration limit")
	}
	what := strings.Join(covers, " and ")
	msg := "[supervisor] Running " + what + " until the container stops"
	if alreadyRunning {
		msg = "[supervisor] Already running for this container (" + what + ")"
	}
	if logPath != "" {
		msg += " (log: " + logPath + ")"
	}
	return msg
}

var superviseStatePath string

var superviseCmd = &cobra.Command{
	Use:    "supervise",
	Short:  "Run a session's monitoring and runtime limit until its container stops (internal)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runSupervisor(superviseStatePath)
	},
}

func init() {
	superviseCmd.Flags().StringVar(&superviseStatePath, "state", "", "Path to the supervisor state file")
	_ = superviseCmd.MarkFlagRequired("state")
}

// runSupervisor runs the container's monitoring and runtime-limit timer until
// the container stops or is deleted, then stops them (removing their nft
// rules) and exits.
func runSupervisor(statePath string) error {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read supervisor state: %w", err)
	}
	var state supervisorState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse supervisor state: %w", err)
	}
	_, lockPath, err := supervisorPaths(state.ContainerName)
	if err != nil {
		return err
	}
	held, err := lockSupervisor(lockPath)
	if err != nil {
		return fmt.Errorf("supervisor lock: %w", err)
	}
	if held == nil {
		return nil // another supervisor already runs for this container
	}
	defer held.Close()

	// Same process-wide settings `coi shell` applied for this session.
	container.Configure(state.Incus.Project, state.Incus.CodeUser, state.Incus.CodeUID)
	network.SetSudoAllowed(state.Network.SudoAllowed())

	home, _ := os.UserHomeDir()
	log := logger.New(state.ContainerName, home)
	defer log.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()

	cfg := &config.Config{
		Incus:      state.Incus,
		Network:    state.Network,
		Monitoring: state.Monitoring,
		Detection:  state.Detection,
	}
	a := &App{cfg: cfg}
	var mon monitor.MonitorDaemon
	var nft nftmonitor.NFTMonitorDaemon
	if teardown := a.startSessionMonitoring(ctx, state.ContainerName, state.WorkspacePath, log, &mon, &nft); teardown != nil {
		defer teardown()
	}

	if d, err := limits.ParseDuration(state.Runtime.MaxDuration); err == nil && d > 0 {
		tm := limits.NewTimeoutMonitor(ctx, state.ContainerName, d,
			config.BoolVal(state.Runtime.AutoStop), config.BoolVal(state.Runtime.StopGraceful),
			state.Incus.Project, log)
		tm.Start()
		defer tm.Stop()
	}

	log.Printf("[supervisor] supervising %s", state.ContainerName)
	ticker := time.NewTicker(supervisorPollInterval)
	defer ticker.Stop()
	var failingSince time.Time
	for {
		select {
		case <-ctx.Done():
			log.Printf("[supervisor] stopping (signal)")
			return nil
		case <-ticker.C:
			gone, why, err := containerGone(state.ContainerName)
			if err != nil {
				if failingSince.IsZero() {
					failingSince = time.Now()
				}
				if time.Since(failingSince) > supervisorMaxQueryFailure {
					log.Errorf("[supervisor] can't query %s for %s (%v), stopping", state.ContainerName, supervisorMaxQueryFailure, err)
					return nil
				}
				continue
			}
			failingSince = time.Time{}
			if gone {
				log.Printf("[supervisor] %s %s, stopping", state.ContainerName, why)
				return nil
			}
		}
	}
}

// containerGone reports whether the container was deleted or stopped. A
// frozen (auto-paused) container is still supervised. An incus error is
// returned rather than read as "gone": stopping the monitor on a transient
// failure would leave the container unwatched.
func containerGone(name string) (gone bool, why string, err error) {
	out, err := container.IncusOutput("list", "^"+name+"$", "--format=csv", "--columns=s")
	if err != nil {
		return false, "", err
	}
	gone, why = containerGoneFromStatus(out)
	return gone, why, nil
}

// containerGoneFromStatus interprets `incus list --columns=s` output for one
// container (split out so it can be tested without incus).
func containerGoneFromStatus(out string) (bool, string) {
	switch strings.ToUpper(strings.TrimSpace(out)) {
	case "":
		return true, "was deleted"
	case "STOPPED":
		return true, "stopped"
	default: // RUNNING, FROZEN, and transitional states
		return false, ""
	}
}
