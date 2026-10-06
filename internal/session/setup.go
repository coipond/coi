// Package session sets up, runs and tears down coi sessions: container
// launch and configuration, mounts, credentials, git identity and guards,
// security hardening, and cleanup.
package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/limits"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/timing"
	"github.com/coipond/coi/internal/tool"
)

// Container images: DefaultImage is the stock base image, CoiImage the
// coi-built image used by default.
const (
	DefaultImage = "images:ubuntu/22.04"
	CoiImage     = "coi-default"
)

// GitOptions groups the git identity and commit-attribution settings applied
// inside the container. Grouping keeps the related [git] config together as
// SetupOptions is decomposed from a flat bag into a tree.
type GitOptions struct {
	Identity                 GitIdentity // Resolved host git identity to configure inside the container
	Readonly                 bool        // Identity is provided by a read-only ~/.gitconfig mount; skip the in-container git config writes
	StripAttribution         bool        // [git] strip_attribution: install the global commit-msg hook stripping AI co-author/footer lines
	StripAttributionPatterns []string    // [git] strip_attribution_patterns: override the default strip patterns (grep -E, per line)
	ProtectedBranches        []string    // [git] protected_branches (already resolved): pre-commit/pre-push guard set; empty = guard off
}

// SecurityOptions groups the container's security posture: which host paths are
// mounted read-only or masked, host-side immutability, and the docker /
// kernel-surface hardening flags (read together by hardeningPolicyFrom).
type SecurityOptions struct {
	ProtectedPaths            []string               // Paths to mount read-only (e.g., .git/hooks, .vscode)
	Config                    *config.SecurityConfig // Security config so worktree-config expansion honors disable_protection/writable_paths (nil = expand unconditionally)
	SecretPaths               []string               // Workspace-relative globs to MASK (empty read-only mount hides contents)
	HostImmutable             bool                   // Apply chattr +i on host-side protected paths (set by CLI from config)
	Docker                    bool                   // [container] docker: nesting + syscall interception + low-port sysctl (precedence vs ReduceKernelSurface resolved by container.HardeningPolicy.DockerEnabled)
	ReduceKernelSurface       bool                   // [security] reduce_kernel_surface: deny high-risk kernel-escape syscalls; wins over Docker
	ReduceKernelSurfaceStrict bool                   // [security] reduce_kernel_surface_strict: additionally deny perf_event_open (implies ReduceKernelSurface)
}

// NetworkOptions groups network isolation and host<->container forwarding.
type NetworkOptions struct {
	Config          *config.NetworkConfig // Network isolation mode + rules
	Ports           *PortConfig           // Configured [[ports]] entries to publish on the host
	Sockets         *SocketConfig         // Forwarded host unix sockets
	ForwardSSHAgent bool                  // Forward host SSH agent to container
}

// ContextOptions groups the sandbox-context injection settings.
type ContextOptions struct {
	FilePath         string   // Custom context .md file on host (overrides tool default)
	ProfileFile      string   // Profile context .md file (appended to sandbox context)
	Auto             *bool    // Auto-inject sandbox context into tool's native system (default: true)
	JSON             *bool    // Write ~/SANDBOX_CONTEXT.json for programmatic consumers (default: true)
	JSONFilePath     string   // Custom context .json file on host (overrides the generated JSON)
	ForwardedEnvVars []string // Names of host env vars being forwarded (for context file)
}

// SetupOptions contains options for setting up a session. Cohesive groups of
// related settings live in sub-structs (Git, Security, Network, Context); the
// remaining fields are session/container basics that don't cluster.
type SetupOptions struct {
	WorkspacePath         string
	SessionName           string // [container] session_name: keys the session identity instead of the workspace path when set
	Image                 string
	StoragePool           string // [container] storage_pool: Incus storage pool for the container (empty = Incus default pool)
	Persistent            bool   // Keep container between sessions (don't delete on cleanup)
	ResumeFromID          string
	Slot                  int
	MountConfig           *MountConfig         // Multi-mount support
	CredentialConfig      *CredentialConfig    // Configured [[credentials]] entries (catalog + ad-hoc)
	SessionsDir           string               // e.g., ~/.coi/sessions-claude
	CLIConfigPath         string               // e.g., ~/.claude (host CLI config to copy credentials from)
	Tool                  tool.Tool            // AI coding tool being used
	PermissionMode        string               // Tool permission mode: "bypass" (default) or "interactive"; gates Claude auto-mode suppression (#764)
	DisableShift          bool                 // Disable UID shifting (for Colima/Lima environments)
	LimitsConfig          *config.LimitsConfig // Resource and time limits
	IncusProject          string               // Incus project name
	PreserveWorkspacePath bool                 // Mount workspace at same path as host instead of /workspace
	Timezone              string               // Resolved IANA timezone name (e.g., "America/New_York"), empty for UTC
	Alias                 string               // Human-friendly alias for this container (set user.coi.alias)
	ReadyTimeout          int                  // Seconds to wait for the container to become ready (<=0 = default 30)
	ContainerName         string               // Use existing container (for testing) - skips container creation
	Logger                func(string)

	Git      GitOptions      // Git identity + commit-attribution policy applied inside the container
	Security SecurityOptions // Read-only/masked paths, host immutability, docker/kernel-surface hardening
	Network  NetworkOptions  // Network isolation + host<->container forwarding (ports, sockets, ssh-agent)
	Context  ContextOptions  // Sandbox-context file injection
}

// SetupResult contains the result of setup
type SetupResult struct {
	ContainerName          string
	Manager                container.ContainerManager
	NetworkManager         network.NetworkManager
	TimeoutMonitor         *limits.TimeoutMonitor
	Logger                 *logger.SessionLogger
	HomeDir                string
	RunAsRoot              bool
	Image                  string
	ContainerWorkspacePath string            // Path where workspace is mounted inside container (default: /workspace)
	SSHAgentSocketPath     string            // SSH agent socket path in container (empty if not forwarded)
	SocketEnv              map[string]string // env var name -> in-container path for all forwarded sockets
	PortsEnv               map[string]string // env var name -> host port for all published [[ports]]
	PublishedPorts         []PublishedPort   // ports published on the host this session (for the context file)
	Timezone               string            // Resolved timezone applied to the container (empty = UTC)
	HasImmutableProtection bool              // True if host-side immutable attribute was applied to protected paths
}

// Setup initializes a container for a Claude session.
//
// It builds the container up in a fixed sequence of small phases (see
// setup_phases.go), each mutating a shared setupState. The former ~600-line
// body is now this driver plus one method per numbered step. Cleanup on failure
// is unchanged: Setup is forward-only, and the caller's session.Cleanup handles
// teardown, so the phases register no teardowns of their own.
func Setup(ctx context.Context, opts SetupOptions) (*SetupResult, error) {
	// Default logger
	if opts.Logger == nil {
		opts.Logger = func(msg string) {
			fmt.Fprintf(os.Stderr, "[setup] %s\n", msg)
		}
	}

	st := &setupState{opts: opts, result: &SetupResult{}}

	pipe := &Pipeline{}
	if err := pipe.Run(ctx,
		phase("resolve-name", st.phaseResolveName),
		phase("validate-bedrock", st.phaseValidateBedrock),
		phase("ensure-bridge", st.phaseEnsureBridge),
		phase("resolve-image", st.phaseResolveImage),
		phase("reconcile-existing", st.phaseReconcileExisting),
		phase("filter-trusted", st.phaseFilterTrusted),
		phase("preflight-ports", st.phasePreflightPorts),
		phase("create-container", st.phaseCreateContainer),
		phase("wait-ready", st.phaseWaitReady),
		phase("configure-docker-bridge", st.phaseConfigureDockerBridge),
		phase("size-tmpfs", st.phaseSizeTmpfs),
		phase("detect-user", st.phaseDetectUser),
		phase("remap-uid", st.phaseRemapUID),
		phase("forward-sockets", st.phaseForwardSockets),
		phase("publish-ports", st.phasePublishPorts),
		phase("configure-git", st.phaseConfigureGit),
		phase("claude-settings", st.phaseClaudeSettings),
		phase("configure-timezone", st.phaseConfigureTimezone),
		phase("start-timeout-monitor", st.phaseStartTimeoutMonitor),
		phase("setup-network", st.phaseSetupNetwork),
		phase("resume-restore", st.phaseResumeRestore),
		phase("mounts-context-path", st.phaseMountsAndContextPath),
		phase("setup-cli-config", st.phaseSetupCLIConfig),
		phase("apply-tool-env", st.phaseApplyToolEnv),
		phase("setup-credentials", st.phaseSetupCredentials),
		phase("inject-context", st.phaseInjectContext),
	); err != nil {
		// Pipeline.Run annotates a failing phase's error as "<phase>: %w". Setup's
		// phases already return user-facing, actionable messages (e.g. "image 'X'
		// not found - run 'coi build' first"), so strip that one layer of phase
		// annotation before returning. A non-phase error such as context
		// cancellation is returned bare (Unwrap yields nil) and passes through.
		if phaseErr := errors.Unwrap(err); phaseErr != nil {
			return nil, phaseErr
		}
		return nil, err
	}

	st.opts.Logger("Container setup complete!")
	return st.result, nil
}

// dockerDaemonJSON is the daemon.json written to new containers.
// It merges two concerns:
//   - "group": "code" — preserves the base-image setting that gives the
//     non-root `code` user access to /var/run/docker.sock (also enforced
//     via a systemd socket drop-in written in build.sh). Omitting this
//     regresses non-root Docker access after a container reboot.
//   - "bip" / "default-address-pools" — avoid Docker bridge IP conflicts.
//     Docker's built-in pool (172.17–172.29) overlaps with many corporate
//     VPNs and cloud subnets. The chosen ranges (172.30.x, 172.31.x) sit
//     at the far end of RFC 1918's 172.16.0.0/12 block where conflicts are
//     rare in practice.
const dockerDaemonJSON = `{
  "group": "code",
  "bip": "172.30.0.1/24",
  "default-address-pools": [
    {"base": "172.31.0.0/16", "size": 24}
  ]
}`

// ConfigureDockerDaemon writes /etc/docker/daemon.json inside the container
// to configure bridge CIDRs that don't overlap with the host network.
func ConfigureDockerDaemon(mgr container.ContainerExecution, logFn func(string)) error {
	cmd := fmt.Sprintf(
		"mkdir -p /etc/docker && printf '%%s' %s > /etc/docker/daemon.json",
		shellEscape(dockerDaemonJSON),
	)
	if _, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true}); err != nil {
		return fmt.Errorf("write /etc/docker/daemon.json: %w", err)
	}
	logFn("Configured Docker bridge CIDRs (172.30.0.0/24, 172.31.0.0/16)")
	return nil
}

// shellEscape single-quotes a string for safe interpolation in a shell command.
func shellEscape(s string) string {
	escaped := strings.ReplaceAll(s, "'", "'\"'\"'")
	return "'" + escaped + "'"
}

// ErrNotReady is the sentinel wrapped by WaitForReady's timeout error, so
// callers can tell "the window expired" apart from cancellation or probe
// errors (e.g. to attach cause hints — see AnnotateReadyTimeout).
var ErrNotReady = errors.New("container failed to become ready")

// ErrStoppedDuringBoot is the sentinel for a container that stopped while
// WaitForReady was waiting for it, i.e. its start failed. It is reported at once
// with the start log's errors instead of after the whole readiness window.
var ErrStoppedDuringBoot = errors.New("container stopped during boot")

// stoppedConfirmations is how many consecutive "not running" probes make
// WaitForReady give up early, so a single odd status answer can't end a wait.
const stoppedConfirmations = 3

// startLogReader is implemented by *container.Manager; kept out of
// container.ContainerManager so test fakes needn't grow it.
type startLogReader interface {
	StartLogErrors(maxLines int) []string
}

// WaitForReady waits for the container to be ready: running AND able to
// execute a command. It probes once per second for up to maxRetries seconds
// and honors ctx cancellation between probes (a SIGINT-cancelled context
// stops the wait immediately instead of sleeping out the window against a
// container the signal handler already tore down). This is the single
// readiness chokepoint for every wait-for-container path (shell, run, health
// probes) — private copies of this loop drift, as coi run's no-sleep variant
// proved.
func WaitForReady(ctx context.Context, mgr container.ContainerManager, maxRetries int, logger func(string)) error {
	return waitForReady(ctx, mgr, time.Duration(maxRetries)*time.Second, readyPollInterval, logger)
}

// readyPollInterval is how often WaitForReady re-probes. It used to be a full
// second, so a container that became ready a moment after the first probe
// (the usual case right after a start) cost almost a second of nothing.
const readyPollInterval = 200 * time.Millisecond

func waitForReady(ctx context.Context, mgr container.ContainerManager, timeout, interval time.Duration, logger func(string)) error {
	defer timing.Start(timing.CatStep, "wait-for-ready")()
	logger("Waiting for container to be ready...")
	start := time.Now()
	deadline := start.Add(timeout)
	nextNote := 5 * time.Second
	notRunning := 0
	for {
		// A command that runs proves the container is running AND usable, so
		// try it first: on an already-running container that is the only call.
		if _, err := mgr.ExecCommand("echo ready", container.ExecCommandOptions{Capture: true}); err == nil {
			return nil
		}
		// Not usable yet. Surface a real status-query failure (incus down)
		// as an error rather than waiting out the window.
		running, err := mgr.Running()
		if err != nil {
			return fmt.Errorf("failed to check container status: %w", err)
		}
		// Every caller waits on a container it has just started, so one that is
		// not running is not booting slowly: its start failed. Report that now,
		// with the reason from the start log, instead of probing a stopped
		// container until the window runs out.
		if running {
			notRunning = 0
		} else {
			notRunning++
			if notRunning >= stoppedConfirmations {
				return stoppedDuringBootError(mgr)
			}
		}

		// No sleep after the final probe — it would delay the error for
		// nothing.
		if !time.Now().Add(interval).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
		if waited := time.Since(start); waited >= nextNote {
			logger(fmt.Sprintf("Still waiting... (%ds)", int(waited.Seconds())))
			nextNote += 5 * time.Second
		}
	}

	return fmt.Errorf("%w after %d seconds", ErrNotReady, int(timeout.Seconds()))
}

// stoppedDuringBootError builds the ErrStoppedDuringBoot error, quoting the
// errors of the container's start log when they can be read.
func stoppedDuringBootError(mgr container.ContainerManager) error {
	const reason = "it is not running, so its start most likely failed"
	if r, ok := mgr.(startLogReader); ok {
		if lines := r.StartLogErrors(6); len(lines) > 0 {
			return fmt.Errorf("%w: %s; start log errors:\n  %s", ErrStoppedDuringBoot, reason, strings.Join(lines, "\n  "))
		}
	}
	return fmt.Errorf("%w: %s (see `incus info --show-log <container>`)", ErrStoppedDuringBoot, reason)
}

// AnnotateReadyTimeout appends a cause hint to a WaitForReady timeout when
// disk I/O limits were active during boot: a low configured rate (e.g.
// read = "100kB") throttles the container's root disk while it is still
// booting and can starve startup past the readiness window — a failure mode
// that otherwise presents as a bare, misleading timeout. Errors other than
// the ErrNotReady timeout (cancellation, probe failures) pass through
// unchanged.
func AnnotateReadyTimeout(err error, limitsCfg *config.LimitsConfig) error {
	if err == nil || limitsCfg == nil || !errors.Is(err, ErrNotReady) {
		return err
	}
	var active []string
	if limitsCfg.Disk.Read != "" {
		active = append(active, "read="+limitsCfg.Disk.Read)
	}
	if limitsCfg.Disk.Write != "" {
		active = append(active, "write="+limitsCfg.Disk.Write)
	}
	if limitsCfg.Disk.Max != "" {
		active = append(active, "max="+limitsCfg.Disk.Max)
	}
	if len(active) == 0 {
		return err
	}
	return fmt.Errorf("%w (note: [limits.disk] %s was active while the container booted — a low disk I/O rate can starve startup past the readiness window)",
		err, strings.Join(active, " "))
}

// DetectCodeUser returns true if the named user account exists inside
// the running container. It is used to decide whether to run sessions
// as `code` or fall back to root — replacing the old broken heuristic
// that matched the image alias literally against "coi-default" and
// misclassified every custom image built from it as a root image.
//
// Implemented on probeCodeUser (shared with ResolveCodeUID): "user not
// present" is recognized by `id`'s own stderr, while incus-level exec
// failures return an error so the caller can decide whether to warn or
// fall back. See probeCodeUser for the argv-injection defence notes.
func DetectCodeUser(mgr container.ContainerExecution, codeUser string) (bool, error) {
	_, exists, err := probeCodeUser(mgr, codeUser)
	return exists, err
}

// codeUserMissing reports whether a probe error means `id` itself ran and
// said the account doesn't exist — as opposed to an incus-level failure
// (daemon unreachable, container stopped mid-race, permission denied,
// missing binary) that ALSO surfaces as *container.ExitError from the CLI
// exec path, with the same non-zero exit code. The stderr text is the only
// reliable discriminator: `id` (GNU coreutils and busybox alike) says
// "no such user"/"unknown user", incus's own failures say "Error: ...".
// Only a genuine no-such-user may fall back to root — misclassifying an
// infra failure would silently misdirect callers to root's tmux socket,
// the exact #588 failure mode.
func codeUserMissing(err error) bool {
	var exitErr *container.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	stderr := strings.ToLower(exitErr.Stderr)
	return strings.Contains(stderr, "no such user") || strings.Contains(stderr, "unknown user")
}

// probeCodeUser is the ONE code-user probe shared by DetectCodeUser and
// ResolveCodeUID (so their error taxonomies cannot drift): it runs
// `id -u <codeUser>` in the container and returns (uid, true, nil) when the
// account exists, (0, false, nil) when `id` reports it missing, and an error
// for anything else — including incus-level exec failures, which are
// distinguished from "no such user" by stderr (see codeUserMissing).
//
// codeUser is passed as a raw argv entry to `id` rather than interpolated
// into a shell string — defence-in-depth against a maliciously crafted
// [incus] code_user config value: `id` receives it as a single argument and
// reports "no such user"; the shell never sees it.
func probeCodeUser(mgr container.ContainerExecution, codeUser string) (int, bool, error) {
	out, err := mgr.ExecArgsCapture(
		[]string{"id", "-u", codeUser},
		container.ExecCommandOptions{Capture: true},
	)
	if err != nil {
		if codeUserMissing(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, false, fmt.Errorf("unexpected `id -u %s` output %q: %w", codeUser, out, err)
	}
	return uid, true, nil
}

// ResolveCodeUID returns the UID the container's code user ACTUALLY has,
// probed from the container itself, or root (0) when the account doesn't
// exist — images without a code user run their sessions, and therefore
// their tmux server, as root. Callers that must talk to a session's
// per-user resources (e.g. the tmux socket at /tmp/tmux-<uid>, #588) need
// this rather than the config-derived container.CodeUID: after an
// in-container remap (remapContainerUserIfNeeded / [incus] code_uid) the
// two can differ. Note the probe uses the CURRENT config's code_user NAME,
// so it resolves cross-config UID variance but not a container created
// under a different [incus] code_user name (custom-image corner case —
// such containers probe as "no user" and resolve to root).
func ResolveCodeUID(mgr container.ContainerExecution, codeUser string) (int, error) {
	uid, exists, err := probeCodeUser(mgr, codeUser)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil // no code user: sessions run as root
	}
	return uid, nil
}

// restartStoppedContainer reconciles and restarts a stopped, reusable container
// (persistent or explicit --container). It re-runs the same workspace-mount and
// security-device setup a fresh launch uses (issue #610) and applies the boot
// network block; it mutates result (workspace path, immutable flag) and
// opts.Security.ProtectedPaths in place. Extracted verbatim from Setup.
func restartStoppedContainer(result *SetupResult, opts *SetupOptions, containerName string) error {
	opts.Logger("Starting existing container...")
	// Strip stale port devices while STOPPED: they would re-bind
	// their old host ports at start (colliding with the preflight
	// below, or failing the start outright if another process took
	// a port meanwhile). The current plan is re-published later.
	RemoveStalePortDevices(result.Manager, opts.Logger)
	// Reconcile the workspace-sourced security devices against the
	// CURRENT workspace BEFORE start (issue #610). A protect-*/mask-*/
	// gitc-* device attached at first launch keeps its original host
	// source; if that source was removed while the container was stopped,
	// Incus rejects the container at start-validation with "Missing
	// source path" and no fresh coi invocation self-heals it. Strip those
	// devices and re-run the SAME security setup a fresh launch uses, so
	// materialization / symlink-rejection / type handling all come from
	// one place and protection matches the current workspace.
	reuseCWP := result.Manager.GetWorkspacePath()
	result.ContainerWorkspacePath = reuseCWP
	reuseLayout, reuseWtErr := ResolveGitWorktree(opts.WorkspacePath)
	if reuseWtErr != nil {
		// The layout also feeds the shift decision below; losing it
		// silently would drop the common dir's vote (#683).
		opts.Logger(fmt.Sprintf("Warning: git worktree not resolved (%v); its git dirs are skipped by the UID-mapping check and git commands may fail in the container", reuseWtErr))
	}
	reuseWritableHooks := !containsGitHooksPath(opts.Security.ProtectedPaths)
	secDevices := NewSecurityDeviceReconciler(result.Manager, opts.Logger)
	// Reconcile the kernel-surface policy while the container is stopped —
	// the only window where security.nesting and security.syscalls.deny can
	// change — so a persistent container converges to the CURRENT
	// [container] docker / [security] reduce_kernel_surface config. Skipped
	// entirely for an explicit --container attach ("use it as it is"), and a
	// no-op when the config already matches, so a user-managed container's own
	// instance config is never clobbered. Fail-closed: abort rather than boot a
	// container whose hardening could not be brought to the desired state.
	if opts.ContainerName == "" {
		changed, err := container.ReconcileKernelSurfacePolicy(result.ContainerName, hardeningPolicyFrom(opts))
		if err != nil {
			return fmt.Errorf("could not reconcile docker/kernel-hardening settings: %w", err)
		}
		if changed {
			// Never silent: this rewrite also resets any manual `incus config
			// set` hardening (e.g. a hand-added syscall deny) back to policy.
			opts.Logger("Reconciled docker/kernel-hardening settings to the current config (any manual security.nesting/syscalls overrides were reset)")
		}
	}
	// Decide the shift flag the same way a fresh launch does (issue
	// #685). The old `!opts.DisableShift` ignored both cases that turn
	// shift off at first launch — a host/code UID mismatch and a
	// Colima/Lima guest that maps UIDs itself — so every reuse re-added
	// the protect-* devices with shift=true. On a container the #678
	// fallback had already converted to raw.idmap that re-armed the
	// exact configuration whose start failure caused the conversion,
	// once per session. ResolveReuseUIDMapping additionally converts
	// creation-time shift=true devices when the decision is raw.idmap
	// (#683 — a pre-upgrade container on OrbStack ≥2.2.2 never hits
	// the start failure the reactive fallback keys on).
	//
	// The decision deliberately sees the UNGATED mount config: on
	// reuse, mount devices persist from creation regardless of
	// current trust (the 4.6 gate below only warns), so the
	// currently-declared mounts are the closest available stand-in
	// for the devices actually attached. Trust-gating the vote
	// would be both unsafe and pointless here: a mount whose trust
	// was revoked after creation is still attached and its
	// filesystem still matters, while the only influence any path
	// has on the vote is flipping toward raw.idmap — whose value
	// derives from host/code UIDs, never from the path — so an
	// untrusted entry cannot inject anything.
	reuseSources := MountSources(opts.WorkspacePath, opts.MountConfig, WorktreeSources(reuseLayout)...)
	reuseUseShift := ResolveReuseUIDMapping(containerName, reuseSources, opts.DisableShift, opts.Logger)
	// A named session (session_name) can be reused from a different
	// workspace location than the container was created with — the
	// persisted workspace device then points at the old source and
	// must be replaced before the security mounts derive their
	// overlays from the container-side workspace path.
	// An EXPLICIT --container is exempt: it means "enter that
	// container as it is" — rebinding its workspace to whatever
	// directory the caller happens to be in would both break the
	// testing flow and silently mount an unintended directory
	// (e.g. $HOME) read-write into the container.
	if opts.ContainerName == "" {
		if cwp, moved, remountErr := RemountMovedWorkspace(result.Manager, opts.WorkspacePath, opts.PreserveWorkspacePath, reuseLayout, reuseUseShift, opts.Logger); remountErr != nil {
			return remountErr
		} else if moved {
			reuseCWP = cwp
			result.ContainerWorkspacePath = cwp
		}
	}
	reusePaths, reuseImmutable, reuseErr := applySessionSecurity(secDevices, *opts, reuseCWP, reuseUseShift, reuseLayout, reuseWritableHooks, containerName)
	secDevices.Finish()
	opts.Security.ProtectedPaths = reusePaths
	if reuseImmutable {
		result.HasImmutableProtection = true
	}
	if reuseErr != nil {
		return reuseErr
	}
	// Reuse gets the same start fallbacks as a fresh launch and as
	// run's persistent reuse (internal/cli/run.go): a persistent
	// container may carry security.idmap.isolated, and its disk devices
	// only materialize at start, so an idmap-incompatible mount fails
	// right here with nothing to catch it (#685).
	if err := container.StartWithIsolationFallback(result.ContainerName); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	// Block network immediately: a previous session's AI agent may have
	// planted startup scripts (systemd units, cron jobs, shell hooks) that
	// would otherwise phone home during the boot window before
	// SetupForContainer installs proper isolation rules.
	if opts.Network.Config != nil {
		if err := network.ApplyBootBlockRule(result.ContainerName); err != nil {
			// Fail closed in restricted/allowlist mode: rather than let
			// the container run unblocked during the boot window, stop it
			// and abort. Open mode opts into unrestricted egress.
			if opts.Network.Config.Mode != config.NetworkModeOpen {
				_ = result.Manager.Stop(true)
				return fmt.Errorf("boot network block failed in %s mode; stopped container to avoid an unprotected boot window: %w", opts.Network.Config.Mode, err)
			}
			opts.Logger(fmt.Sprintf("Warning: boot block not applied (open mode): %v", err))
		} else {
			opts.Logger("Boot network block applied (lifted after isolation rules are set up)")
		}
	}
	return nil
}

// createAndStartContainer creates a fresh container (init), mounts the
// workspace + configured/worktree/security devices, applies limits and the
// pre-boot hardening, starts it, and applies the boot network block. It mutates
// result and opts.Security.ProtectedPaths in place. Extracted verbatim from Setup.
func createAndStartContainer(result *SetupResult, opts *SetupOptions, image, containerName string) error {
	opts.Logger(fmt.Sprintf("Creating container from %s...", image))
	// Create container without starting it (init). Honor the configured
	// storage pool ([container] storage_pool) the same way the run pipeline
	// does via `-s <pool>` — otherwise `coi shell` silently lands on the
	// Incus default pool (#726). An empty pool means "use the default".
	initArgs := []string{"init", image, result.ContainerName}
	if opts.StoragePool != "" {
		initArgs = append(initArgs, "-s", opts.StoragePool)
	}
	if err := container.IncusExec(initArgs...); err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Detect a git worktree checkout (.git is a file whose real git internals
	// live outside the workspace) BEFORE the UID-mapping decision: the common
	// dir is mounted as its own shift-carrying disk device, so its filesystem
	// must vote on that decision too (#683). A valid layout forces
	// preserve-path so git's pointers resolve identically host<->container,
	// and its external git dirs are mounted + protected below (issue #533). A
	// pointer that fails the safety guard is not mounted; git fails loudly
	// rather than exposing a mis-pointed dir.
	worktreeLayout, wtErr := ResolveGitWorktree(opts.WorkspacePath)
	if wtErr != nil {
		opts.Logger(fmt.Sprintf("Warning: git worktree not mounted (%v); git commands may fail in the container", wtErr))
	}
	worktreeWritableHooks := !containsGitHooksPath(opts.Security.ProtectedPaths)

	// Configure UID/GID mapping for the workspace bind mount. Shared with
	// the run pipeline via ConfigureUIDMapping so both honor Colima/Lima
	// auto-detection AND set raw.idmap on any host-UID/code-UID mismatch
	// (issue #530).
	// Shell path sets raw.idmap before its own start (below), so the
	// idmapApplied signal is not needed for the workspace mount itself — but it
	// gates a per-mount shift=true override, which is mutually exclusive with
	// raw.idmap (#604).
	useShift, rawIdmapActive, err := ConfigureUIDMapping(result.ContainerName, MountSources(opts.WorkspacePath, opts.MountConfig, WorktreeSources(worktreeLayout)...), opts.DisableShift, opts.Logger)
	if err != nil {
		// Fail fast (#838): the workspace can't be UID-mapped and would be
		// unwritable — better a clear error than a silently broken session.
		return err
	}

	// Determine container mount path - either /workspace (default) or same as host path
	preserveWorkspace := opts.PreserveWorkspacePath || worktreeLayout != nil
	containerWorkspacePath := "/workspace"
	if preserveWorkspace {
		// Validate that the path doesn't conflict with critical system directories.
		if WorkspaceUnderSystemDir(opts.WorkspacePath) {
			if worktreeLayout != nil {
				// Can't preserve the path, so the worktree's git pointers can't
				// resolve and its internals can't be protected — fail closed.
				return fmt.Errorf("git worktree workspace %q is under a system directory; cannot preserve its host path to mount git internals safely", opts.WorkspacePath)
			}
			opts.Logger(fmt.Sprintf("Warning: preserve_workspace_path requested for %q conflicts with system directories; using /workspace instead", opts.WorkspacePath))
		} else {
			containerWorkspacePath = filepath.Clean(opts.WorkspacePath)
			opts.Logger(fmt.Sprintf("Adding workspace mount: %s -> %s (preserving host path)", opts.WorkspacePath, containerWorkspacePath))
		}
	}
	if containerWorkspacePath == "/workspace" && !preserveWorkspace {
		opts.Logger(fmt.Sprintf("Adding workspace mount: %s -> %s", opts.WorkspacePath, containerWorkspacePath))
	}
	result.ContainerWorkspacePath = containerWorkspacePath
	if err := result.Manager.MountDisk("workspace", opts.WorkspacePath, containerWorkspacePath, useShift, false); err != nil {
		return fmt.Errorf("failed to add workspace device: %w", err)
	}
	// Mount the worktree's external git common dir (read-write, at its host path)
	// so git resolves; its RCE sinks are re-covered read-only after the security
	// mounts below (issue #533).
	if worktreeLayout != nil {
		if err := MountGitWorktreeDirs(result.Manager, worktreeLayout, useShift); err != nil {
			return fmt.Errorf("failed to mount git worktree dirs: %w", err)
		}
		opts.Logger(fmt.Sprintf("Mounted git worktree common dir (read-write): %s", worktreeLayout.CommonDir))
	}

	// Mount all configured directories
	if err := setupMounts(result.Manager, opts.MountConfig, useShift, rawIdmapActive, opts.Logger); err != nil {
		return err
	}

	// Protect security-sensitive paths (read-only mounts), extend protection to a
	// worktree's external git common dir, apply the host-immutable belt, and mask
	// secret paths — all via applySessionSecurity, the single implementation shared
	// with the reuse/restart reconcile below (issue #610). Must be added after the
	// workspace mount for the overlays to layer on top.
	effectivePaths, hasImmutable, secErr := applySessionSecurity(result.Manager, *opts, containerWorkspacePath, useShift, worktreeLayout, worktreeWritableHooks, containerName)
	// Adopt the expanded list as the canonical protected set so downstream
	// consumers (the SANDBOX_CONTEXT.md "Protected paths" listing built from
	// opts.Security.ProtectedPaths below) reflect what was actually mounted, including the
	// per-worktree configs.
	opts.Security.ProtectedPaths = effectivePaths
	if hasImmutable {
		result.HasImmutableProtection = true
	}
	if secErr != nil {
		return secErr
	}

	// Apply resource limits before starting (if configured)
	if opts.LimitsConfig.HasAny() {
		opts.Logger("Applying resource limits...")
		applyOpts := limits.ApplyOptions{
			ContainerName: result.ContainerName,
			CPU: limits.CPULimits{
				Count:     opts.LimitsConfig.CPU.Count,
				Allowance: opts.LimitsConfig.CPU.Allowance,
				Priority:  opts.LimitsConfig.CPU.Priority,
			},
			Memory: limits.MemoryLimits{
				Limit:   opts.LimitsConfig.Memory.Limit,
				Enforce: opts.LimitsConfig.Memory.Enforce,
				Swap:    opts.LimitsConfig.Memory.Swap,
			},
			Disk: limits.DiskLimits{
				Read:     opts.LimitsConfig.Disk.Read,
				Write:    opts.LimitsConfig.Disk.Write,
				Max:      opts.LimitsConfig.Disk.Max,
				Size:     opts.LimitsConfig.Disk.Size,
				Priority: opts.LimitsConfig.Disk.Priority,
			},
			Runtime: limits.RuntimeLimits{
				MaxProcesses: opts.LimitsConfig.Runtime.MaxProcesses,
			},
			Project: opts.IncusProject,
		}
		if err := limits.ApplyResourceLimits(applyOpts); err != nil {
			return fmt.Errorf("failed to apply resource limits: %w", err)
		}
	}

	// Apply the kernel-surface policy: Docker/nesting support and/or syscall
	// denies per [container] docker and [security] reduce_kernel_surface
	// (must be set before first boot).
	policy := hardeningPolicyFrom(opts)
	if policy.DockerEnabled() {
		opts.Logger("Enabling Docker support...")
	} else {
		opts.Logger("Docker support disabled; applying kernel-surface hardening...")
	}
	if err := container.ApplyKernelSurfacePolicy(result.ContainerName, policy); err != nil {
		return fmt.Errorf("failed to apply kernel-surface policy: %w", err)
	}

	// Isolate UID/GID namespace so each container gets a unique host-side UID
	// range, preventing cross-container file access via shared host UIDs.
	// Non-fatal: some environments (nested containers, CI runners) don't have
	// enough subuid/subgid space. The fallback at start time handles this.
	idmapIsolated := false
	if err := container.IsolateUIDNamespace(result.ContainerName); err != nil {
		opts.Logger(fmt.Sprintf("Warning: UID namespace isolation unavailable: %v", err))
	} else {
		idmapIsolated = true
	}

	// Disable guest API to prevent host topology leaks (FLAWS Finding 3)
	if err := container.DisableGuestAPI(result.ContainerName); err != nil {
		return fmt.Errorf("failed to disable guest API: %w", err)
	}

	// Harden the bridge NIC against egress-isolation bypass: anti-spoof the
	// source IP/MAC (so saddr-keyed nft rules can't be dodged) and isolate the
	// bridge port (so the container can't reach sibling containers at L2).
	// Non-fatal: unmanaged/static/macvlan NICs degrade to nft-only enforcement.
	if err := container.EnableNICSecurity(result.ContainerName); err != nil {
		opts.Logger(fmt.Sprintf("Warning: NIC security hardening not applied: %v", err))
	}

	// For restricted/allowlist modes, disable IPv6 from the kernel's first
	// instant so there is no IPv6 egress window before the host-side ip6 drop
	// is installed. Open mode opts into unrestricted egress, so skip it.
	if opts.Network.Config != nil && opts.Network.Config.Mode != config.NetworkModeOpen {
		if err := container.DisableIPv6AtBoot(result.ContainerName); err != nil {
			opts.Logger(fmt.Sprintf("Warning: pre-boot IPv6 disable not applied: %v", err))
		}
		// With IPv6 disabled, keep systemd-networkd from wedging on it (#548).
		if err := container.ConfigureNetworkdIPv4Only(result.ContainerName); err != nil {
			opts.Logger(fmt.Sprintf("Warning: networkd IPv4-only config not applied: %v", err))
		}
	}

	// Block privileged containers — they defeat all isolation
	if err := container.CheckNotPrivileged(result.ContainerName); err != nil {
		return err
	}

	// Now start the container
	opts.Logger("Starting container...")
	if idmapIsolated {
		if err := container.StartWithIsolationFallback(result.ContainerName); err != nil {
			return fmt.Errorf("failed to start container: %w", err)
		}
	} else {
		// Isolation was never set, so the isolation fallback has nothing to
		// unset — but the #678 idmapped-mount failure is orthogonal to it and
		// hits this branch just the same (#685).
		if err := container.StartWithIdmapFallback(result.ContainerName); err != nil {
			return fmt.Errorf("failed to start container: %w", err)
		}
	}
	// Block network immediately after first boot as well: defence-in-depth
	// against a malicious base image that runs something on init.
	if opts.Network.Config != nil {
		if err := network.ApplyBootBlockRule(result.ContainerName); err != nil {
			// Fail closed in restricted/allowlist mode: stop the just-started
			// container and abort rather than leave an unprotected boot window.
			// Open mode opts into unrestricted egress.
			if opts.Network.Config.Mode != config.NetworkModeOpen {
				_ = result.Manager.Stop(true)
				return fmt.Errorf("boot network block failed in %s mode; stopped container to avoid an unprotected boot window: %w", opts.Network.Config.Mode, err)
			}
			opts.Logger(fmt.Sprintf("Warning: boot block not applied (open mode): %v", err))
		} else {
			opts.Logger("Boot network block applied (lifted after isolation rules are set up)")
		}
	}
	return nil
}

// injectSandboxContext builds the tool.ContextInfo from the resolved session
// facts, injects ~/SANDBOX_CONTEXT.md (and the optional .json companion), and
// returns the rendered context content for the auto-context step. Extracted
// verbatim from Setup's phase-12 block.
func sandboxContextOps(result *SetupResult, opts SetupOptions) (string, []guestOp) {
	networkMode := ""
	var allowedPorts []int
	var dnsServers, allowedDomains []string
	if opts.Network.Config != nil {
		networkMode = string(opts.Network.Config.Mode)
		allowedPorts = opts.Network.Config.AllowedPorts
		dnsServers = opts.Network.Config.DNSServers
		allowedDomains = opts.Network.Config.AllowedDomains
	}
	// Check if GH_TOKEN or GITHUB_TOKEN is among forwarded env vars
	ghAuthenticated := false
	for _, name := range opts.Context.ForwardedEnvVars {
		if name == "GH_TOKEN" || name == "GITHUB_TOKEN" {
			ghAuthenticated = true
			break
		}
	}

	toolName := "AI coding tool"
	if opts.Tool != nil {
		toolName = opts.Tool.Name()
	}

	var extraMounts []tool.MountInfo
	if opts.MountConfig != nil {
		for _, m := range opts.MountConfig.Mounts {
			extraMounts = append(extraMounts, tool.MountInfo{ContainerPath: m.ContainerPath})
		}
	}

	var cpuLimit, memoryLimit, maxDuration string
	if opts.LimitsConfig != nil {
		cpuLimit = opts.LimitsConfig.CPU.Count
		memoryLimit = opts.LimitsConfig.Memory.Limit
		maxDuration = opts.LimitsConfig.Runtime.MaxDuration
	}

	// Read profile context file content if configured
	var profileContext string
	if opts.Context.ProfileFile != "" {
		data, err := os.ReadFile(opts.Context.ProfileFile)
		if err != nil {
			opts.Logger(fmt.Sprintf("Warning: Failed to read profile context file %s: %v", opts.Context.ProfileFile, err))
		} else {
			profileContext = string(data)
			opts.Logger(fmt.Sprintf("Loaded profile context from %s", opts.Context.ProfileFile))
		}
	}

	ctxInfo := tool.ContextInfo{
		WorkspacePath:      result.ContainerWorkspacePath,
		HomeDir:            result.HomeDir,
		Persistent:         opts.Persistent,
		NetworkMode:        networkMode,
		AllowedPorts:       allowedPorts,
		DNSServers:         dnsServers,
		AllowedDomains:     allowedDomains,
		SSHAgentForwarded:  result.SSHAgentSocketPath != "",
		RunAsRoot:          result.RunAsRoot,
		ProtectedPaths:     opts.Security.ProtectedPaths,
		ProtectedBranches:  opts.Git.ProtectedBranches,
		GHCLIAuthenticated: ghAuthenticated,
		ForwardedEnvVars:   opts.Context.ForwardedEnvVars,
		Timezone:           result.Timezone,
		ExtraMounts:        extraMounts,
		PublishedPorts:     publishedPortInfos(result.PublishedPorts),
		CPULimit:           cpuLimit,
		MemoryLimit:        memoryLimit,
		MaxDuration:        maxDuration,
		ToolName:           toolName,
		ContainerName:      result.ContainerName,
		ProfileContext:     profileContext,
		DockerUnavailable:  !hardeningPolicyFrom(&opts).DockerEnabled(),
	}
	contextContent := resolveContextContent(ctxInfo, opts.Context.FilePath, opts.Logger)
	var ops []guestOp
	if op, err := contextFileOp(ctxInfo, opts.Context.FilePath, result.HomeDir, opts.Logger); err != nil {
		opts.Logger(fmt.Sprintf("Warning: Failed to inject context file: %v", err))
	} else {
		ops = append(ops, op)
	}
	// Machine-readable companion for programmatic consumers (#705), enabled
	// by default. Written from ctxInfo (the real facts) unless [tool]
	// context_json_file provides a custom JSON to inject verbatim; disable
	// entirely with context_json = false.
	if config.BoolVal(opts.Context.JSON) {
		if op, err := contextJSONFileOp(ctxInfo, opts.Context.JSONFilePath, result.HomeDir, opts.Logger); err != nil {
			opts.Logger(fmt.Sprintf("Warning: Failed to inject context JSON file: %v", err))
		} else {
			ops = append(ops, op)
		}
	}
	return contextContent, ops
}

// injectSandboxContextFiles writes ~/SANDBOX_CONTEXT.md, the optional .json,
// and (when [tool] auto_context is on and the tool has one) the tool's native
// auto-load file, all in ONE exec. Runs for both new and resumed sessions so
// dynamic info stays current.
//
// preOps run first in the same exec (other phases' deferred steps); the
// combined output is returned so their callers can report what happened.
func injectSandboxContextFiles(result *SetupResult, opts SetupOptions, preOps ...guestOp) string {
	contextContent, contextOps := sandboxContextOps(result, opts)
	ops := append(append([]guestOp{}, preOps...), contextOps...)

	if opts.Tool != nil && config.BoolVal(opts.Context.Auto) && contextContent != "" {
		if acf, ok := opts.Tool.(tool.ToolWithAutoContextFile); ok {
			if op, err := autoContextFileOp(result.Manager, acf, contextContent, result.HomeDir, opts.Logger); err != nil {
				opts.Logger(fmt.Sprintf("Warning: Failed to inject auto-context file: %v", err))
			} else {
				ops = append(ops, op)
			}
		}
	}
	if len(ops) == 0 {
		return ""
	}
	out, err := runGuestOpsOutput(result.Manager, ops, container.ExecCommandOptions{})
	if err != nil {
		opts.Logger(fmt.Sprintf("Warning: Failed to write sandbox context files: %v", err))
		return out
	}
	for _, op := range ops {
		if op.write != nil {
			opts.Logger(fmt.Sprintf("Context file injected at %s", op.write.path))
		}
	}
	return out
}

// remapContainerUser remaps the container's `code` user to a non-default
// [incus] code_uid (groupmod+usermod), then best-effort chowns its home.
// usermod's home-ownership walk may exit non-zero against a read-only mount
// even though the passwd change committed, so the UID is re-probed before
// treating the failure as fatal. Extracted verbatim from Setup (§6.5).
func remapContainerUser(result *SetupResult, opts SetupOptions) error {
	opts.Logger(fmt.Sprintf("Remapping user %s from UID 1000 to %d...", container.CodeUser, container.CodeUID))
	remapCmd := fmt.Sprintf(
		"groupmod -g %d %s && usermod -u %d -g %d %s",
		container.CodeUID, container.CodeUser,
		container.CodeUID, container.CodeUID, container.CodeUser,
	)
	if _, err := result.Manager.ExecCommand(remapCmd, container.ExecCommandOptions{Capture: true}); err != nil {
		// usermod -u, even without -m, walks the home directory chowning
		// files it finds owned by the old UID — that walk hits any
		// read-only mount already living under /home/<code> (protected
		// paths, [[mounts]] entries; disk devices attach pre-start per
		// #534) and usermod exits non-zero (E_HOMEDIR) despite the passwd
		// update having already been committed. Don't trust the exit code
		// alone: probe whether the account really did move to the target
		// UID before treating this as fatal. groupmod ran first in the
		// chain and usermod commits uid+gid in the same passwd write, so
		// a confirmed UID implies the full remap landed.
		actualUID, _, probeErr := probeCodeUser(result.Manager, container.CodeUser)
		if probeErr != nil || actualUID != container.CodeUID {
			return fmt.Errorf("failed to remap user %s to UID %d: %w", container.CodeUser, container.CodeUID, err)
		}
		opts.Logger(fmt.Sprintf("Warning: UID/GID remap for %s succeeded but usermod's home-directory ownership walk hit an unwritable path: %v", container.CodeUser, err))
	}
	// The home-ownership sweep is best-effort, separately from the remap
	// itself (mirrors the coi run path, #534): a read-only mount under
	// /home/<code> makes chown -R exit non-zero after fixing everything it
	// could, which must not abort setup. Keeping it OUT of the fatal &&
	// chain also means it still runs when usermod exited non-zero above —
	// fused, the chain would skip it and leave writable home files owned
	// by the old UID (the code user unable to write its own dotfiles).
	chownCmd := fmt.Sprintf("chown -R %s:%s /home/%s", container.CodeUser, container.CodeUser, container.CodeUser)
	if _, err := result.Manager.ExecCommand(chownCmd, container.ExecCommandOptions{Capture: true}); err != nil {
		opts.Logger(fmt.Sprintf("Warning: could not chown all of /home/%s after UID remap (a read-only mount under it is expected to fail): %v", container.CodeUser, err))
	}
	return nil
}

// configureGitIdentity locks the commit identity read-only when git.readonly
// is set with a complete identity (fail-closed), otherwise installs the
// useConfigOnly guard and writes the identity. Extracted verbatim from Setup
// (§6.6.1). Also installs the [git] strip_attribution hook (#788): on the
// readonly path core.hooksPath rides inside the mounted gitconfig (a live
// `git config --global` would fail read-only), on the writable path the hook
// setup writes it itself.
func configureGitIdentity(ctx context.Context, result *SetupResult, opts SetupOptions) error {
	// identityLock is the "make the identity unoverridable" intent. It currently
	// equals readonlyLock (git.readonly) — the two enforcement layers below key
	// off this one binding, so a future [git] enforce_identity that turns them on
	// WITHOUT the heavyweight whole-gitconfig read-only mount is a one-line change.
	readonlyLock := opts.Git.Readonly && opts.Git.Identity.Complete()
	identityLock := readonlyLock
	guardBranches := opts.Git.ProtectedBranches
	guardOn := len(guardBranches) > 0
	// core.hooksPath must be installed whenever ANY hook policy is active: the
	// strip hook, the identity re-stamp hook, or the branch guard (all share the
	// one hook directory).
	hooksPath := ""
	if opts.Git.StripAttribution || identityLock || guardOn {
		hooksPath = GitHooksDir
	}
	if readonlyLock {
		if err := SetupGitIdentityReadonly(result.Manager, result.HomeDir, opts.Git.Identity, hooksPath); err != nil {
			return fmt.Errorf("git.readonly: could not lock the commit identity read-only: %w", err)
		}
		opts.Logger("Git identity locked read-only (git.readonly): " + result.HomeDir + "/.gitconfig cannot be changed in-container")
	} else {
		if opts.Git.Readonly {
			opts.Logger("Warning: git.readonly is set but no identity is resolvable — set [git] name/email (or enable seed_host_identity); nothing to lock")
		}
		// Guard + identity + (when any hook policy is on) the hooks, in one exec.
		SetupWritableGitConfig(result.Manager, result.HomeDir, opts.Git.Identity, opts.Git.StripAttribution, opts.Git.StripAttributionPatterns, identityLock, guardBranches, opts.Logger)
	}
	if readonlyLock && (opts.Git.StripAttribution || identityLock || guardOn) {
		// The hook dir is needed on every hook path; core.hooksPath is written
		// live only on the writable path (the readonly mount already carries it).
		SetupGitHooks(result.Manager, result.HomeDir, opts.Git.Identity, opts.Git.StripAttribution, opts.Git.StripAttributionPatterns, identityLock, false, guardBranches, opts.Logger)
	}
	// Layer 1: pin GIT_AUTHOR_*/GIT_COMMITTER_* as container-level env so `-c
	// user.*` overrides lose without rewriting history. No-op (and unsets stale
	// keys) when the identity isn't locked.
	ApplyGitIdentityContainerEnv(ctx, result.ContainerName, opts.Git.Identity, identityLock, opts.Logger)
	return nil
}
