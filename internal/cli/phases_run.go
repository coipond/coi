package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/limits"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/nftmonitor"
	"github.com/coipond/coi/internal/session"
	"github.com/coipond/coi/internal/timing"
	"github.com/coipond/coi/internal/tool"
	"github.com/coipond/coi/internal/vmhost"
)

// runState is the mutable state accumulated across run pipeline phases.
// Each phase reads its inputs from state and writes its outputs back.
type runState struct {
	// After resolve-workspace
	absWorkspace string

	// Run-script mode (coi run with no command): execute <workspace>/coi-run
	// from the workspace mount. The file is required to be executable, so it
	// runs directly and its shebang decides the interpreter.
	runScript bool

	// Prompt mode (coi run --prompt / --prompt-file / --prompt-name): run the
	// AI agent headlessly with a predefined prompt and exit with its status
	// code (#701). promptText is the resolved prompt; promptSessionID is a fresh
	// session id used to stage the prompt file and as the tool's --session-id.
	promptMode      bool
	promptText      string
	promptSessionID string
	promptTool      tool.Tool // resolved once in resolvePromptMode, reused by runPromptPhase

	// After validate-env
	containerName  string
	img            string
	effectiveAlias string

	// After launch-container (mount/socket config is parsed + trust-gated and
	// all disk devices are attached by the launch phase's pre-start hook; only
	// the wasRestarted reuse path resolves containerWorkspace later, in
	// configure-container)
	mgr                container.ContainerManager
	wasRestarted       bool
	useShift           bool                       // resolved by the launch phase's UID-mapping pre-start hook
	rawIdmapActive     bool                       // true when the container uses raw.idmap (mutually exclusive with per-device shift, #604)
	containerWorkspace string                     // in-container workspace path
	gitWorktree        *session.GitWorktreeLayout // external git dirs for a worktree checkout (#533), nil otherwise
	mountConfig        *session.MountConfig       // trust-gated
	socketConfig       *session.SocketConfig      // trust-gated
	credentialConfig   *session.CredentialConfig  // trust-gated [[credentials]] to seed (#726 follow-up)
	portConfig         *session.PortConfig        // trust-gated [[ports]] to publish (#558)
	slot               int                        // resolved slot number (for port allocation)
	resolvedPorts      []session.PublishedPort    // preflighted port plan (see session.ResolvePorts)

	// After apply-network
	socketEnv map[string]string
	tz        string

	// After start-monitoring
	monitorDaemon monitor.MonitorDaemon
	nftDaemon     nftmonitor.NFTMonitorDaemon
}

// validateEnvRunPhase checks Incus availability, allocates a slot, resolves
// the image name, and validates the storage pool and alias.
func (a *App) validateEnvRunPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "validate-env",
		RunFn: func(_ context.Context) (session.Teardown, error) {
			if !container.Available() {
				return nil, container.IncusNotAvailableError()
			}
			if err := container.CheckMinimumVersion(); err != nil {
				return nil, err
			}
			if warning := container.CheckKernelVersion(); warning != "" {
				fmt.Fprintf(os.Stderr, "%s\n", warning)
			}

			slotNum := a.slot
			var err error
			if slotNum == 0 {
				// Persistent mode: prefer the stopped container from a
				// previous run — plain AllocateSlot treats it as occupying
				// its slot and would silently launch a FRESH container on
				// the next slot (state never persists, slots exhaust).
				if a.persistent {
					if reuse, ok := session.FindReusablePersistentSlot(s.absWorkspace, a.sessionName(), 10); ok {
						slotNum = reuse
						fmt.Fprintf(os.Stderr, "Reusing persistent container on slot %d\n", slotNum)
					}
				}
				if slotNum == 0 {
					slotNum, err = session.AllocateSlot(s.absWorkspace, a.sessionName(), 10)
					if err != nil {
						return nil, fmt.Errorf("failed to allocate slot: %w", err)
					}
					fmt.Fprintf(os.Stderr, "Auto-allocated slot %d\n", slotNum)
					warnNamedSessionFork(s.absWorkspace, a.sessionName(), slotNum)
				}
			}
			s.containerName = session.ContainerName(s.absWorkspace, a.sessionName(), slotNum)
			s.slot = slotNum

			img := ResolveImageName(a.cfg)
			if err := AutoBuildIfNeeded(a.cfg, img); err != nil {
				return nil, err
			}
			if err := CheckAndReportStaleBase(a.cfg, img); err != nil {
				return nil, err
			}
			if err := container.ValidateStoragePool(a.cfg.Container.StoragePool); err != nil {
				return nil, err
			}
			s.img = img

			effectiveAlias, err := validateAndPrepareAlias(a.cfg.Container.Alias)
			if err != nil {
				return nil, err
			}
			s.effectiveAlias = effectiveAlias
			return nil, nil
		},
	}
}

// launchContainerRunPhase launches or reuses the container and registers a
// teardown that stops or deletes it on exit.
func (a *App) launchContainerRunPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "launch-container",
		RunFn: func(_ context.Context) (session.Teardown, error) {
			ensureBridgeTrustedZone()
			fmt.Fprintf(os.Stderr, "Launching container %s from image %s...\n", s.containerName, s.img)

			mgr := container.NewManager(s.containerName)
			containerExists, err := mgr.Exists()
			if err != nil {
				return nil, fmt.Errorf("failed to check if container exists: %w", err)
			}
			s.wasRestarted = containerExists && a.persistent

			// Mount/socket config is parsed and trust-gated BEFORE launch so the
			// pre-start hook below can attach every disk device to the stopped
			// container (all host-side computation; no container required).
			mc, err := ParseMountConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid mount configuration: %w", err)
			}
			sc, err := ParseSocketConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid socket configuration: %w", err)
			}
			cc, err := ParseCredentialConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid credential configuration: %w", err)
			}
			// One combined trust gate over mounts + sockets + credentials + ports,
			// so the per-source fingerprint matches what `coi trust` recorded.
			pc := ParsePortConfig(a.cfg)
			s.mountConfig, s.socketConfig, s.credentialConfig, s.portConfig = a.gateRunForwarding(mc, sc, cc, pc, s.absWorkspace, s.wasRestarted)

			// A reused persistent container still carries the previous
			// session's port devices; strip them while it is STOPPED so they
			// neither fail the start (a stale device whose old host port is
			// now taken aborts the whole container start) nor linger for
			// entries that were removed or untrusted since. The current plan
			// is re-published after start.
			// (Only when stopped: a RUNNING container belongs to a concurrent
			// session — launchOrReuseContainer refuses it below — and its live
			// port forwards must not be yanked here.)
			if s.wasRestarted {
				if running, _ := mgr.Running(); !running {
					logFn := stderrLogFn
					session.RemoveStalePortDevices(mgr, logFn)
				}
			}

			// Preflight the port plan BEFORE launching: pinned host ports
			// already in use abort here; auto/pool ports get their final
			// numbers (see session.ResolvePorts).
			s.resolvedPorts, err = session.ResolvePorts(s.portConfig, s.absWorkspace, a.sessionName(), s.slot)
			if err != nil {
				return nil, fmt.Errorf("port preflight failed: %w", err)
			}

			// Pre-start hook: runs AFTER init but BEFORE first start, on fresh
			// launches only (reused persistent containers go through preRestart
			// below, which re-decides the mapping and reconciles the security
			// devices). Two jobs:
			//  1. Apply the workspace UID mapping (raw.idmap on a host/code UID
			//     mismatch; Colima/Lima auto-detect) so it takes effect at first
			//     boot (#530).
			//  2. Attach ALL disk devices (workspace, additional mounts, security
			//     + secret masks) to the STOPPED container, exactly like the shell
			//     path does. The devices then materialize at start, so a
			//     filesystem that cannot satisfy security.idmap.isolated (e.g. a
			//     virtiofs workspace under OrbStack/Colima) fails the START — where
			//     the existing isolation fallback disables isolation and retries —
			//     instead of failing a post-start hot-mount with no fallback at
			//     all (issue #534).
			// If the ephemeral isolation fallback recreates the container, this
			// hook re-runs on the fresh container, re-applying mapping and devices.
			// s.useShift is set by whichever hook runs (preStart or preRestart)
			// before anything reads it.
			logFn := stderrLogFn
			hardening := a.hardeningPolicy()
			warnDockerHardeningConflict(a.cfg)
			preStart := func() error {
				defer timing.Start(timing.CatStep, "pre-start-hook")()
				// The kernel-surface policy is applied once at init by
				// LaunchWithPreStartPolicy (below), before this hook runs — no
				// second apply needed here.
				// Detect a git worktree checkout (.git is a file → external git dirs)
				// BEFORE the UID-mapping decision: the common dir is mounted as its
				// own shift-carrying disk device, so its filesystem votes on that
				// decision too (#683). A valid layout forces preserve-path so git's
				// pointers resolve, and its internals are mounted + protected in
				// applyWorkspaceMounts (#533).
				layout, wtErr := session.ResolveGitWorktree(s.absWorkspace)
				if wtErr != nil {
					logFn(fmt.Sprintf("Warning: git worktree not mounted (%v); git commands may fail in the container", wtErr))
				}
				s.gitWorktree = layout
				var idmapErr error
				s.useShift, s.rawIdmapActive, idmapErr = session.ConfigureUIDMapping(s.containerName, session.MountSources(s.absWorkspace, s.mountConfig, session.WorktreeSources(layout)...), a.cfg.Incus.DisableShift, logFn)
				if idmapErr != nil {
					// Fail fast (#838): abort the launch rather than boot an agent
					// against a workspace it cannot write.
					return idmapErr
				}
				// Harden the bridge NIC against egress-isolation bypass: anti-spoof
				// the source IP/MAC (so saddr-keyed nft rules can't be dodged) and
				// isolate the bridge port (no L2 reach to sibling containers). The
				// shell path applies this; coi run must too, or a restricted/allowlist
				// run can bypass its own egress allowlist (#726 follow-up). Must be set
				// before first boot; non-fatal on unmanaged/static NICs.
				if err := container.EnableNICSecurity(s.containerName); err != nil {
					logFn(fmt.Sprintf("Warning: NIC security hardening not applied: %v", err))
				}
				// Restricted/allowlist: kill IPv6 from the kernel's first instant so
				// there is no IPv6 egress window before the host-side ip6 drop lands
				// (shell parity), and pre-seed an IPv4-only networkd config so the link
				// reaches "configured" and systemd-networkd-wait-online does not hang
				// (#548). Non-fatal. Open mode opts into unrestricted egress.
				if m := a.cfg.Network.Mode; m != "" && m != config.NetworkModeOpen {
					if err := container.DisableIPv6AtBoot(s.containerName); err != nil {
						logFn(fmt.Sprintf("Warning: pre-boot IPv6 disable not applied: %v", err))
					}
					if err := container.ConfigureNetworkdIPv4Only(s.containerName); err != nil {
						logFn(fmt.Sprintf("Warning: networkd IPv4-only config not applied: %v", err))
					}
				}
				if layout != nil && session.WorkspaceUnderSystemDir(s.absWorkspace) {
					return fmt.Errorf("git worktree workspace %q is under a system directory; cannot preserve its host path to mount git internals safely", s.absWorkspace)
				}
				s.containerWorkspace = a.resolveContainerWorkspacePath(s.absWorkspace, layout != nil)
				defer timing.Start(timing.CatStep, "apply-workspace-mounts")()
				return a.applyWorkspaceMounts(mgr, s.containerName, s.absWorkspace, &s.containerWorkspace, s.mountConfig, s.useShift, s.rawIdmapActive, false, layout)
			}

			// preRestart reconciles a REUSED persistent container's security devices
			// against the current workspace before it is restarted (issue #610). The
			// creation-time protect-*/mask-*/gitc-* devices keep their original host
			// sources; a source removed while the container was stopped would make
			// Incus reject the container at start-validation. Read the existing
			// workspace mount, re-resolve the worktree layout, strip those devices,
			// and re-run the SAME security setup fresh launch uses (applySecurityMounts).
			preRestart := func() error {
				// Reconcile the kernel-surface policy while the container is
				// stopped — the only window where security.nesting and the
				// syscall deny list can change — so a persistent container
				// converges to the current config (mirrors the shell reuse path).
				// Fail-closed: abort the restart rather than boot a container
				// whose hardening config could not be brought to the desired
				// state. Skips the write when the config already matches.
				changed, reconcileErr := container.ReconcileKernelSurfacePolicy(s.containerName, hardening)
				if reconcileErr != nil {
					return fmt.Errorf("could not reconcile docker/kernel-hardening settings: %w", reconcileErr)
				}
				if changed {
					// Never silent: this rewrite also resets any manual `incus
					// config set` hardening back to policy (mirrors setup.go).
					logFn("Reconciled docker/kernel-hardening settings to the current config (any manual security.nesting/syscalls overrides were reset)")
				}
				s.containerWorkspace = mgr.GetWorkspacePath()
				layout, wtErr := session.ResolveGitWorktree(s.absWorkspace)
				if wtErr != nil {
					// The layout also feeds the shift decision below; losing it
					// silently would drop the common dir's vote (#683).
					logFn(fmt.Sprintf("Warning: git worktree not resolved (%v); its git dirs are skipped by the UID-mapping check and git commands may fail in the container", wtErr))
				}
				s.gitWorktree = layout
				// Strip BEFORE deciding the mapping (matching the shell reuse
				// path in session.Setup): the conversion scan inside
				// ResolveReuseUIDMapping then never enumerates security devices
				// that are about to be re-created with the new flag anyway.
				//
				// The reconciler keeps devices that would be re-added identically
				// (the usual reuse: same workspace, same config) instead of a
				// remove + add round trip per device; devices whose host source
				// vanished are removed right here, before anything else (#610).
				secDevices := session.NewSecurityDeviceReconciler(mgr, logFn)
				// Apply the fresh-launch mapping decision to the reused container,
				// mirroring the shell reuse path: an existing raw.idmap wins over
				// the config (#685), and creation-time shift=true devices are
				// converted when the decision is raw.idmap (#683 — the reactive
				// #678 fallback never fires on OrbStack ≥2.2.2's silent breakage).
				s.useShift = session.ResolveReuseUIDMapping(s.containerName, session.MountSources(s.absWorkspace, s.mountConfig, session.WorktreeSources(layout)...), a.cfg.Incus.DisableShift, logFn)
				// On reuse, [[mounts]] devices persist from creation and are never
				// re-added, so a changed per-mount `shift` is a silent no-op. Warn
				// when an attached mount device's shift drifts from the current
				// config (#604), mirroring the shell reuse path.
				if s.mountConfig != nil {
					session.WarnMountShiftDrift(s.containerName, s.mountConfig.Mounts, logFn)
				}
				// A named session (session_name) can be reused from a different
				// workspace location than the container was created with — the
				// persisted workspace device then points at the old source and
				// must be replaced before applySecurityMounts derives overlays
				// from the container-side workspace path.
				if cwp, moved, err := session.RemountMovedWorkspace(mgr, s.absWorkspace, a.cfg.Paths.PreserveWorkspacePath, layout, s.useShift, logFn); err != nil {
					return err
				} else if moved {
					s.containerWorkspace = cwp
				}
				secErr := a.applySecurityMounts(secDevices, s.absWorkspace, s.containerWorkspace, s.containerName, s.useShift, layout)
				secDevices.Finish() // before the start: drop devices not requested this run
				return secErr
			}

			s.mgr = mgr
			// The teardown pairs with THIS phase's acquisitions: the pre-start
			// hook applies host-side immutable flags (chattr +i on protected
			// paths inside the workspace), so their removal belongs here — not in
			// a later phase whose teardown never registers if that phase (or this
			// one) fails first. Leaked +i flags make the workspace undeletable
			// (pytest tmpdir cleanup EPERM).
			teardown := func() {
				logFn := stderrLogFn
				session.RemoveImmutable(s.containerName, logFn)
				if !a.persistent {
					fmt.Fprintf(os.Stderr, "Cleaning up container %s...\n", s.containerName)
					_ = s.mgr.Delete(true)
				} else {
					if running, _ := s.mgr.Running(); running {
						fmt.Fprintf(os.Stderr, "Stopping persistent container %s...\n", s.containerName)
						_ = s.mgr.Stop(false)
					}
				}
			}

			stopLaunch := timing.Start(timing.CatStep, "launch-or-reuse")
			launchErr := launchOrReuseContainer(mgr, s.img, a.cfg.Container.StoragePool, s.containerName, containerExists, a.persistent, preStart, preRestart, hardening)
			stopLaunch()
			if launchErr != nil {
				// No teardown on a failed launch: launchOrReuseContainer already
				// removed the half-created container when it was safe to (never a
				// running one — a concurrent invocation may own it), and the
				// teardown's unconditional delete must not fire on a container
				// that may not be ours. Only the immutable flags the pre-start
				// hook may have applied need releasing here.
				logFn := stderrLogFn
				session.RemoveImmutable(s.containerName, logFn)
				return nil, launchErr
			}

			// From here the container is definitively ours (we created or
			// restarted it) — register the teardown, including alongside an
			// error: the pipeline registers teardowns returned with a failed Run.

			// Block egress immediately after first boot, before the container's
			// init can phone home, until the real isolation rules land in
			// apply-network (which removes this temporary rule). Shell parity
			// (#726 follow-up). Only for non-open modes: open opts into
			// unrestricted egress, and its network path never removes a boot
			// block (applyNetworkIsolation short-circuits), so installing one
			// there would strand the container with no network. Fail closed.
			if m := a.cfg.Network.Mode; m != "" && m != config.NetworkModeOpen {
				if err := network.ApplyBootBlockRule(s.containerName); err != nil {
					return teardown, fmt.Errorf("boot network block failed in %s mode; refusing to run with an unprotected boot window: %w", m, err)
				}
			}

			if err := applyContainerAlias(s.effectiveAlias, s.containerName, s.absWorkspace); err != nil {
				return teardown, err
			}

			return teardown, nil
		},
	}
}

// configureContainerRunPhase applies resource limits, waits for the container
// to be ready, and remaps the code user's UID/GID if configured. Disk devices
// (workspace, additional mounts, security + secret overlays) and the immutable
// flags are the launch phase's job now — attached by its pre-start hook,
// released by its teardown (#534); only the wasRestarted reuse path resolves
// its existing workspace mount path here.
func (a *App) configureContainerRunPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "configure-container",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			if !s.wasRestarted {
				limitsConfig := &a.cfg.Limits
				if limitsConfig.HasAny() {
					fmt.Fprintf(os.Stderr, "Applying resource limits...\n")
					applyOpts := limits.ApplyOptions{
						ContainerName: s.containerName,
						CPU: limits.CPULimits{
							Count:     limitsConfig.CPU.Count,
							Allowance: limitsConfig.CPU.Allowance,
							Priority:  limitsConfig.CPU.Priority,
						},
						Memory: limits.MemoryLimits{
							Limit:   limitsConfig.Memory.Limit,
							Enforce: limitsConfig.Memory.Enforce,
							Swap:    limitsConfig.Memory.Swap,
						},
						Disk: limits.DiskLimits{
							Read:     limitsConfig.Disk.Read,
							Write:    limitsConfig.Disk.Write,
							Max:      limitsConfig.Disk.Max,
							Size:     limitsConfig.Disk.Size,
							Priority: limitsConfig.Disk.Priority,
						},
						Runtime: limits.RuntimeLimits{
							MaxProcesses: limitsConfig.Runtime.MaxProcesses,
						},
						Project: a.cfg.Incus.Project,
					}
					if err := limits.ApplyResourceLimits(applyOpts); err != nil {
						return nil, fmt.Errorf("failed to apply resource limits: %w", err)
					}
				}
			}

			logFn := stderrLogFn

			// ctx is the pipeline's signal-cancelled context (run.go's
			// NotifyContext), so Ctrl+C aborts the wait instead of polling
			// out the window against a container teardown already deleted.
			if err := session.WaitForReady(ctx, s.mgr, a.cfg.Container.ReadyTimeoutSeconds(), logFn); err != nil {
				return nil, session.AnnotateReadyTimeout(err, &a.cfg.Limits)
			}

			// Configure the Docker bridge CIDR whenever Docker is enabled — on
			// reuse too, not only fresh launches: a persistent container flipped
			// from docker=false to docker=true has no daemon.json yet, so gating
			// on !wasRestarted would leave dockerd on its default 172.17/16
			// bridge. The write is idempotent.
			if a.hardeningPolicy().DockerEnabled() {
				if err := session.ConfigureDockerDaemon(s.mgr, logFn); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to configure Docker daemon: %v\n", err)
				}
			}
			if !s.wasRestarted {
				// Apply an explicit [limits.disk] tmpfs_size the same way the
				// shell path does, so a profile's /tmp sizing applies to
				// `coi run` too — the container is running now (#728/#769).
				session.ApplyTmpfsSizing(s.mgr, &a.cfg.Limits, logFn)
				if err := remapContainerUserIfNeeded(s.mgr, s.wasRestarted); err != nil {
					return nil, err
				}
			}

			// Git commit identity + [[credentials]], applied the same way the
			// shell path does so `coi run -- git commit`/credential-consuming
			// scripts behave identically (#726 follow-up). Applied on reuse too,
			// not just fresh launches: the shell path re-applies both on reuse
			// (setup.go runs them outside its fresh-only block), and the helpers
			// are idempotent (SetupGitIdentityReadonly re-mounts, SetupGitIdentity
			// re-writes, SetupCredentials re-pushes) — so a reused persistent
			// container picks up identity/credential config changes made since it
			// was created, instead of silently keeping stale values.
			homeDir := "/home/" + container.CodeUser
			gitID := resolveGitIdentity(&a.cfg.Git)
			stripAttribution := a.cfg.Git.IsStripAttributionEnabled()
			readonlyLock := a.cfg.Git.IsReadonlyEnabled() && gitID.Complete()
			identityLock := readonlyLock
			guardBranches := a.cfg.Git.EffectiveProtectedBranches()
			guardOn := len(guardBranches) > 0
			// core.hooksPath must be installed when ANY hook policy is active: the
			// strip hook, the identity re-stamp hook, or the branch guard (they
			// share the one hook dir).
			hooksPath := ""
			if stripAttribution || identityLock || guardOn {
				hooksPath = session.GitHooksDir
			}
			if readonlyLock {
				// Fail closed: the user asked to lock the identity read-only.
				// core.hooksPath for the hooks rides inside the mounted gitconfig
				// (a live `git config --global` would fail against the read-only
				// mount).
				if err := session.SetupGitIdentityReadonly(s.mgr, homeDir, gitID, hooksPath); err != nil {
					return nil, fmt.Errorf("git.readonly: could not lock the commit identity read-only: %w", err)
				}
			} else {
				// Guard + identity + hooks (strip #788, identity re-stamp, branch
				// guard) or the stale core.hooksPath cleanup — one exec, as on the
				// shell path.
				session.SetupWritableGitConfig(s.mgr, homeDir, gitID, stripAttribution, a.cfg.Git.StripAttributionPatterns, identityLock, guardBranches, logFn)
			}
			// Read-only gitconfig: the hook dir is still needed; core.hooksPath
			// rides inside the mounted gitconfig.
			if readonlyLock && (stripAttribution || identityLock || guardOn) {
				session.SetupGitHooks(s.mgr, homeDir, gitID, stripAttribution, a.cfg.Git.StripAttributionPatterns, identityLock, false, guardBranches, logFn)
			}
			// Layer 1: pin GIT_AUTHOR_*/GIT_COMMITTER_* container-level env so a
			// `-c user.*` override loses; no-op / unset when identity isn't locked.
			session.ApplyGitIdentityContainerEnv(ctx, s.containerName, gitID, identityLock, logFn)
			// Claude source-level layer for the same policy
			// (includeCoAuthoredBy=false via managed settings) — it also covers
			// the hook's two blind spots (local core.hooksPath repos, commits
			// with --no-verify). Auto-mode suppression stays off here: the run
			// pipeline never needed it (#764 concerns interactive sessions).
			if a.cfg.Tool.Name == "claude" {
				session.SetupClaudeManagedSettings(s.mgr, false, stripAttribution, logFn)
			}
			if err := session.SetupCredentials(s.mgr, homeDir, s.credentialConfig, logFn); err != nil {
				return nil, fmt.Errorf("failed to set up credentials: %w", err)
			}

			// Disk devices (workspace, additional mounts, security + secret masks)
			// and the UID mapping were applied by the launch phase's pre-start
			// hook, BEFORE first start — so raw.idmap takes effect at boot (#530)
			// and a device on an idmap-incompatible filesystem (virtiofs) fails
			// the start where the isolation fallback covers it (#534). Only a
			// reused persistent container has work left here: resolve its existing
			// workspace mount path from the container config.
			// Reuse needs no work here: preRestart already resolved
			// s.containerWorkspace (including the moved-workspace remount) and
			// re-applied the security devices; re-reading the device here would
			// only mask a half-failed remount behind the "/workspace" fallback.

			// No teardown: the immutable-flag removal moved to the launch phase's
			// teardown, alongside the pre-start hook that now applies them —
			// so it runs even when a later phase (this one included) fails
			// before registering anything.
			return nil, nil
		},
	}
}

// applyNetworkRunPhase forwards the SSH agent and any configured [[sockets]],
// installs network isolation rules, configures the timezone, and trusts mise
// config. Its teardown removes the firewall rules before the container is deleted.
func (a *App) applyNetworkRunPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "apply-network",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			s.socketEnv = a.applyForwardSockets(s.mgr, s.socketConfig)

			// Publish [ports] on the host (localhost:<port> -> container)
			// and expose the mapping to the command env (COI_PORTS /
			// COI_PORT_<NAME>).
			logFn := stderrLogFn
			_, portsEnv := session.PublishResolvedPorts(s.mgr, s.resolvedPorts, logFn)
			for k, v := range portsEnv {
				if s.socketEnv == nil {
					s.socketEnv = map[string]string{}
				}
				s.socketEnv[k] = v
			}

			nm, err := a.applyNetworkIsolation(ctx, s.containerName)
			if err != nil {
				return nil, err
			}

			// Timezone ("" = UTC, resetting a reused container) and workspace
			// mise trust in one exec.
			s.tz = resolveTimezone(a.cfg)
			session.ConfigureTimezoneAndMiseTrust(s.mgr, s.tz, s.containerWorkspace, logFn)

			if nm == nil {
				return nil, nil
			}
			teardown := func() {
				// Use a fresh background context for teardown: the run context
				// may already be cancelled (SIGINT), but we must still remove
				// the nftables rules before the container is deleted.
				if err := nm.Teardown(context.Background(), s.containerName); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to teardown network isolation: %v\n", err)
				}
			}
			return teardown, nil
		},
	}
}

// startMonitoringRunPhase starts the security monitoring daemons for the run
// container via the shared startSessionMonitoring helper (same watchers as an
// agent session). Threat events land in the audit log via the responder;
// diagnostics use a discard logger (run has no session log file).
func (a *App) startMonitoringRunPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "start-monitoring",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			teardown := a.startSessionMonitoring(ctx, s.containerName, s.absWorkspace, logger.NewDiscard(), &s.monitorDaemon, &s.nftDaemon)
			return teardown, nil
		},
	}
}

// runCommandPhase starts the optional timeout monitor, executes the user's
// command inside the container via incus exec, and returns any exit-code error.
func (a *App) runCommandPhase(args []string, s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "run-command",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			timeoutMon := a.startRunTimeoutMonitor(ctx, s.containerName)
			defer func() {
				if timeoutMon != nil {
					timeoutMon.Stop()
				}
			}()

			// Run-script mode: execute the script straight from the workspace
			// mount — it comes from the host, nothing is pushed. It runs
			// directly, so the shebang decides the interpreter.
			execArgs := args
			if s.runScript {
				execArgs = []string{s.containerWorkspace + "/" + runScriptName}
				fmt.Fprintf(os.Stderr, "Running workspace run script: %s\n", runScriptName)
			} else {
				fmt.Fprintf(os.Stderr, "Executing: %s\n", strings.Join(args, " "))
			}

			incusArgs := []string{
				"exec", s.containerName, "--user", fmt.Sprintf("%d", container.CodeUID),
				"--group", fmt.Sprintf("%d", container.CodeUID), "--cwd", s.containerWorkspace,
			}
			incusArgs, err := a.appendEnvArgs(incusArgs, "/home/"+container.CodeUser, s.tz, s.socketEnv)
			if err != nil {
				return nil, err
			}
			incusArgs = append(incusArgs, "--")
			incusArgs = append(incusArgs, execArgs...)

			// Streamed exec: output appears live (a long build isn't silent
			// until completion) and stdin is connected for piped input.
			if err := container.IncusExecStreamedContext(ctx, incusArgs...); err != nil {
				if exitErr, ok := err.(*container.ExitError); ok {
					fmt.Fprintf(os.Stderr, "\nCommand exited with code %d\n", exitErr.ExitCode)
					return nil, &ExitCodeError{Code: exitErr.ExitCode}
				}
				return nil, fmt.Errorf("command failed: %w", err)
			}

			fmt.Fprintf(os.Stderr, "\nCommand completed successfully\n")
			return nil, nil
		},
	}
}

// startRunTimeoutMonitor starts the [limits.runtime] max_duration monitor for a
// run container, or returns nil when no max_duration is configured. Shared by
// the command and prompt run phases. Call Stop() on the result when done.
func (a *App) startRunTimeoutMonitor(ctx context.Context, containerName string) *limits.TimeoutMonitor {
	if a.cfg.Limits.Runtime.MaxDuration == "" {
		return nil
	}
	maxDur, _ := limits.ParseDuration(a.cfg.Limits.Runtime.MaxDuration)
	autoStop := config.BoolVal(a.cfg.Limits.Runtime.AutoStop)
	if a.cfg.Limits.Runtime.AutoStop == nil {
		autoStop = true
	}
	stopGraceful := config.BoolVal(a.cfg.Limits.Runtime.StopGraceful)
	mon := limits.NewTimeoutMonitor(ctx, containerName, maxDur, autoStop, stopGraceful, a.cfg.Incus.Project, logger.NewDiscard())
	mon.Start()
	return mon
}

// runPromptPhase runs the AI agent headlessly with a predefined prompt and
// propagates its exit code (#701). It seeds the agent's auth/context/model env
// (which the lean run pipeline otherwise skips), stages the prompt into a
// container file so arbitrary text never touches the command line, builds the
// tool's headless (print-mode) launch command, and execs it through `bash -lc`
// so the "$(cat <file>)" prompt substitution expands.
func (a *App) runPromptPhase(s *runState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "run-prompt",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			timeoutMon := a.startRunTimeoutMonitor(ctx, s.containerName)
			defer func() {
				if timeoutMon != nil {
					timeoutMon.Stop()
				}
			}()

			// The tool was resolved and validated (claude-only, non-interactive)
			// in resolvePromptMode; reuse it rather than rebuilding.
			t := s.promptTool
			if t == nil {
				return nil, fmt.Errorf("internal error: prompt tool was not resolved before run-prompt phase")
			}

			// Resolve the uid the agent runs as and the home its runs dir lives
			// under (code user, or root when the image has none).
			uid, homeDir, err := toolSpecUserHome(s.mgr)
			if err != nil {
				return nil, err
			}

			// Seed tool auth + context + model/effort env, exactly as an
			// interactive `coi shell` session does — the lean run pipeline skips
			// this, but a headless agent needs it to authenticate and load context.
			hostHome, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to resolve host home directory: %w", err)
			}
			var cliConfigPath string
			if dirName := t.ConfigDirName(); dirName != "" {
				// VM-aware: fall back to the shared macOS home under Colima/Lima/
				// OrbStack when the guest home lacks the tool config dir, matching
				// the interactive `coi shell` seeding path (#817).
				var configFiles []string
				if tcf, ok := t.(tool.ToolWithConfigDirFiles); ok {
					configFiles = tcf.EssentialConfigFiles()
				}
				// Headless run path: no interactive Keychain hint here (an
				// orchestrator consumes this output); the hint is shell-only (#818).
				cliConfigPath, _ = vmhost.HostToolConfigDir(hostHome, dirName, configFiles)
			}
			seedResult := &session.SetupResult{
				Manager:                s.mgr,
				ContainerName:          s.containerName,
				ContainerWorkspacePath: s.containerWorkspace,
				HomeDir:                homeDir,
				Timezone:               s.tz,
			}
			seedOpts := session.SetupOptions{
				Tool:          t,
				CLIConfigPath: cliConfigPath,
				LimitsConfig:  &a.cfg.Limits,
				Persistent:    a.persistent,
				Logger:        stderrLogFn,
				Context: session.ContextOptions{
					Auto:             a.cfg.Tool.AutoContext,
					JSON:             a.cfg.Tool.ContextJSON,
					FilePath:         a.cfg.Tool.ContextFile,
					JSONFilePath:     a.cfg.Tool.ContextJSONFile,
					ProfileFile:      a.cfg.ProfileContextFile,
					ForwardedEnvVars: resolveForwardedEnvVarNames(a.cfg.Defaults.ForwardEnv),
				},
				Network: session.NetworkOptions{
					Config: &a.cfg.Network,
				},
				// The branch guard is active on this run (installed earlier via
				// SetupGitHooks); surface it in the generated context so a headless
				// agent knows from startup not to commit/push to a protected branch.
				Git: session.GitOptions{
					ProtectedBranches: a.cfg.Git.EffectiveProtectedBranches(),
				},
				Security: session.SecurityOptions{
					// The kernel-surface flags feed injectSandboxContext's Docker
					// availability line; omitting them here (zero value = docker
					// off) would make every headless run's context claim Docker is
					// unavailable while the container actually has it (the launch
					// phase applies the real policy). Mirrors phases_shell.go.
					// The strict tier is intentionally not threaded here: this seed
					// path only drives the Docker-availability line, which depends
					// solely on DockerEnabled() — and ReduceKernelSurface already
					// reflects the strict tier (it implies the base flag).
					Docker:              a.cfg.Container.IsDockerEnabled(),
					ReduceKernelSurface: a.cfg.Security.IsReduceKernelSurfaceEnabled(),
				},
			}
			if err := session.SeedToolConfigForRun(ctx, seedResult, seedOpts); err != nil {
				return nil, err
			}

			// Stage the prompt as an in-container file owned by the run user
			// (shared runs-dir helper with `coi tool spec`).
			runsDir, err := ensureContainerRunsDir(s.mgr, homeDir, uid)
			if err != nil {
				return nil, err
			}
			promptPath := filepath.Join(runsDir, s.promptSessionID+".prompt")
			if err := s.mgr.CreateFileWithOwner(promptPath, s.promptText, uid, uid, "0600"); err != nil {
				return nil, fmt.Errorf("failed to stage prompt file in container: %w", err)
			}

			// Build the headless (print-mode) launch command. A fresh session per
			// fire (Resume:false) is the right cron default — deterministic, no
			// accumulating conversation state.
			argv, outOfBand, err := buildToolLaunchArgv(t, tool.LaunchSpec{
				SessionID:  s.promptSessionID,
				PromptFile: promptPath,
				Print:      true,
			})
			if err != nil {
				return nil, err
			}
			if outOfBand != "" {
				// Tool can't embed the prompt in argv and coi run has no
				// orchestrator to deliver it out-of-band.
				return nil, &ExitCodeError{Code: 2, Message: fmt.Sprintf(
					"tool %q cannot run a prompt headlessly via coi run", t.Name())}
			}

			// incus exec as the run user; route through a non-login shell so the
			// argv's "$(cat <prompt-file>)" substitution expands without sourcing
			// profile scripts (whose stdout would pollute the agent's output).
			// HOME is pinned to the resolved home so it matches where the tool
			// config was seeded (matters for a no-code-user/root image). Model and
			// effort reach the agent via SeedToolConfigForRun (container-level env
			// + settings.json), so no per-exec tool env is needed here.
			incusArgs := []string{
				"exec", s.containerName, "--user", fmt.Sprintf("%d", uid),
				"--group", fmt.Sprintf("%d", uid), "--cwd", s.containerWorkspace,
			}
			incusArgs, err = a.appendEnvArgs(incusArgs, homeDir, s.tz, s.socketEnv)
			if err != nil {
				return nil, err
			}
			incusArgs = append(incusArgs, "--", "bash", "-c", strings.Join(argv, " "))

			fmt.Fprintf(os.Stderr, "Running headless prompt with %s (session %s)...\n", t.Name(), s.promptSessionID)
			if err := container.IncusExecStreamedContext(ctx, incusArgs...); err != nil {
				if exitErr, ok := err.(*container.ExitError); ok {
					fmt.Fprintf(os.Stderr, "\nAgent exited with code %d\n", exitErr.ExitCode)
					return nil, &ExitCodeError{Code: exitErr.ExitCode}
				}
				return nil, fmt.Errorf("headless prompt run failed: %w", err)
			}

			fmt.Fprintf(os.Stderr, "\nPrompt run completed successfully\n")
			return nil, nil
		},
	}
}
