package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/alias"
	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/nftmonitor"
	"github.com/coipond/coi/internal/session"
	"github.com/coipond/coi/internal/tool"
	"github.com/coipond/coi/internal/vmhost"
	"github.com/spf13/cobra"
)

// shellState is the mutable state accumulated across shell pipeline phases.
// Each phase reads its inputs from state and writes its outputs back.
type shellState struct {
	aliasArg string // positional argument from cobra args[0], if given

	// After resolve-workspace
	absWorkspace string

	// After validate-env
	useTmux bool // determined from [shell] use_tmux config (default true)

	// After configure-session
	sessionID    string
	resumeID     string
	slotNum      int
	toolInstance tool.Tool
	sessionsDir  string
	setupOpts    session.SetupOptions // fully built options for session.Setup

	// After setup-container
	result *session.SetupResult

	// After start-monitoring
	monitorDaemon monitor.MonitorDaemon
	nftDaemon     nftmonitor.NFTMonitorDaemon
}

// resolveWorkspacePhase resolves the absolute workspace path from --workspace
// or alias, overlays the workspace's project config, and applies any alias
// profile/slot inherited from the registry.
func (a *App) resolveWorkspacePhase(cmd *cobra.Command, s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "resolve-workspace",
		RunFn: func(_ context.Context) (session.Teardown, error) {
			absWorkspace, err := filepath.Abs(a.workspace)
			if err != nil {
				return nil, fmt.Errorf("invalid workspace path: %w", err)
			}

			// When no alias is given, overlay the workspace's project config when it
			// differs from CWD (config.Load only reads from CWD).
			if s.aliasArg == "" {
				if cwd, err := os.Getwd(); err == nil {
					if absCWD, err := filepath.Abs(cwd); err == nil && absWorkspace != absCWD {
						if err := a.cfg.OverlayProjectConfig(absWorkspace); err != nil && !os.IsNotExist(err) {
							return nil, fmt.Errorf("failed to load project config from %s: %w", absWorkspace, err)
						}
						container.Configure(a.cfg.Incus.Project, a.cfg.Incus.CodeUser, a.cfg.Incus.CodeUID)
					}
				}
			}

			// Alias resolution overrides workspace and may apply a saved profile/slot.
			if s.aliasArg != "" {
				resolved, err := alias.ResolveAliasForLaunch(s.aliasArg)
				if err != nil {
					return nil, err
				}
				absWorkspace = resolved.Workspace

				if err := a.cfg.OverlayProjectConfig(absWorkspace); err != nil && !os.IsNotExist(err) {
					return nil, fmt.Errorf("failed to load project config from %s: %w", absWorkspace, err)
				}

				if resolved.Profile != "" && !cmd.Flags().Changed("profile") {
					a.profile = resolved.Profile
					if err := a.cfg.ApplyProfile(a.profile); err != nil {
						return nil, err
					}
				}
				container.Configure(a.cfg.Incus.Project, a.cfg.Incus.CodeUser, a.cfg.Incus.CodeUID)
				if resolved.Slot > 0 && !cmd.Flags().Changed("slot") {
					a.slot = resolved.Slot
				}
			}

			// An explicitly requested --profile must keep winning over the
			// workspace/alias overlays for [container] settings — otherwise a
			// project config could silently override the profile the user
			// asked for, with precedence depending on the invocation
			// directory. (The alias branch above re-applies a saved profile
			// only when --profile was NOT given, so this covers the rest.)
			if cmd.Flags().Changed("profile") && a.profile != "" {
				if err := a.cfg.ReapplyProfileContainer(a.profile); err != nil {
					return nil, err
				}
			}

			// The workspace/alias config overlays (and an alias-applied
			// profile) may set [container] persistent — PersistentPreRunE
			// computed a.persistent before they ran, so recompute it here.
			// Resume metadata (configureSessionPhase) still overrides later.
			a.persistent = config.BoolVal(a.cfg.Container.Persistent)

			s.absWorkspace = absWorkspace
			return nil, nil
		},
	}
}

// validateEnvPhase determines the effective tmux mode ([shell] use_tmux,
// default true) and verifies that Incus is available and at the minimum
// required version.
func (a *App) validateEnvPhase(cmd *cobra.Command, s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "validate-env",
		RunFn: func(_ context.Context) (session.Teardown, error) {
			// Tmux mode is config-driven: [shell] use_tmux (default true).
			s.useTmux = true
			if a.cfg.Shell.UseTmux != nil {
				s.useTmux = *a.cfg.Shell.UseTmux
			}

			// Both are independent incus round trips: run them side by side.
			versionErr := make(chan error, 1)
			go func() { versionErr <- container.CheckMinimumVersion() }()
			if !container.Available() {
				return nil, container.IncusNotAvailableError()
			}
			if err := <-versionErr; err != nil {
				return nil, err
			}
			if warning := container.CheckKernelVersion(); warning != "" {
				fmt.Fprintf(os.Stderr, "%s\n", warning)
			}
			return nil, nil
		},
	}
}

// configureSessionPhase assembles all session options: chooses the tool,
// determines the sessions directory, resolves the resume ID, allocates a
// slot, and constructs the SetupOptions for the container.
//
//nolint:gocyclo // Many configuration paths — sequential by design
func (a *App) configureSessionPhase(cmd *cobra.Command, s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "configure-session",
		RunFn: func(ctx context.Context) (_ session.Teardown, retErr error) {
			ti, err := getConfiguredTool(a.cfg)
			if err != nil {
				return nil, err
			}
			s.toolInstance = ti

			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
			baseDir := filepath.Join(homeDir, ".coi")
			sessionsDir := session.GetSessionsDir(baseDir, ti)
			if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
				return nil, fmt.Errorf("failed to create sessions directory: %w", err)
			}
			s.sessionsDir = sessionsDir

			// Resolve the resume/continue ID.
			resumeID := a.resume
			if a.continueSession != "" {
				resumeID = a.continueSession
			}
			// No profile selected by --profile or an alias: fall back to
			// [defaults] profile (#607) BEFORE the resume lookup — the profile
			// may carry [container] session_name, which keys which saved
			// sessions the auto-resume below can even see. A resume-remembered
			// profile still wins: the metadata block below applies it ON TOP
			// (ApplyProfile merges over), preserving the
			// explicit > alias > resume > default precedence.
			if applied, err := a.applyDefaultProfileFallback(cmd); err != nil {
				return nil, err
			} else if applied {
				// The profile may set [container] persistent; on resume the
				// metadata reconciliation below still overrides via
				// resumePersistence.
				a.persistent = config.BoolVal(a.cfg.Container.Persistent)
			}

			resumeFlagSet := cmd.Flags().Changed("resume") || cmd.Flags().Changed("continue")

			isWorkspaceSessionTool := false
			if ti.Name() == "opencode" {
				workspaceSessionDir := filepath.Join(s.absWorkspace, ".opencode")
				if info, err := os.Stat(workspaceSessionDir); err == nil && info.IsDir() {
					isWorkspaceSessionTool = true
				}
			}

			if resumeFlagSet && (resumeID == "" || resumeID == "auto") {
				if isWorkspaceSessionTool {
					resumeID = "workspace-session"
					fmt.Fprintf(os.Stderr, "Resuming %s session from workspace\n", ti.Name())
				} else {
					resumeID, err = session.GetLatestSessionForWorkspace(sessionsDir, s.absWorkspace, a.sessionName())
					if err != nil {
						return nil, fmt.Errorf("no previous session to resume for this workspace: %w", err)
					}
					fmt.Fprintf(os.Stderr, "Auto-detected session: %s\n", resumeID)
				}
			} else if resumeID != "" && !isWorkspaceSessionTool {
				if !session.SessionExists(sessionsDir, resumeID) {
					return nil, fmt.Errorf("session '%s' not found - check available sessions with: coi list --all", resumeID)
				}
				fmt.Fprintf(os.Stderr, "Resuming session: %s\n", resumeID)
			}
			s.resumeID = resumeID

			// Inherit persistent flag, profile, and slot from session metadata.
			var resumeSlot int
			if resumeID != "" && !isWorkspaceSessionTool {
				metadataPath := filepath.Join(sessionsDir, resumeID, "metadata.json")
				if metadata, err := session.LoadSessionMetadata(metadataPath); err == nil {
					if !cmd.Flags().Changed("profile") && metadata.ProfileName != "" {
						a.profile = metadata.ProfileName
						if err := a.cfg.ApplyProfile(a.profile); err != nil {
							return nil, fmt.Errorf("failed to apply saved profile '%s': %w", a.profile, err)
						}
						fmt.Fprintf(os.Stderr, "Inherited profile '%s' from session\n", a.profile)
					}
					// Session metadata records how the session was actually
					// created and is the default on resume — but an EXPLICIT
					// [container] persistent in the effective config wins, so
					// a user can still convert a session's mode (with the
					// --persistent flag removed, config is the only lever;
					// unconditional metadata would make ephemeral-ness sticky
					// forever, re-recorded into metadata on every resume).
					a.persistent = resumePersistence(a.cfg.Container.Persistent, metadata.Persistent)
					if a.persistent != metadata.Persistent {
						fmt.Fprintf(os.Stderr,
							"Config [container] persistent = %v overrides the session's saved mode\n",
							a.persistent)
					}
					if a.persistent {
						fmt.Fprintf(os.Stderr, "Inherited persistent mode from session\n")
					}
					if !cmd.Flags().Changed("slot") {
						if _, origSlot, err := session.ParseContainerName(metadata.ContainerName); err == nil {
							resumeSlot = origSlot
						}
					}
				}
			}

			// Generate or reuse session ID.
			if resumeID != "" {
				s.sessionID = resumeID
			} else {
				id, err := session.GenerateSessionID()
				if err != nil {
					return nil, err
				}
				s.sessionID = id
			}

			// Serialise slot selection with concurrent launches of the same
			// workspace/session_name until our container is up (see
			// session.AcquireLaunchLock); released via SetupOptions.OnContainerUp,
			// or below / at teardown if anything fails first.
			releaseLaunchLock, err := session.AcquireLaunchLock(ctx, s.absWorkspace, a.sessionName(), func(m string) { fmt.Fprintln(os.Stderr, m) })
			if err != nil {
				return nil, err
			}
			defer func() {
				if retErr != nil {
					releaseLaunchLock()
				}
			}()

			// Allocate slot.
			slotNum := a.slot
			if resumeSlot > 0 && slotNum == 0 {
				slotNum = resumeSlot
				fmt.Fprintf(os.Stderr, "Reusing original slot %d from session\n", slotNum)
			} else if slotNum == 0 {
				// Persistent mode: prefer restarting the identity's stopped
				// container over allocating a fresh slot — for a NAMED
				// persistent session this is the core promise (auto-allocation
				// would otherwise fork it on every plain `coi shell`), and it
				// mirrors what the run pipeline has done since #610.
				if a.persistent {
					if reuse, ok := session.FindReusablePersistentSlot(s.absWorkspace, a.sessionName(), 10); ok {
						slotNum = reuse
						fmt.Fprintf(os.Stderr, "Reusing stopped persistent container on slot %d\n", slotNum)
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
			} else {
				available, err := session.IsSlotAvailable(s.absWorkspace, a.sessionName(), slotNum)
				if err != nil {
					return nil, fmt.Errorf("failed to check slot availability: %w", err)
				}
				if !available {
					orig := slotNum
					slotNum, err = session.AllocateSlotFrom(s.absWorkspace, a.sessionName(), slotNum+1, 10)
					if err != nil {
						return nil, fmt.Errorf("slot %d is occupied and failed to find next available slot: %w", orig, err)
					}
					fmt.Fprintf(os.Stderr, "Slot %d is occupied, using slot %d instead\n", orig, slotNum)
					warnNamedSessionFork(s.absWorkspace, a.sessionName(), slotNum)
				}
			}
			s.slotNum = slotNum

			// Resolve image and auto-build if needed.
			img := ResolveImageName(a.cfg)
			if err := AutoBuildIfNeeded(a.cfg, img); err != nil {
				return nil, err
			}
			if err := CheckAndReportStaleBase(a.cfg, img); err != nil {
				return nil, err
			}
			// Validate the configured storage pool up front (matching coi run),
			// so a typo fails clearly instead of the container silently landing
			// on the default pool (#726).
			if err := container.ValidateStoragePool(a.cfg.Container.StoragePool); err != nil {
				return nil, err
			}

			// Build config-derived options.
			networkConfig := a.cfg.Network
			limitsConfig := &a.cfg.Limits
			var protectedPaths []string
			if !a.cfg.Security.DisableProtection {
				protectedPaths = a.cfg.Security.GetEffectiveProtectedPaths()
			}
			protectedPaths = filterWritableGitHooks(protectedPaths, a.cfg)

			var cliConfigPath string
			if configDirName := ti.ConfigDirName(); configDirName != "" {
				// VM-aware: inside a Colima/Lima/OrbStack Mac VM this falls back to
				// the config dir under the shared macOS home when the guest home has
				// none, so tool credentials seed correctly (#817).
				var configFiles []string
				if tcf, ok := ti.(tool.ToolWithConfigDirFiles); ok {
					configFiles = tcf.EssentialConfigFiles()
				}
				var vmKind vmhost.Kind
				cliConfigPath, vmKind = vmhost.HostToolConfigDir(homeDir, configDirName, configFiles)
				// macOS: if the tool's credential lives in the Keychain (no file to
				// seed), tell the user how to materialize it on the Mac (#818). Stay
				// quiet for API-key auth or a resumed session (already logged in).
				printMacKeychainHint(ti, cliConfigPath, vmKind,
					apiKeyAuthConfigured(a.cfg.Defaults.ForwardEnv), resumeFlagSet)
			}

			resolvedForwardedEnvVars := resolveForwardedEnvVarNames(a.cfg.Defaults.ForwardEnv)
			resolvedTimezone := resolveTimezone(a.cfg)

			mountConfig, err := ParseMountConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid mount configuration: %w", err)
			}
			socketConfig, err := ParseSocketConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid socket configuration: %w", err)
			}
			credConfig, err := ParseCredentialConfig(a.cfg)
			if err != nil {
				return nil, fmt.Errorf("invalid credential configuration: %w", err)
			}
			portConfig := ParsePortConfig(a.cfg)
			// Untrusted mounts/sockets are gated at the session.Setup chokepoint
			// (combined trust fingerprint over both); pass them through unfiltered.
			if err := session.ValidateMounts(mountConfig); err != nil {
				return nil, fmt.Errorf("mount validation failed: %w", err)
			}

			if a.cfg.Container.Alias != "" {
				if err := alias.ValidateAlias(a.cfg.Container.Alias); err != nil {
					return nil, fmt.Errorf("invalid container alias: %w", err)
				}
			}

			s.setupOpts = session.SetupOptions{
				OnContainerUp:         releaseLaunchLock,
				WorkspacePath:         s.absWorkspace,
				SessionName:           a.sessionName(),
				Image:                 img,
				StoragePool:           a.cfg.Container.StoragePool,
				Persistent:            a.persistent,
				ResumeFromID:          resumeID,
				Slot:                  slotNum,
				MountConfig:           mountConfig,
				CredentialConfig:      credConfig,
				SessionsDir:           sessionsDir,
				CLIConfigPath:         cliConfigPath,
				Tool:                  ti,
				PermissionMode:        a.cfg.Tool.PermissionMode,
				DisableShift:          a.cfg.Incus.DisableShift,
				LimitsConfig:          limitsConfig,
				IncusProject:          a.cfg.Incus.Project,
				PreserveWorkspacePath: a.cfg.Paths.PreserveWorkspacePath,
				ContainerName:         containerName,
				Timezone:              resolvedTimezone,
				Alias:                 a.cfg.Container.Alias,
				ReadyTimeout:          a.cfg.Container.ReadyTimeoutSeconds(),
				Git: session.GitOptions{
					Identity:                 resolveGitIdentity(&a.cfg.Git),
					Readonly:                 a.cfg.Git.IsReadonlyEnabled(),
					StripAttribution:         a.cfg.Git.IsStripAttributionEnabled(),
					StripAttributionPatterns: a.cfg.Git.StripAttributionPatterns,
					ProtectedBranches:        a.cfg.Git.EffectiveProtectedBranches(),
				},
				Security: session.SecurityOptions{
					ProtectedPaths:            protectedPaths,
					Config:                    &a.cfg.Security,
					SecretPaths:               a.cfg.Security.SecretPaths,
					HostImmutable:             a.cfg.Security.IsHostImmutableEnabled(),
					Docker:                    a.cfg.Container.IsDockerEnabled(),
					ReduceKernelSurface:       a.cfg.Security.IsReduceKernelSurfaceEnabled(),
					ReduceKernelSurfaceStrict: a.cfg.Security.IsReduceKernelSurfaceStrictEnabled(),
				},
				Network: session.NetworkOptions{
					Config:          &networkConfig,
					Ports:           portConfig,
					Sockets:         socketConfig,
					ForwardSSHAgent: config.BoolVal(a.cfg.SSH.ForwardAgent),
				},
				Context: session.ContextOptions{
					FilePath:         a.cfg.Tool.ContextFile,
					ProfileFile:      a.cfg.ProfileContextFile,
					Auto:             a.cfg.Tool.AutoContext,
					JSON:             a.cfg.Tool.ContextJSON,
					JSONFilePath:     a.cfg.Tool.ContextJSONFile,
					ForwardedEnvVars: resolvedForwardedEnvVars,
				},
			}
			warnDockerHardeningConflict(a.cfg)
			// Teardown releases the lock if setup never reached container-up.
			return func() { releaseLaunchLock() }, nil
		},
	}
}

// setupContainerPhase calls session.Setup, saves early metadata for coi list,
// and registers the alias in the global registry. Its teardown calls
// session.Cleanup so the container and session data are handled correctly on
// all exit paths.
func (a *App) setupContainerPhase(s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "setup-container",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			fmt.Fprintf(os.Stderr, "Setting up session %s...\n", s.sessionID)
			result, err := session.Setup(ctx, s.setupOpts)
			if err != nil {
				return nil, fmt.Errorf("failed to setup session: %w", err)
			}
			s.result = result

			if err := session.SaveMetadataEarly(s.sessionsDir, s.sessionID, result.ContainerName, s.absWorkspace, a.persistent, a.profile); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to save early metadata: %v\n", err)
			}

			if effectiveAlias := a.cfg.Container.Alias; effectiveAlias != "" {
				if reg, err := alias.Load(); err == nil {
					if err := reg.Register(effectiveAlias, s.absWorkspace, a.profile); err != nil {
						return nil, fmt.Errorf("alias conflict: %w", err)
					}
					if err := reg.Save(); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: Failed to save alias registry: %v\n", err)
					}
				}
			}

			teardown := func() {
				fmt.Fprintf(os.Stderr, "\nCleaning up session...\n")
				if s.result.TimeoutMonitor != nil {
					s.result.TimeoutMonitor.Stop()
				}
				cleanupOpts := session.CleanupOptions{
					ContainerName:  s.result.ContainerName,
					SessionID:      s.sessionID,
					Persistent:     a.persistent,
					ProfileName:    a.profile,
					SessionsDir:    s.sessionsDir,
					SaveSession:    true,
					Workspace:      s.absWorkspace,
					Tool:           s.toolInstance,
					NetworkManager: s.result.NetworkManager,
					SessionLogger:  s.result.Logger,
					// Bound the wait for an in-flight `close`/poweroff by the
					// same budget graceful shutdowns get everywhere else.
					ShutdownTimeout: a.cfg.Container.ShutdownTimeoutSeconds(),
				}
				if err := session.Cleanup(cleanupOpts); err != nil {
					fmt.Fprintf(os.Stderr, "Cleanup error: %v\n", err)
				}
			}
			return teardown, nil
		},
	}
}

// startMonitoringPhase starts the session's security monitoring and runtime
// limit in a per-container supervisor (see supervise.go) that outlives this
// command. If the supervisor can't start, it falls back to running the
// monitors in-process (startSessionMonitoring, shared with the run pipeline),
// whose teardown stops them.
func (a *App) startMonitoringPhase(s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "start-monitoring",
		RunFn: func(ctx context.Context) (session.Teardown, error) {
			// Hand monitoring and the runtime limit to a supervisor that lives
			// as long as the container, so they keep running after this
			// command returns (--background, detach, or exiting the agent
			// with the container kept running).
			var runtime config.RuntimeLimits
			if s.setupOpts.LimitsConfig != nil {
				runtime = s.setupOpts.LimitsConfig.Runtime
			}
			if needsSupervisor(a.cfg, runtime) {
				already, err := startSessionSupervisor(supervisorState{
					ContainerName: s.result.ContainerName,
					WorkspacePath: s.absWorkspace,
					Incus:         a.cfg.Incus,
					Network:       a.cfg.Network,
					Monitoring:    a.cfg.Monitoring,
					Detection:     a.cfg.Detection,
					Runtime:       runtime,
				}, s.result.Logger)
				if err == nil {
					fmt.Fprintln(os.Stderr, supervisorNotice(config.BoolVal(a.cfg.Monitoring.Enabled), runtime.MaxDuration, already, s.result.Logger.ErrPath()))
					// The supervisor enforces max_duration from here on.
					if s.result.TimeoutMonitor != nil {
						s.result.TimeoutMonitor.Stop()
						s.result.TimeoutMonitor = nil
					}
					return nil, nil
				}
				fmt.Fprintf(os.Stderr, "Warning: could not start the session supervisor (%v); monitoring and the runtime limit stop when this command exits\n", err)
			}
			teardown := a.startSessionMonitoring(ctx, s.result.ContainerName, s.absWorkspace, s.result.Logger, &s.monitorDaemon, &s.nftDaemon)
			return teardown, nil
		},
	}
}

// resumePersistence decides a resumed session's persistence: an explicitly
// configured [container] persistent (non-nil pointer — the embedded default
// leaves it unset) wins so users can convert a session's mode; otherwise the
// session metadata (how the session was actually created) is inherited.
func resumePersistence(cfgPersistent *bool, metadataPersistent bool) bool {
	if cfgPersistent != nil {
		return *cfgPersistent
	}
	return metadataPersistent
}

// runToolPhase executes the AI coding tool (via tmux or direct mode) and
// normalises expected exit conditions (SIGINT, container shutdown) to nil.
func (a *App) runToolPhase(s *shellState) session.Phase {
	return session.PhaseFunc{
		PhaseName: "run-tool",
		RunFn: func(_ context.Context) (session.Teardown, error) {
			fmt.Fprintf(os.Stderr, "\nStarting session...\n")
			fmt.Fprintf(os.Stderr, "Session ID: %s\n", s.sessionID)
			fmt.Fprintf(os.Stderr, "Container: %s\n", s.result.ContainerName)
			fmt.Fprintf(os.Stderr, "Workspace: %s\n", s.absWorkspace)

			useResumeFlag := (s.resumeID != "") && a.persistent
			restoreOnly := (s.resumeID != "") && !a.persistent

			var runErr error
			if s.useTmux {
				if background {
					fmt.Fprintf(os.Stderr, "Mode: Background (tmux)\n")
				} else {
					fmt.Fprintf(os.Stderr, "Mode: Interactive (tmux)\n")
				}
				if restoreOnly {
					fmt.Fprintf(os.Stderr, "Resume mode: Restored conversation (auto-detect)\n")
				} else if useResumeFlag {
					fmt.Fprintf(os.Stderr, "Resume mode: Persistent session\n")
				}
				fmt.Fprintf(os.Stderr, "\n")
				runErr = a.runCLIInTmux(s.result, s.sessionID, background, useResumeFlag, restoreOnly, s.sessionsDir, s.resumeID, s.toolInstance)
			} else {
				fmt.Fprintf(os.Stderr, "Mode: Direct (no tmux)\n")
				if restoreOnly {
					fmt.Fprintf(os.Stderr, "Resume mode: Restored conversation (auto-detect)\n")
				} else if useResumeFlag {
					fmt.Fprintf(os.Stderr, "Resume mode: Persistent session\n")
				}
				fmt.Fprintf(os.Stderr, "\n")
				runErr = a.runCLI(s.result, s.sessionID, useResumeFlag, restoreOnly, s.sessionsDir, s.resumeID, s.toolInstance)
			}

			// Normalise expected exit conditions so the pipeline doesn't log
			// a spurious error and the teardown (cleanup) still runs.
			if runErr != nil {
				errStr := runErr.Error()
				if errStr == "exit status 130" {
					return nil, nil
				}
				if strings.Contains(errStr, "Failed to retrieve PID") ||
					strings.Contains(errStr, "server exited") ||
					strings.Contains(errStr, "connection reset") ||
					errStr == "exit status 1" {
					return nil, nil
				}
			}
			return nil, runErr
		},
	}
}
