package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// 9 / 9.5 When resuming: restore session data if the container was recreated,
// inject fresh credentials, and refresh configured [[credentials]].
func (st *setupState) phaseResumeRestore(_ context.Context) (Teardown, error) {
	// Skip if tool uses ENV-based auth (no config directory)
	if st.opts.ResumeFromID != "" && st.opts.Tool != nil && st.opts.Tool.ConfigDirName() != "" {
		// If we launched a new container (not reusing persistent one), restore config from saved session
		if !st.skipLaunch && st.opts.SessionsDir != "" {
			if err := restoreSessionData(st.result.Manager, st.opts.ResumeFromID, st.result.HomeDir, st.opts.SessionsDir, st.opts.Tool, st.opts.Logger); err != nil {
				st.opts.Logger(fmt.Sprintf("Warning: Could not restore session data: %v", err))
			}
		}

		// Always inject fresh credentials/sandbox settings when resuming
		if tcf, ok := st.opts.Tool.(tool.ToolWithConfigDirFiles); ok {
			if st.opts.CLIConfigPath != "" || tcf.AlwaysSetupConfig() {
				copied, err := injectCredentials(st.result.Manager, st.opts.CLIConfigPath, st.result.HomeDir, tcf, st.opts.Logger)
				if err != nil {
					st.opts.Logger(fmt.Sprintf("Warning: Could not inject credentials: %v", err))
				}
				st.toolFiles = copied
			}
		}
	}

	// Refresh/copy configured [[credentials]] entries (catalog bundles and
	// ad-hoc). Independent of which Tool is selected. Re-run on every resume
	// (idempotent) so a rotated host credential stays in sync; on a fresh
	// session it's applied once at phaseSetupCredentials alongside CLI tool config.
	if st.opts.ResumeFromID != "" && st.opts.CredentialConfig != nil && len(st.opts.CredentialConfig.Entries) > 0 {
		st.opts.Logger("Refreshing configured credentials...")
		copied, err := setupCredentials(st.result.Manager, st.result.HomeDir, st.opts.CredentialConfig.Entries, st.opts.Logger)
		if err != nil {
			st.opts.Logger(fmt.Sprintf("Warning: Could not refresh credentials: %v", err))
		}
		st.copiedCredentials = copied
	}
	return nil, nil
}

// 10 / 10.2 / 10.5 Note reused mounts, auto-trust workspace mise config, and
// set the auto-context path for config-based tools (before setupCLIConfig).
func (st *setupState) phaseMountsAndContextPath(_ context.Context) (Teardown, error) {
	// Workspace and configured mounts are already mounted (added before container start in phaseCreateContainer)
	if st.skipLaunch {
		st.opts.Logger("Reusing existing workspace and mount configurations")
	}

	// Auto-trust mise config files in the workspace so mise doesn't
	// prompt or error when the workspace contains mise.toml / .tool-versions.
	// Deferred into the context-files exec (phaseInjectContext), like the
	// timezone, instead of a round trip of its own.
	st.pendingGuestOps = append(st.pendingGuestOps, miseTrustOp(st.result.ContainerWorkspacePath))

	// Set auto-context path for config-based tools (must happen before setupCLIConfig
	// so the path is included in GetSandboxSettings output)
	if st.opts.Tool != nil && config.BoolVal(st.opts.Context.Auto) {
		if acp, ok := st.opts.Tool.(tool.ToolWithAutoContextPath); ok {
			acp.SetAutoContextPath(filepath.Join(st.result.HomeDir, "SANDBOX_CONTEXT.md"))
		}
	}
	return nil, nil
}

// seedToolConfig copies the tool's config in and records the copied files for
// the grants report.
func (st *setupState) seedToolConfig(tcf tool.ToolWithConfigDirFiles) {
	copied, err := setupCLIConfig(st.result.Manager, st.opts.CLIConfigPath, st.result.HomeDir, tcf, st.opts.Logger)
	if err != nil {
		st.opts.Logger(fmt.Sprintf("Warning: Failed to setup %s config: %v", st.opts.Tool.Name(), err))
	}
	st.toolFiles = copied
}

// 11. Setup CLI tool config (skip if resuming — config already restored).
func (st *setupState) phaseSetupCLIConfig(_ context.Context) (Teardown, error) {
	if st.opts.Tool != nil {
		if tcf, ok := st.opts.Tool.(tool.ToolWithConfigDirFiles); ok {
			if st.opts.CLIConfigPath != "" && st.opts.ResumeFromID == "" {
				_, statErr := os.Stat(st.opts.CLIConfigPath)
				hostDirExists := statErr == nil

				if hostDirExists || tcf.AlwaysSetupConfig() {
					switch {
					case !st.skipLaunch:
						st.opts.Logger(fmt.Sprintf("Setting up %s config...", st.opts.Tool.Name()))
						st.seedToolConfig(tcf)
					case !toolConfigSeeded(st.result.Manager, st.result.HomeDir, tcf):
						// Persistent reuse with a tool coi hasn't seeded in this
						// container yet — e.g. a profile that shares [container]
						// session_name but sets a different [tool] name, so you
						// re-enter the same container (code, packages, state) with
						// another tool (#708 follow-up). Keyed on the tool's own
						// essential config files (not dir existence/content, which
						// the base image and agent installers pre-populate). Seed
						// its config once so it authenticates, without touching the
						// original tool's config or conversation history.
						st.opts.Logger(fmt.Sprintf("Setting up %s config in reused container (first use of this tool here)...", st.opts.Tool.Name()))
						st.seedToolConfig(tcf)
					default:
						st.opts.Logger(fmt.Sprintf("Reusing existing %s config (persistent container)", st.opts.Tool.Name()))
					}
				} else if statErr != nil && !os.IsNotExist(statErr) {
					return nil, fmt.Errorf("failed to check %s config directory: %w", st.opts.Tool.Name(), statErr)
				}
			} else if st.opts.ResumeFromID != "" {
				st.opts.Logger(fmt.Sprintf("Resuming session - using restored %s config", st.opts.Tool.Name()))
			}
		} else if st.opts.Tool.ConfigDirName() == "" {
			st.opts.Logger(fmt.Sprintf("Tool %s uses ENV-based auth, skipping config setup", st.opts.Tool.Name()))
		}
	}
	return nil, nil
}

// 11.1 Persist the tool's resolved env as container-level environment.* so
// every exec inherits the profile's tool config (#744).
func (st *setupState) phaseApplyToolEnv(ctx context.Context) (Teardown, error) {
	if st.opts.Tool != nil {
		applyToolContainerEnv(ctx, st.result.ContainerName, st.result.ContainerWorkspacePath, st.opts.Tool, st.opts.Logger)
	}
	// The last instance-config write of setup: read the applied config now,
	// in the background, overlapping the file copies that follow.
	st.startAppliedRead()
	return nil, nil
}

// 11.5 Setup configured [[credentials]] entries (fresh, non-resume launches).
func (st *setupState) phaseSetupCredentials(_ context.Context) (Teardown, error) {
	if !st.skipLaunch && st.opts.ResumeFromID == "" && st.opts.CredentialConfig != nil && len(st.opts.CredentialConfig.Entries) > 0 {
		st.opts.Logger("Setting up configured credentials...")
		copied, err := setupCredentials(st.result.Manager, st.result.HomeDir, st.opts.CredentialConfig.Entries, st.opts.Logger)
		if err != nil {
			st.opts.Logger(fmt.Sprintf("Warning: Failed to setup credentials: %v", err))
		}
		st.copiedCredentials = copied
	}
	return nil, nil
}

// 12 / 13 Inject the sandbox context file (~/SANDBOX_CONTEXT.md) and, for tools
// that support it, the native auto-context file (e.g. Claude's ~/.claude/CLAUDE.md).
func (st *setupState) phaseInjectContext(_ context.Context) (Teardown, error) {
	// Runs for both new and resumed sessions so dynamic info stays current.
	// The context files state whether Docker works, from the applied config.
	st.awaitApplied()
	// The leftover-file check, the copy record and the tmux probe ride along
	// first, so a later failing op can't cut them short. The check looks only
	// at files not copied this launch, so it doesn't see this launch's record.
	var ops []guestOp
	if op, ok := st.planLeftoverCheck(); ok {
		ops = append(ops, op)
	}
	if op, ok := recordCopiesOp(append(append([]CredentialEntry{}, st.copiedCredentials...), st.toolFiles...)); ok {
		ops = append(ops, op)
	}
	// Only a container that was already there can have the tool running.
	if st.skipLaunch {
		ops = append(ops, tmuxRunningOp(st.result))
	}
	ops = append(ops, st.pendingGuestOps...)
	out, ctxInfo := injectSandboxContextFiles(st.result, st.opts, ops...)
	st.leftovers.parse(out)
	st.result.ToolRunning = strings.Contains(out, tmuxRunningMarker)
	st.contextInfo = ctxInfo
	st.pendingGuestOps = nil
	reportTimezone(out, st.opts.Timezone, st.opts.Logger)
	reportMiseTrust(out, st.opts.Logger)
	return nil, nil
}

// tmuxRunningMarker is printed by tmuxRunningOp when the session exists.
const tmuxRunningMarker = "coi:tmux-running"

// tmuxRunningOp checks, as root, whether the tool's tmux session exists, via
// the socket of the user the tool runs as (tmux's default /tmp/tmux-<uid>), so
// the shell knows before it reports the grants whether the launch attaches to
// a running tool. Always succeeds, so it can't fail the batch.
func tmuxRunningOp(result *SetupResult) guestOp {
	uid := container.CodeUID
	if result.RunAsRoot {
		uid = 0
	}
	return guestCmd(fmt.Sprintf("if tmux -S /tmp/tmux-%d/default has-session -t %s 2>/dev/null; then echo %s; fi",
		uid, shellEscape(TmuxSessionName(result.ContainerName)), tmuxRunningMarker))
}
