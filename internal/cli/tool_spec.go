package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
	"github.com/coipond/coi/internal/tool"
	"github.com/spf13/cobra"
)

// continueSelfSentinel is the value a bare `--continue` (no `=id`) carries via
// the flag's NoOptDefVal, meaning "resume the --session-id session if it has
// prior state". A distinct sentinel keeps it apart from an explicit
// `--continue=<id>` and from the flag being absent. The `@` prefix can't collide
// with a real coi session id (those are workspace-derived slugs / UUIDs).
const continueSelfSentinel = "@self"

var (
	toolSpecContainer        string
	toolSpecSessionID        string
	toolSpecPromptFile       string
	toolSpecSystemPromptFile string
	toolSpecContinue         string
	toolSpecResumeID         string
	toolSpecResumeLatest     bool
	toolSpecJSON             bool
)

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "Work with the profile's configured AI tool",
	Long: `Inspect the profile's configured AI coding tool without launching an
interactive session.`,
}

var toolSpecCmd = &cobra.Command{
	Use:   "spec",
	Short: "Print a tool's launch command + env for an orchestrator to run (#751)",
	Long: `Print, without executing, the exact command and tool-derived environment for
launching the profile's tool inside an existing container. An external
orchestrator then runs that command through its own container exec + tmux,
owning the terminal, streaming, input, and lifecycle.

coi builds the command from the profile's tool via the tool.Tool abstraction
(session id, resume, model, permission), so it is correct for any supported
tool (claude/codex/…). The prompt (and optional system prompt) are staged into
the container as files and referenced via "$(cat <file>)", keeping arbitrary
prompt content off the command line. Only tool-derived env (model/effort) is
emitted; secrets and auth stay with the caller, which adds its own --env when it
execs.

Tools that can't embed the initial prompt in their launch command (e.g.
opencode) instead get a "prompt" field: the in-container path to the staged
prompt file, for the orchestrator to deliver out-of-band after launch (e.g.
tmux load-buffer + paste-buffer).

Resume strategies (at most one): --continue[=<id>] discovers coi's host-side
session store and resumes if found, else starts fresh; --resume-id <id> asserts
an exact session id verbatim (no discovery) for an orchestrator that owns
session state itself; --resume-latest resumes the most recent conversation with
no id. (There is no bare --resume here — it is the global session-resume flag and
is rejected on this command; use --resume-latest or --resume-id.)

  coi tool spec --container <ctr> --session-id <id> --prompt-file <host> \
      [--system-prompt-file <host>] [--continue[=<id>] | --resume-id <id> | --resume-latest] --json`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return app.toolSpecCommand(cmd)
	},
}

func init() {
	toolSpecCmd.Flags().StringVar(&toolSpecContainer, "container", "", "Existing container to build the launch spec for (required)")
	toolSpecCmd.Flags().StringVar(&toolSpecSessionID, "session-id", "", "Session id for the launch (required; letters, digits, '.', '_', '-', start alphanumeric, max 64)")
	toolSpecCmd.Flags().StringVar(&toolSpecPromptFile, "prompt-file", "", "Host file whose contents are staged as the tool's initial prompt")
	toolSpecCmd.Flags().StringVar(&toolSpecSystemPromptFile, "system-prompt-file", "", "Host file whose contents are staged as the tool's system prompt (tools that support one)")
	toolSpecCmd.Flags().StringVar(&toolSpecContinue, "continue", "", "Resume-or-fresh: resume a session (default: --session-id) if prior state exists, else start fresh. Optional value: --continue=<id>")
	toolSpecCmd.Flags().Lookup("continue").NoOptDefVal = continueSelfSentinel
	toolSpecCmd.Flags().StringVar(&toolSpecResumeID, "resume-id", "", "Orchestrator-owned resume: build a resume command for this exact session id, verbatim (no host-side discovery). Mutually exclusive with --continue/--resume-latest")
	toolSpecCmd.Flags().BoolVar(&toolSpecResumeLatest, "resume-latest", false, "Resume the latest conversation with no id. Mutually exclusive with --continue/--resume-id")
	toolSpecCmd.Flags().BoolVar(&toolSpecJSON, "json", false, "Print the spec as JSON (the machine-readable form orchestrators consume)")

	toolCmd.AddCommand(toolSpecCmd)
}

// toolSpecResult is the machine-readable spec a `coi tool spec` prints: the
// exact argv to run in the container and the tool-derived env (model/effort)
// only. Secrets/auth are deliberately absent — the caller adds those itself.
//
// Prompt is set only for tools that can't embed the initial prompt in their
// launch command (they don't implement ToolWithPrompt, e.g. opencode). It is the
// in-container path to the staged prompt file — the same file embedding tools
// reference via "$(cat …)" in Command — so the orchestrator delivers it
// out-of-band after launch (e.g. `tmux load-buffer <prompt>` + `paste-buffer`,
// which is file-based and safe for arbitrary content). Empty when the prompt is
// embedded in Command, or when no prompt was given.
type toolSpecResult struct {
	Command []string          `json:"command"`
	Env     map[string]string `json:"env"`
	Prompt  string            `json:"prompt,omitempty"`
}

// toolSpecCommand builds and prints the launch spec for the profile's tool
// against an existing container (#751). It stages the prompt(s) into the
// container and reuses the same tool.Tool / ToolWithPrompt / ToolWithContainerEnv
// methods the interactive launch uses, but never executes anything — the
// orchestrator owns execution.
func (a *App) toolSpecCommand(cmd *cobra.Command) error {
	if toolSpecContainer == "" {
		return &ExitCodeError{Code: 2, Message: "--container is required"}
	}
	if toolSpecSessionID == "" {
		return &ExitCodeError{Code: 2, Message: "--session-id is required"}
	}
	// The session id is a caller-supplied value that becomes a filename
	// component and is joined into the shell-run launch command (referenced via
	// "$(cat …/<id>.prompt)"); reject anything that isn't a safe token so it
	// can't break or inject the command.
	if err := session.ValidateSessionID(toolSpecSessionID); err != nil {
		return &ExitCodeError{Code: 2, Message: err.Error()}
	}

	// `coi tool spec` has no bare --resume: that name is the global session-resume
	// flag (resume a coi session by id), which is inherited here but this handler
	// never reads — so a `--resume`/`--resume=<id>` would be silently ignored
	// (fresh launch). Reject it loudly and point at the two real strategies.
	if cmd.Flags().Changed("resume") {
		return &ExitCodeError{Code: 2, Message: "coi tool spec has no --resume; use --resume-latest (resume the most recent conversation) or --resume-id <id> (resume a specific session)"}
	}

	// Resolve and validate the resume strategy up front — before any container or
	// filesystem access — so a bad combination or unsafe id is rejected early.
	// At most one of --continue / --resume-id / --resume-latest may be set; they
	// express conflicting contracts (discover-or-fresh vs assert-this-id vs
	// resume-latest).
	continueSet := cmd.Flags().Changed("continue")
	resumeIDSet := cmd.Flags().Changed("resume-id")
	if countTrue(continueSet, resumeIDSet, toolSpecResumeLatest) > 1 {
		return &ExitCodeError{Code: 2, Message: "--continue, --resume-id, and --resume-latest are mutually exclusive"}
	}

	// discoverResumeID is the --continue target to look up (discover-or-fresh);
	// empty when --continue isn't used. --resume-id / --resume don't discover.
	discoverResumeID := ""
	if continueSet {
		discoverResumeID = toolSpecContinue
		if discoverResumeID == continueSelfSentinel || discoverResumeID == "" {
			discoverResumeID = toolSpecSessionID
		}
		if err := session.ValidateSessionID(discoverResumeID); err != nil {
			return &ExitCodeError{Code: 2, Message: err.Error()}
		}
	}
	if resumeIDSet {
		// Orchestrator-owned resume: the caller asserts the id (it's
		// shell-interpolated / a filename component), so validate it — but do NOT
		// discover or otherwise probe for it.
		if err := session.ValidateSessionID(toolSpecResumeID); err != nil {
			return &ExitCodeError{Code: 2, Message: err.Error()}
		}
	}

	t, err := getConfiguredTool(a.cfg)
	if err != nil {
		return err
	}

	mgr := container.NewManager(toolSpecContainer)
	if running, err := mgr.Running(); err != nil {
		return fmt.Errorf("failed to check container status: %w", err)
	} else if !running {
		return fmt.Errorf("container %s is not running", toolSpecContainer)
	}

	uid, homeDir, err := toolSpecUserHome(mgr)
	if err != nil {
		return err
	}
	runsDir, err := ensureContainerRunsDir(mgr, homeDir, uid)
	if err != nil {
		return err
	}

	// Stage prompt / system prompt as in-container files so their (arbitrary)
	// content never touches the launch command line.
	promptPath, err := a.stageSpecFile(mgr, toolSpecPromptFile, filepath.Join(runsDir, toolSpecSessionID+".prompt"), uid)
	if err != nil {
		return err
	}
	systemPromptPath, err := a.stageSpecFile(mgr, toolSpecSystemPromptFile, filepath.Join(runsDir, toolSpecSessionID+".sys"), uid)
	if err != nil {
		return err
	}

	spec := tool.LaunchSpec{
		SessionID:        toolSpecSessionID,
		PromptFile:       promptPath,
		SystemPromptFile: systemPromptPath,
	}

	// Apply the resume strategy resolved above.
	switch {
	case resumeIDSet:
		// Assert the caller's id verbatim — no host-side discovery. Correct when
		// the orchestrator owns session state (it restored the tool's state dir
		// into the container and knows the id).
		spec.Resume = true
		spec.ResumeSessionID = toolSpecResumeID
	case toolSpecResumeLatest:
		// Resume-latest with no id: latest-only tools (pi/omp) resume the last
		// conversation; claude/codex render `--continue` / `resume --last`.
		spec.Resume = true
	case discoverResumeID != "":
		// --continue: discover-or-fresh against coi's host-side session store.
		hostHome, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		sessionsDir := session.GetSessionsDir(filepath.Join(hostHome, ".coi"), t)
		if prior := discoverResumeSessionID(t, sessionsDir, discoverResumeID); prior != "" {
			spec.Resume = true
			spec.ResumeSessionID = prior
		}
	}

	argv, outOfBandPrompt, err := buildToolSpecCommand(t, spec)
	if err != nil {
		return err
	}

	// Env: tool-derived only (model/effort), computed against the container's
	// ACTUAL workspace mount — pi/omp/opencode derive session-dir/XDG paths from
	// it, so a container that mounts the workspace somewhere other than
	// /workspace (preserve_workspace_path / worktree) must get the real path,
	// not a hardcoded default. Secrets/auth stay with the caller.
	env := map[string]string{}
	mergeToolEnv(env, t, mgr.GetWorkspacePath())

	return emitToolSpec(toolSpecResult{Command: argv, Env: env, Prompt: outOfBandPrompt})
}

// toolSpecUserHome resolves the uid the run files are owned by and the home dir
// the runs directory lives under, for an existing container. It reuses the
// canonical session.ResolveCodeUID, which distinguishes a genuinely-absent code
// user (→ root) from an infra probe failure (→ error): a transient probe error
// therefore surfaces loudly instead of silently misrouting staging to /root
// (the #588 failure mode) for a container that actually has the code user.
func toolSpecUserHome(mgr container.ContainerManager) (uid int, home string, err error) {
	uid, err = session.ResolveCodeUID(mgr, container.CodeUser)
	if err != nil {
		return 0, "", fmt.Errorf("failed to resolve container code user: %w", err)
	}
	if uid == 0 {
		return 0, "/root", nil // no code user: the tool runs as root
	}
	return uid, "/home/" + container.CodeUser, nil
}

// ensureContainerRunsDir creates ~/.coi/runs in the container owned by the run
// user (uid) and returns its path. Shared by `coi tool spec` and the headless
// `coi run --prompt` path so the runs-dir convention and ownership stay in one
// place.
func ensureContainerRunsDir(mgr container.ContainerManager, homeDir string, uid int) (string, error) {
	runsDir := filepath.Join(homeDir, ".coi", "runs")
	if _, err := mgr.ExecCommand(fmt.Sprintf("mkdir -p %s && chown %d:%d %s",
		shellQuote(runsDir), uid, uid, shellQuote(runsDir)),
		container.ExecCommandOptions{Capture: true}); err != nil {
		return "", fmt.Errorf("failed to create runs dir: %w", err)
	}
	return runsDir, nil
}

// stageSpecFile copies a host prompt file into the container at destPath and
// returns destPath; an empty hostPath returns "" (no file, no path emitted).
func (a *App) stageSpecFile(mgr container.ContainerManager, hostPath, destPath string, uid int) (string, error) {
	if hostPath == "" {
		return "", nil
	}
	content, err := os.ReadFile(hostPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %q: %w", hostPath, err)
	}
	if err := mgr.CreateFileWithOwner(destPath, string(content), uid, uid, "0600"); err != nil {
		return "", fmt.Errorf("failed to stage prompt file in container: %w", err)
	}
	return destPath, nil
}

// buildToolLaunchArgv returns the launch argv for the tool and, when the tool
// can't embed the prompt in argv, the in-container prompt-file path to deliver
// out-of-band (the toolSpecResult.Prompt field). Tools implementing
// ToolWithPrompt (claude/codex) embed the prompt (and system prompt) directly;
// tools without it (opencode) get the base command plus outOfBandPrompt so the
// prompt is surfaced rather than silently dropped. A system prompt on a tool
// without one is still rejected loudly (those tools have no such concept).
//
// It does NOT apply the COI_USE_DUMMY test override: `coi run --prompt` runs the
// tool by its real binary name (the dummy test image installs the stub AS
// `claude`), so rewriting argv[0] to "dummy" would exec a nonexistent command.
// buildToolSpecCommand layers that override on for the orchestrator path.
func buildToolLaunchArgv(t tool.Tool, spec tool.LaunchSpec) (argv []string, outOfBandPrompt string, err error) {
	if twp, ok := t.(tool.ToolWithPrompt); ok {
		argv, err = twp.BuildCommandLaunch(spec)
		if err != nil {
			return nil, "", err
		}
	} else {
		if spec.SystemPromptFile != "" {
			return nil, "", fmt.Errorf("tool %q has no system-prompt support for a launch spec", t.Name())
		}
		argv = t.BuildCommand(spec.SessionID, spec.Resume, spec.ResumeSessionID)
		// The prompt can't ride in argv for this tool; hand its staged path back
		// so the orchestrator delivers it out-of-band after launch.
		outOfBandPrompt = spec.PromptFile
	}
	return argv, outOfBandPrompt, nil
}

// buildToolSpecCommand is buildToolLaunchArgv plus the COI_USE_DUMMY test
// override (argv[0] -> "dummy"), for the `coi tool spec` orchestrator path where
// the caller provides its own dummy binary. Mirrors buildCLICommand.
func buildToolSpecCommand(t tool.Tool, spec tool.LaunchSpec) (argv []string, outOfBandPrompt string, err error) {
	argv, outOfBandPrompt, err = buildToolLaunchArgv(t, spec)
	if err != nil {
		return nil, "", err
	}
	if os.Getenv("COI_USE_DUMMY") == "1" && len(argv) > 0 {
		argv[0] = "dummy"
	}
	return argv, outOfBandPrompt, nil
}

// emitToolSpec prints the spec: JSON on stdout with --json (the orchestrator
// form), otherwise a human-readable summary.
func emitToolSpec(res toolSpecResult) error {
	if toolSpecJSON {
		b, err := json.Marshal(res)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	fmt.Println("command:")
	for _, arg := range res.Command {
		fmt.Printf("  %s\n", arg)
	}
	if len(res.Env) > 0 {
		fmt.Println("env:")
		for _, k := range sortedEnvKeys(res.Env) {
			fmt.Printf("  %s=%s\n", k, res.Env[k])
		}
	}
	if res.Prompt != "" {
		fmt.Printf("prompt (deliver out-of-band): %s\n", res.Prompt)
	}
	return nil
}

// countTrue returns how many of the given booleans are true — used to enforce
// "at most one" among mutually exclusive flags.
func countTrue(bs ...bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// discoverResumeSessionID mirrors buildCLICommand's resume discovery: it looks
// up the tool's internal session id from saved state, returning "" when none
// exists (so resume degrades to a fresh start).
func discoverResumeSessionID(t tool.Tool, sessionsDir, resumeID string) string {
	var statePath string
	if configDir := t.ConfigDirName(); configDir != "" {
		statePath = filepath.Join(sessionsDir, resumeID, configDir)
	} else {
		statePath = filepath.Join(sessionsDir, resumeID)
	}
	return t.DiscoverSessionID(statePath)
}
