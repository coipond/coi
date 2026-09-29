package tool

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// CodexTool implements Tool for OpenAI Codex CLI (https://developers.openai.com/codex/cli)
type CodexTool struct {
	permissionMode  string // "bypass" (default) or "interactive"
	model           string // codex model, delivered as -m (e.g. "gpt-5-codex") — empty means unset (codex's own default)
	reasoningEffort string // "minimal", "low", "medium", "high" — delivered as -c model_reasoning_effort=<v>; empty means unset
}

// NewCodex creates a new codex tool instance
func NewCodex() Tool { return &CodexTool{} }

func (c *CodexTool) Name() string { return "codex" }

func (c *CodexTool) Binary() string { return "codex" }

// ConfigDirName returns the config directory for codex (~/.codex, aka CODEX_HOME).
func (c *CodexTool) ConfigDirName() string { return mustBundle("codex").ConfigDir }

func (c *CodexTool) SessionsDirName() string { return "sessions-codex" }

// rolloutSessionFile matches codex session files
// (sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl) and captures the UUID.
var rolloutSessionFile = regexp.MustCompile(`^rollout-.*-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.jsonl$`)

// codexSafeFlagValue is the set of values accepted for codex launch knobs.
// BuildCommand's argv is joined into a shell command string by the CLI layer
// (and nested inside tmux quoting), and the [tool] config section is mergeable
// from an untrusted project .coi/config.toml — so flag values MUST be single
// shell-safe tokens. Anything else is rejected at the setter (and loudly, with
// an error, by ValidateCodexFlagValue at the CLI wiring layer) rather than
// quoted, because no legitimate codex model or reasoning-effort value contains
// shell metacharacters or whitespace.
var codexSafeFlagValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)

// ValidateCodexFlagValue returns an error when a [tool.codex] launch value
// (model, reasoning_effort) is not a single shell-safe token. Empty is valid
// (knob unset). Shared by the CLI wiring (loud failure at launch) and the
// setters below (fail-closed even if a future caller skips validation).
func ValidateCodexFlagValue(key, value string) error {
	if value == "" || codexSafeFlagValue.MatchString(value) {
		return nil
	}
	return fmt.Errorf("[tool.codex] %s %q must be a single token of letters, digits, or ._:/@- (shell metacharacters and whitespace are not allowed in launch flags)", key, value)
}

// BuildCommand builds the codex launch command. Every codex flag coi relies on
// lives in this one function so upstream flag drift has a single fix site.
//
// In bypass mode (default) coi passes --dangerously-bypass-approvals-and-sandbox:
// the Incus container is the sandbox, codex's own Landlock sandbox may not work
// nested inside it, and the flag also skips the first-run folder-trust prompt.
// In interactive mode codex keeps its approval prompts with a writable workspace.
//
// The Coi sessionID is unused — codex has no flag to set a session ID on a fresh
// launch (sessions get a rollout UUID internally); Coi UUIDs are metadata-only,
// as with pi. On resume, `codex resume <uuid>` pins the session discovered by
// DiscoverSessionID, falling back to `codex resume --last` when discovery fails.
// The resume subcommand is assumed to accept the same mode/model flags as the
// root command; if upstream ever drops that, remove the flags from the resume
// path — the host-seeded ~/.codex/config.toml still governs defaults.
func (c *CodexTool) BuildCommand(sessionID string, resume bool, resumeSessionID string) []string {
	cmd := []string{"codex"}

	if resume {
		cmd = append(cmd, "resume")
		if resumeSessionID != "" {
			cmd = append(cmd, resumeSessionID)
		} else {
			cmd = append(cmd, "--last")
		}
	}

	if c.permissionMode == "interactive" {
		cmd = append(cmd, "-s", "workspace-write", "-a", "on-request")
	} else {
		cmd = append(cmd, "--dangerously-bypass-approvals-and-sandbox")
	}

	// Flag values are guaranteed single shell-safe tokens: the setters drop
	// anything that fails ValidateCodexFlagValue (and the CLI wiring rejects
	// such values with an error first). buildCLICommand joins argv with
	// spaces into a shell command string, so this invariant is load-bearing.
	if c.model != "" {
		cmd = append(cmd, "-m", c.model)
	}
	if c.reasoningEffort != "" {
		cmd = append(cmd, "-c", "model_reasoning_effort="+c.reasoningEffort)
	}

	return cmd
}

// BuildCommandLaunch implements ToolWithPrompt for Codex. Codex takes the
// initial prompt as a trailing positional argument, on both a fresh launch
// (`codex … [PROMPT]`) and a resume: `codex resume [OPTIONS] [SESSION_ID]
// [PROMPT]` and `codex resume [OPTIONS] --last [PROMPT]` both accept the prompt
// positional (verified against codex-cli 0.152.0, the version coi's installer
// pulls — #755), so appending it after BuildCommand's resume rendering is
// correct and the prompt is not dropped. codex is unpinned (latest at image
// build), so install_codex in internal/image/build.sh smoke-checks that `codex
// resume --help` still advertises the [PROMPT] positional and fails the build if
// a future release drops it. Codex has no first-class system-prompt
// flag (instructions live in AGENTS.md), so a SystemPromptFile is rejected
// rather than silently dropped. The prompt is passed as `"$(cat <file>)"` so
// arbitrary content stays in the file.
func (c *CodexTool) BuildCommandLaunch(spec LaunchSpec) ([]string, error) {
	if spec.SystemPromptFile != "" {
		return nil, fmt.Errorf("codex has no system-prompt flag; use AGENTS.md instead of --system-prompt-file")
	}
	cmd := c.BuildCommand(spec.SessionID, spec.Resume, spec.ResumeSessionID)
	if spec.PromptFile != "" {
		cmd = append(cmd, catSubst(spec.PromptFile))
	}
	return cmd, nil
}

// DiscoverSessionID finds the newest codex session UUID in the saved state dir.
// Codex stores sessions as sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl,
// so the lexicographically greatest matching path is the newest session
// (zero-padded date dirs + ISO timestamps sort chronologically). Deliberately
// NOT mtime-based: the saved state is round-tripped through `incus file pull`,
// which does not preserve mtimes — after a save every file carries its
// pull-time mtime in transfer order, so mtimes carry no session-recency signal.
// Returns "" when nothing is found — BuildCommand then falls back to
// `codex resume --last`, which is independent of the sessions layout.
func (c *CodexTool) DiscoverSessionID(stateDir string) string {
	sessionsDir := filepath.Join(stateDir, "sessions")

	var newestPath, newestID string
	_ = filepath.WalkDir(sessionsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil // skip unreadable entries; discovery is best-effort
		}
		m := rolloutSessionFile.FindStringSubmatch(d.Name())
		if m != nil && path > newestPath {
			newestPath, newestID = path, m[1]
		}
		return nil
	})

	return newestID
}

// GetSandboxSettings returns no settings for codex. Unlike claude/opencode,
// codex's config file (~/.codex/config.toml) is TOML while coi's settings
// injection (mergeJSONSettings) is JSON-only, so coi never rewrites it — the
// host file is seeded verbatim and everything coi controls (permission mode,
// model, reasoning effort) is delivered as launch flags in BuildCommand.
func (c *CodexTool) GetSandboxSettings() map[string]interface{} {
	return map[string]interface{}{}
}

// SetPermissionMode sets the permission mode for codex.
// Valid values: "bypass" (default) or "interactive" (human-in-the-loop).
// Consumed by BuildCommand (not GetSandboxSettings — see there for why).
func (c *CodexTool) SetPermissionMode(mode string) {
	c.permissionMode = mode
}

// SetModel implements ToolWithModel. Delivered as `-m <model>`;
// when unset codex uses its own default. Configured via [tool.codex] model.
// A value that is not a shell-safe token is dropped (fail-closed): the CLI
// wiring rejects such values with an error before this setter runs, so the
// drop only matters if a future caller skips ValidateCodexFlagValue.
func (c *CodexTool) SetModel(model string) {
	if ValidateCodexFlagValue("model", model) != nil {
		return
	}
	c.model = model
}

// SetEffortLevel implements ToolWithEffortLevel. For codex this maps to
// `model_reasoning_effort` ("minimal", "low", "medium", "high") — codex's
// scale, not Claude's effort levels. Configured via [tool.codex] reasoning_effort.
// Non-shell-safe values are dropped, as in SetModel.
func (c *CodexTool) SetEffortLevel(level string) {
	if ValidateCodexFlagValue("reasoning_effort", level) != nil {
		return
	}
	c.reasoningEffort = level
}

// EssentialConfigFiles implements ToolWithConfigDirFiles.
func (c *CodexTool) EssentialConfigFiles() []string {
	return mustBundle("codex").Files
}

// SandboxSettingsFileName implements ToolWithConfigDirFiles.
// Empty: codex has no JSON settings file to inject into (see GetSandboxSettings).
func (c *CodexTool) SandboxSettingsFileName() string { return mustBundle("codex").SandboxSettingsFile }

// StateConfigFileName implements ToolWithConfigDirFiles.
// Codex has no sibling state file (everything lives inside ~/.codex).
func (c *CodexTool) StateConfigFileName() string { return mustBundle("codex").StateFile }

// AlwaysSetupConfig implements ToolWithConfigDirFiles.
// Codex needs credentials from ~/.codex (auth.json), so skip setup when the
// host dir is missing — auto-context injection runs independently either way.
func (c *CodexTool) AlwaysSetupConfig() bool { return mustBundle("codex").AlwaysSetup }

// AutoContextFile implements ToolWithAutoContextFile.
// Codex reads ~/.codex/AGENTS.md as global instructions; coi injects its
// managed sandbox-context block there (container-side), never into the
// workspace AGENTS.md, which lives on the host bind-mount.
func (c *CodexTool) AutoContextFile() string { return mustBundle("codex").AutoContextFile }
