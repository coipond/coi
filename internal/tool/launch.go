package tool

// LaunchSpec carries the session-specific dynamics an external orchestrator
// supplies when it asks coi for a tool's launch spec (`coi tool spec`, #751).
// The tool owns the translation into its CLI; the caller owns only these
// dynamics.
//
// PromptFile and SystemPromptFile are IN-CONTAINER paths to files holding the
// initial user prompt and an optional system prompt. Passing files (not the
// text) keeps arbitrary prompt content off the launch command line — the tool
// references the prompt via a `"$(cat <file>)"` substitution the container
// shell expands when the orchestrator runs the command, so prompts with
// quotes/newlines can't corrupt it.
type LaunchSpec struct {
	SessionID        string
	Resume           bool
	ResumeSessionID  string
	PromptFile       string // in-container path; empty = no initial prompt
	SystemPromptFile string // in-container path; empty = no system prompt
	// Print requests a headless "run to completion and exit" launch (fire and
	// forget) rather than an interactive session — for Claude, this adds `-p`
	// (`--print`) so the agent runs the prompt, prints its response, and exits
	// with a status code, which is what `coi run --prompt` relies on for cron
	// automation (#701). Tools that can't run headlessly ignore it (the caller
	// gates on tool support before building).
	Print bool
}

// ToolWithPrompt is implemented by tools that can embed an initial prompt (and
// optionally a system prompt) in their launch command. Tools that don't
// implement it have no way to carry the prompt in argv; `coi tool spec` fails
// loudly for them when a prompt is requested so the orchestrator delivers it
// out-of-band (e.g. `coi tmux send`) rather than silently dropping it.
type ToolWithPrompt interface {
	Tool
	// BuildCommandLaunch returns the full argv for a launch, embedding the
	// prompt/system-prompt per the tool's CLI. It returns an error when the
	// spec requests something the tool can't express (e.g. a system prompt on a
	// tool without one) so the caller fails loudly instead of dropping it.
	BuildCommandLaunch(spec LaunchSpec) ([]string, error)
}

// ToolWithHeadlessPrompt is implemented by tools whose headless (print-mode)
// launch is a separate CLI form that carries the prompt itself, even when
// their interactive launch can't (e.g. `opencode run <prompt-file`). It backs
// `coi run --prompt`; `coi tool spec` keeps using ToolWithPrompt.
type ToolWithHeadlessPrompt interface {
	Tool
	// BuildHeadlessCommand returns the full command for a run-to-completion
	// launch of spec, run through a shell (it may redirect stdin). It errors
	// on what the tool can't express.
	BuildHeadlessCommand(spec LaunchSpec) ([]string, error)
}

// catSubst returns a `"$(cat <path>)"` token whose value the container shell
// expands to the file's contents at launch. path is a coi-controlled file
// (~/.coi/runs/<id>.*) with no shell metacharacters, so the arbitrary prompt
// text lives only in the file, never on the command line. Valid only where the
// command runs through a shell (e.g. the orchestrator's `bash -c "<command>"`),
// which expands the substitution.
func catSubst(path string) string {
	return `"$(cat ` + path + `)"`
}
