package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/tool"
)

func TestBuildToolSpecCommand_ClaudeNative(t *testing.T) {
	argv, prompt, err := buildToolSpecCommand(tool.NewClaude(), tool.LaunchSpec{
		SessionID: "sid", PromptFile: "/run/p", SystemPromptFile: "/run/s",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--session-id sid") {
		t.Errorf("missing --session-id: %q", joined)
	}
	// System prompt embedded via --append-system-prompt "$(cat …)".
	if !strings.Contains(joined, `--append-system-prompt "$(cat /run/s)"`) {
		t.Errorf("missing system prompt: %q", joined)
	}
	// Initial prompt is the trailing positional, staged via "$(cat …)".
	if argv[len(argv)-1] != `"$(cat /run/p)"` {
		t.Errorf("prompt must be trailing cat-subst: %q", joined)
	}
	// Claude embeds the prompt, so there's no out-of-band prompt.
	if prompt != "" {
		t.Errorf("embedding tool must not surface an out-of-band prompt, got %q", prompt)
	}
}

func TestBuildToolSpecCommand_DummyOverride(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")
	argv, _, err := buildToolSpecCommand(tool.NewClaude(), tool.LaunchSpec{SessionID: "sid"})
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 || argv[0] != "dummy" {
		t.Errorf("dummy override should replace the binary, got: %v", argv)
	}
}

// buildToolLaunchArgv (used by `coi run --prompt`) must NOT apply the dummy
// override — the dummy image installs the stub as `claude`, so rewriting argv[0]
// to "dummy" would exec a nonexistent command (#701 review).
func TestBuildToolLaunchArgv_NoDummyOverride(t *testing.T) {
	t.Setenv("COI_USE_DUMMY", "1")
	argv, _, err := buildToolLaunchArgv(tool.NewClaude(), tool.LaunchSpec{SessionID: "sid", Print: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 || argv[0] != "claude" {
		t.Errorf("prompt-mode launch must keep the real binary name, got: %v", argv)
	}
}

func TestBuildToolSpecCommand_CodexPrompt(t *testing.T) {
	// Codex embeds the prompt as a trailing positional and has no system prompt.
	argv, prompt, err := buildToolSpecCommand(tool.NewCodex(), tool.LaunchSpec{
		SessionID: "sid", PromptFile: "/run/p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if argv[len(argv)-1] != `"$(cat /run/p)"` {
		t.Errorf("codex prompt must be trailing cat-subst: %v", argv)
	}
	if prompt != "" {
		t.Errorf("codex embeds the prompt; no out-of-band prompt expected, got %q", prompt)
	}
	if _, _, err := buildToolSpecCommand(tool.NewCodex(), tool.LaunchSpec{
		SessionID: "sid", SystemPromptFile: "/run/s",
	}); err == nil {
		t.Error("codex must reject a system prompt (no such flag)")
	}
}

func TestBuildToolSpecCommand_ToolWithoutPromptOutOfBand(t *testing.T) {
	// opencode doesn't implement ToolWithPrompt: the prompt can't ride in argv,
	// so it comes back as the out-of-band prompt (the staged file path), not in
	// the command and not dropped.
	argv, prompt, err := buildToolSpecCommand(tool.NewOpencode(), tool.LaunchSpec{
		SessionID: "sid", PromptFile: "/run/p",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) == 0 {
		t.Error("expected a base command for opencode")
	}
	if strings.Contains(strings.Join(argv, " "), "$(cat") {
		t.Errorf("opencode must not embed the prompt in argv: %v", argv)
	}
	if prompt != "/run/p" {
		t.Errorf("expected out-of-band prompt path /run/p, got %q", prompt)
	}
	// A system prompt on a tool without one is still rejected loudly.
	if _, _, err := buildToolSpecCommand(tool.NewOpencode(), tool.LaunchSpec{
		SessionID: "sid", SystemPromptFile: "/run/s",
	}); err == nil {
		t.Error("a system prompt on a tool without support must error")
	}
	// With no prompt, the base command is fine and there's nothing out-of-band.
	argv, prompt, err = buildToolSpecCommand(tool.NewOpencode(), tool.LaunchSpec{SessionID: "sid"})
	if err != nil {
		t.Fatalf("no-prompt launch for opencode should succeed: %v", err)
	}
	if len(argv) == 0 || prompt != "" {
		t.Errorf("no-prompt opencode: want base cmd and empty prompt, got argv=%v prompt=%q", argv, prompt)
	}
}

func TestBuildToolSpecCommand_ResumeIDClaude(t *testing.T) {
	// --resume-id renders as claude's `--resume <id>`, replacing --session-id.
	argv, _, err := buildToolSpecCommand(tool.NewClaude(), tool.LaunchSpec{
		SessionID: "new-run", Resume: true, ResumeSessionID: "sess-abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--resume sess-abc") {
		t.Errorf("claude resume-id must render `--resume <id>`: %q", joined)
	}
	if strings.Contains(joined, "--session-id") {
		t.Errorf("a resume must not also pass --session-id: %q", joined)
	}
}

func TestBuildToolSpecCommand_ResumeIDCodex(t *testing.T) {
	// --resume-id renders as codex's `resume <id>`.
	argv, _, err := buildToolSpecCommand(tool.NewCodex(), tool.LaunchSpec{
		SessionID: "new-run", Resume: true, ResumeSessionID: "sess-abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(argv, " "); !strings.Contains(joined, "resume sess-abc") {
		t.Errorf("codex resume-id must render `resume <id>`: %q", joined)
	}
}

func TestBuildToolSpecCommand_ResumeLatest(t *testing.T) {
	// --resume (no id): claude renders `--continue` (headless "resume most recent" - bare
	// `--resume` would open the interactive picker and hang, #754), codex `resume --last`.
	argvC, _, err := buildToolSpecCommand(tool.NewClaude(), tool.LaunchSpec{SessionID: "n", Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	if jc := strings.Join(argvC, " "); !strings.Contains(jc, "--continue") || strings.Contains(jc, "--session-id") {
		t.Errorf("claude resume-latest: want --continue and no --session-id, got %q", jc)
	}
	for _, a := range argvC {
		if a == "--resume" {
			t.Errorf("claude resume-latest launch must not emit bare --resume (picker): %v", argvC)
		}
	}
	argvX, _, err := buildToolSpecCommand(tool.NewCodex(), tool.LaunchSpec{SessionID: "n", Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	if jx := strings.Join(argvX, " "); !strings.Contains(jx, "resume --last") {
		t.Errorf("codex resume-latest: want `resume --last`, got %q", jx)
	}
}

func TestCountTrue(t *testing.T) {
	cases := []struct {
		in   []bool
		want int
	}{
		{[]bool{}, 0},
		{[]bool{false, false}, 0},
		{[]bool{true, false, false}, 1},
		{[]bool{true, true, false}, 2},
		{[]bool{true, true, true}, 3},
	}
	for _, c := range cases {
		if got := countTrue(c.in...); got != c.want {
			t.Errorf("countTrue(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
