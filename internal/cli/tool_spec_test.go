package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/coipond/coi/internal/container"
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

// `coi run --prompt` on opencode (Print) uses `opencode run <prompt-file`, while
// `coi tool spec` (no Print) keeps the out-of-band prompt.
func TestBuildToolLaunchArgv_OpencodePrint(t *testing.T) {
	argv, prompt, err := buildToolLaunchArgv(tool.NewOpencode(), tool.LaunchSpec{
		SessionID: "sid", PromptFile: "/run/p", Print: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); got != `opencode run --auto </run/p` {
		t.Errorf("opencode print launch = %q", got)
	}
	if prompt != "" {
		t.Errorf("opencode run embeds the prompt; no out-of-band prompt expected, got %q", prompt)
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

// bashExecManager runs container execs in a local bash, so commands act on a
// temp dir standing in for the container home.
type bashExecManager struct {
	container.ContainerManager
}

func (bashExecManager) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	return string(out), err
}

// TestEnsureContainerRunsDir_ChownsCreatedDirs: a container without ~/.coi
// must not be left with a root-owned ~/.coi; an existing ~/.coi keeps its
// owner. The owner is the resolved run uid, not container.CodeUID.
func TestEnsureContainerRunsDir_ChownsCreatedDirs(t *testing.T) {
	const uid = 1234
	for _, tc := range []struct {
		name      string
		coiExists bool
	}{
		{"missing ~/.coi", false},
		{"existing ~/.coi", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			coiDir := filepath.Join(home, ".coi")
			if tc.coiExists {
				if err := os.Mkdir(coiDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			bin := t.TempDir()
			logPath := filepath.Join(bin, "chown.log")
			script := "#!/bin/sh\necho \"$*\" >> " + shellQuote(logPath) + "\n"
			if err := os.WriteFile(filepath.Join(bin, "chown"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

			runsDir, err := ensureContainerRunsDir(bashExecManager{}, home, uid)
			if err != nil {
				t.Fatalf("ensureContainerRunsDir: %v", err)
			}
			if want := filepath.Join(coiDir, "runs"); runsDir != want {
				t.Errorf("runsDir = %q, want %q", runsDir, want)
			}
			if info, err := os.Stat(runsDir); err != nil || !info.IsDir() {
				t.Fatalf("runs dir not created: %v", err)
			}

			want := fmt.Sprintf("%d:%d %s\n", uid, uid, runsDir)
			if !tc.coiExists {
				want = fmt.Sprintf("%d:%d %s\n", uid, uid, coiDir) + want
			}
			log, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("chown never ran: %v", err)
			}
			if string(log) != want {
				t.Errorf("chown calls = %q, want %q", log, want)
			}
		})
	}
}

// TestEnsureContainerRunsDir_ConcurrentFirstCalls: parallel first calls on a
// container without ~/.coi (one `coi tool spec` per session) must all
// succeed, though only one of them creates ~/.coi.
func TestEnsureContainerRunsDir_ConcurrentFirstCalls(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "chown"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	for round := 0; round < 50; round++ {
		home := t.TempDir()
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := ensureContainerRunsDir(bashExecManager{}, home, 1234); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: ensureContainerRunsDir: %v", round, err)
		}
	}
}
