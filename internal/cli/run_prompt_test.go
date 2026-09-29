package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mensfeld/coi/internal/config"
	"github.com/spf13/cobra"
)

// newRunPromptCmd returns a cobra command with the prompt flags bound to the
// same package vars runCommand reads, and resets those vars, so each test starts
// clean. Flags are marked "changed" by ParseFlags, which is what
// resolvePromptMode checks.
func newRunPromptCmd(t *testing.T, args []string) *cobra.Command {
	t.Helper()
	runPrompt, runPromptFile, runPromptName = "", "", ""
	cmd := &cobra.Command{Use: "run"}
	cmd.Flags().StringVar(&runPrompt, "prompt", "", "")
	cmd.Flags().StringVar(&runPromptFile, "prompt-file", "", "")
	cmd.Flags().StringVar(&runPromptName, "prompt-name", "", "")
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags(%v): %v", args, err)
	}
	return cmd
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	var ece *ExitCodeError
	if !errors.As(err, &ece) {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
	return ece.Code
}

func TestResolvePromptMode_NoFlags(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, nil)
	s := &runState{}
	if err := a.resolvePromptMode(cmd, s, nil); err != nil {
		t.Fatalf("no prompt flags should be a no-op, got %v", err)
	}
	if s.promptMode {
		t.Error("promptMode should be false with no prompt flags")
	}
}

func TestResolvePromptMode_MutualExclusion(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt", "x", "--prompt-name", "y"})
	err := a.resolvePromptMode(cmd, &runState{}, nil)
	if code := exitCode(t, err); code != 2 {
		t.Errorf("mutual exclusion should exit 2, got %d", code)
	}
}

func TestResolvePromptMode_PositionalRejected(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt", "x"})
	err := a.resolvePromptMode(cmd, &runState{}, []string{"echo", "hi"})
	if code := exitCode(t, err); code != 2 {
		t.Errorf("prompt + positional should exit 2, got %d", code)
	}
}

func TestResolvePromptMode_EmptyPrompt(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt", "   "})
	err := a.resolvePromptMode(cmd, &runState{}, nil)
	if code := exitCode(t, err); code != 2 {
		t.Errorf("empty prompt should exit 2, got %d", code)
	}
}

func TestResolvePromptMode_InlineSuccess(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt", "do the thing"})
	s := &runState{}
	if err := a.resolvePromptMode(cmd, s, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.promptMode || s.promptText != "do the thing" || s.promptSessionID == "" {
		t.Errorf("bad state: %+v", s)
	}
	if s.promptTool == nil || s.promptTool.Name() != "claude" {
		t.Errorf("resolved tool should be stored on runState, got %v", s.promptTool)
	}
}

func TestResolvePromptMode_InteractivePermissionRejected(t *testing.T) {
	a := &App{cfg: &config.Config{Tool: config.ToolConfig{PermissionMode: "interactive"}}}
	cmd := newRunPromptCmd(t, []string{"--prompt", "do it"})
	err := a.resolvePromptMode(cmd, &runState{}, nil)
	if code := exitCode(t, err); code != 2 {
		t.Errorf("interactive permission mode should exit 2, got %d", code)
	}
}

func TestResolvePromptMode_NameSuccess(t *testing.T) {
	a := &App{cfg: &config.Config{Prompts: map[string]config.PromptEntry{
		"quick": {Text: "hello there"},
	}}}
	cmd := newRunPromptCmd(t, []string{"--prompt-name", "quick"})
	s := &runState{}
	if err := a.resolvePromptMode(cmd, s, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.promptMode || s.promptText != "hello there" {
		t.Errorf("bad state: %+v", s)
	}
}

func TestResolvePromptMode_NameMissing(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt-name", "nope"})
	err := a.resolvePromptMode(cmd, &runState{}, nil)
	if code := exitCode(t, err); code != 2 {
		t.Errorf("missing prompt name should exit 2, got %d", code)
	}
}

func TestResolvePromptMode_FileSuccess(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "task.md")
	if err := os.WriteFile(f, []byte("from a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt-file", f})
	s := &runState{}
	if err := a.resolvePromptMode(cmd, s, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.promptText != "from a file" {
		t.Errorf("promptText = %q", s.promptText)
	}
}

func TestResolvePromptMode_FileMissing(t *testing.T) {
	a := &App{cfg: &config.Config{}}
	cmd := newRunPromptCmd(t, []string{"--prompt-file", "/no/such/file"})
	err := a.resolvePromptMode(cmd, &runState{}, nil)
	if code := exitCode(t, err); code != 2 {
		t.Errorf("missing prompt file should exit 2, got %d", code)
	}
}
