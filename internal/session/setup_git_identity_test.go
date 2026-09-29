package session

import (
	"errors"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/container"
)

type recordingExecution struct {
	commands []string
	fail     bool
}

func (r *recordingExecution) Exec(_ ...string) error { return nil }

func (r *recordingExecution) ExecArgs(_ []string, _ container.ExecCommandOptions) error {
	return nil
}

func (r *recordingExecution) ExecArgsCapture(_ []string, _ container.ExecCommandOptions) (string, error) {
	return "", nil
}

func (r *recordingExecution) ExecHostCommand(_ string, _ bool) (string, error) {
	return "", nil
}

func (r *recordingExecution) ExecCommand(command string, _ container.ExecCommandOptions) (string, error) {
	r.commands = append(r.commands, command)
	if r.fail {
		return "", errors.New("boom")
	}
	return "", nil
}

func TestSetupGitIdentityGuardUsesEscapedHome(t *testing.T) {
	rec := &recordingExecution{}

	SetupGitIdentityGuard(rec, "/home/code user", func(msg string) { t.Log(msg) })

	if len(rec.commands) != 1 {
		t.Fatalf("expected 1 command, got %d: %v", len(rec.commands), rec.commands)
	}
	if got := rec.commands[0]; got != "HOME='/home/code user' git config --global user.useConfigOnly true" {
		t.Fatalf("unexpected guard command: %s", got)
	}
}

func TestSetupGitIdentityConfiguresCompleteIdentity(t *testing.T) {
	rec := &recordingExecution{}
	var logs []string

	SetupGitIdentity(rec, "/home/code", GitIdentity{
		Name:  "O'Connor",
		Email: "dev@example.com",
	}, func(msg string) { logs = append(logs, msg) })

	if len(rec.commands) != 1 {
		t.Fatalf("expected 1 command, got %d: %v", len(rec.commands), rec.commands)
	}
	got := rec.commands[0]
	for _, want := range []string{
		"HOME='/home/code' git config --global user.name 'O'\"'\"'Connor'",
		"HOME='/home/code' git config --global user.email 'dev@example.com'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command missing %q:\n%s", want, got)
		}
	}
	if len(logs) != 1 || logs[0] != "Configured container git identity from host global git config" {
		t.Fatalf("unexpected logs: %v", logs)
	}
}

func TestSetupGitIdentityLeavesGuardOnlyWhenIncomplete(t *testing.T) {
	for _, identity := range []GitIdentity{
		{},
		{Name: "Dev"},
		{Email: "dev@example.com"},
		{Name: " ", Email: "dev@example.com"},
	} {
		rec := &recordingExecution{}
		SetupGitIdentity(rec, "/home/code", identity, func(msg string) { t.Log(msg) })
		if len(rec.commands) != 0 {
			t.Fatalf("identity %+v should not configure git, got %v", identity, rec.commands)
		}
	}
}
