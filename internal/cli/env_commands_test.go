package cli

import (
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

func appWithEnvCommands(commands map[string]string, timeout string) *App {
	return &App{cfg: &config.Config{Defaults: config.DefaultsConfig{
		EnvCommands:       commands,
		EnvCommandTimeout: timeout,
	}}}
}

func TestResolveEnvCommands_InjectsTrimmedValue(t *testing.T) {
	a := appWithEnvCommands(map[string]string{"TOKEN": "printf '  minted-secret\\n'"}, "")
	out, err := a.resolveEnvCommands()
	if err != nil {
		t.Fatalf("resolveEnvCommands: %v", err)
	}
	if out["TOKEN"] != "minted-secret" {
		t.Errorf("value should be trimmed; got %q", out["TOKEN"])
	}
}

func TestResolveEnvCommands_Empty(t *testing.T) {
	a := appWithEnvCommands(nil, "")
	out, err := a.resolveEnvCommands()
	if err != nil || out != nil {
		t.Fatalf("no env_commands should be a no-op: out=%v err=%v", out, err)
	}
}

func TestResolveEnvCommands_ExpandsShell(t *testing.T) {
	// `sh -c` so pipelines work.
	a := appWithEnvCommands(map[string]string{"X": "echo hello | tr a-z A-Z"}, "")
	out, err := a.resolveEnvCommands()
	if err != nil {
		t.Fatalf("resolveEnvCommands: %v", err)
	}
	if out["X"] != "HELLO" {
		t.Errorf("shell pipeline not evaluated, got %q", out["X"])
	}
}

func TestResolveEnvCommands_NonZeroExitIsFatal(t *testing.T) {
	a := appWithEnvCommands(map[string]string{"BAD": "echo nope >&2; exit 7"}, "")
	_, err := a.resolveEnvCommands()
	if err == nil {
		t.Fatal("a failing env_command must return an error")
	}
	if !strings.Contains(err.Error(), "BAD") {
		t.Errorf("error should name the variable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should surface command stderr, got: %v", err)
	}
}

func TestResolveEnvCommands_TimeoutIsFatal(t *testing.T) {
	a := appWithEnvCommands(map[string]string{"SLOW": "sleep 5"}, "200ms")
	_, err := a.resolveEnvCommands()
	if err == nil {
		t.Fatal("a timing-out env_command must return an error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error should mention the timeout, got: %v", err)
	}
}

func TestEnvCommandTimeout_DefaultAndInvalid(t *testing.T) {
	if got := appWithEnvCommands(nil, "").envCommandTimeout(); got != defaultEnvCommandTimeout {
		t.Errorf("empty timeout should default, got %s", got)
	}
	if got := appWithEnvCommands(nil, "not-a-duration").envCommandTimeout(); got != defaultEnvCommandTimeout {
		t.Errorf("invalid timeout should fall back to default, got %s", got)
	}
	if got := appWithEnvCommands(nil, "2s").envCommandTimeout(); got.String() != "2s" {
		t.Errorf("valid timeout should be honored, got %s", got)
	}
}
