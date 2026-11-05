package cli

import (
	"context"
	"reflect"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/spf13/pflag"
)

// parseRunFlags parses args with the real runCmd flag set (its own and the
// inherited root flags) and returns the positional args. The flags and the app
// fields they bind are reset to their defaults when the test ends.
func parseRunFlags(t *testing.T, args []string) []string {
	t.Helper()
	t.Cleanup(func() {
		runCmd.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	})
	if err := runCmd.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags(%v): %v", args, err)
	}
	return runCmd.Flags().Args()
}

func TestRunFlags_AfterCommandGoToCommand(t *testing.T) {
	tests := [][]string{
		{"grep", "-w", "/nonexistent-dir-xyz", "pattern"},
		{"ls", "-la"},
		{"true", "--slot", "3", "--profile", "x"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			got := parseRunFlags(t, args)
			if !reflect.DeepEqual(got, args) {
				t.Errorf("coi run %v: command = %v, want %v", args, got, args)
			}
			if app.workspace != "." || app.slot != 0 || app.profile != "" {
				t.Errorf("coi run %v set coi options: workspace=%q slot=%d profile=%q",
					args, app.workspace, app.slot, app.profile)
			}
		})
	}
}

func TestRunFlags_BeforeCommandSetCoiOptions(t *testing.T) {
	got := parseRunFlags(t, []string{"-w", "/tmp/ws", "--slot", "3", "ls", "-la"})
	if want := []string{"ls", "-la"}; !reflect.DeepEqual(got, want) {
		t.Errorf("command = %v, want %v", got, want)
	}
	if app.workspace != "/tmp/ws" || app.slot != 3 {
		t.Errorf("workspace=%q slot=%d, want /tmp/ws and 3", app.workspace, app.slot)
	}
}

func TestRunFlags_DoubleDash(t *testing.T) {
	got := parseRunFlags(t, []string{"-w", "/tmp/ws", "--", "ls", "-la"})
	if want := []string{"ls", "-la"}; !reflect.DeepEqual(got, want) {
		t.Errorf("command = %v, want %v", got, want)
	}
	if app.workspace != "/tmp/ws" {
		t.Errorf("workspace = %q, want /tmp/ws", app.workspace)
	}
}

func TestRunCommand_RejectsResumeFlags(t *testing.T) {
	for _, flag := range []string{"--resume", "--resume=abc", "--continue", "--continue=abc"} {
		t.Run(flag, func(t *testing.T) {
			args := parseRunFlags(t, []string{flag, "--", "true"})
			// An invalid max_duration stops runCommand before any container
			// work if the flags are not rejected first.
			cfg := config.GetDefaultConfig()
			cfg.Limits.Runtime.MaxDuration = "invalid"
			a := &App{cfg: cfg, workspace: "."}
			runCmd.SetContext(context.Background())
			err := a.runCommand(runCmd, args)
			if err == nil {
				t.Fatalf("coi run %s: want a usage error", flag)
			}
			if code := exitCode(t, err); code != ExitUsage {
				t.Errorf("coi run %s: exit code = %d, want %d", flag, code, ExitUsage)
			}
		})
	}
}

func TestRejectRunResumeFlags_AfterCommandGoToCommand(t *testing.T) {
	got := parseRunFlags(t, []string{"echo", "--resume"})
	if err := rejectRunResumeFlags(runCmd); err != nil {
		t.Errorf("--resume after the command must reach the command, got %v", err)
	}
	if want := []string{"echo", "--resume"}; !reflect.DeepEqual(got, want) {
		t.Errorf("command = %v, want %v", got, want)
	}
}
