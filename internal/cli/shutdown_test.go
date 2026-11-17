package cli

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestShutdown_RejectsUsageErrorsBeforeIncus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"slot flag", []string{"shutdown", "--slot", "2", "myproj"}, "coi shutdown does not take --slot"},
		{"slot flag via close", []string{"close", "--slot", "2", "myproj"}, "coi shutdown does not take --slot"},
		{"names with --all", []string{"shutdown", "--all", "--force", "coi-abc12345-1"}, "--all shuts down every container"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := fakeDeleteIncus(t, "", "coi-abc12345-1")

			err := executeWithProfiles(t, nil, noSudoConfig, tt.args...)
			var ece *ExitCodeError
			if !errors.As(err, &ece) || ece.Code != ExitUsage {
				t.Fatalf("coi %v = %v, want an ExitCodeError with code %d", tt.args, err, ExitUsage)
			}
			if !strings.Contains(ece.Message, tt.want) {
				t.Errorf("message = %q, want it to contain %q", ece.Message, tt.want)
			}
			if b, _ := os.ReadFile(logPath); len(b) > 0 {
				t.Errorf("incus called before the usage error:\n%s", b)
			}
		})
	}
}

func TestShutdown_MissingNamedTargetFailsAfterShuttingDownTheRest(t *testing.T) {
	logPath := fakeDeleteIncus(t, "")

	err := executeWithProfiles(t, nil, noSudoConfig, "shutdown", "--force", "coi-abc12345-1", "coi-abc12345-9")
	if err == nil || ExitCodeFor(err) != ExitGeneric {
		t.Fatalf("err = %v, want a failure with exit code %d", err, ExitGeneric)
	}
	if want := "failed to shut down 1 of 2 container(s): coi-abc12345-9"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 || !strings.Contains(calls[0], "coi-abc12345-1") {
		t.Errorf("delete calls = %q, want one for coi-abc12345-1", calls)
	}
}

func TestShutdown_AllToleratesContainerGoneSinceList(t *testing.T) {
	logPath := fakeDeleteIncus(t, "", "coi-abc12345-1", "coi-abc12345-9")

	if err := executeWithProfiles(t, nil, noSudoConfig, "shutdown", "--all", "--force"); err != nil {
		t.Fatalf("coi shutdown --all --force = %v, want nil", err)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 || !strings.Contains(calls[0], "coi-abc12345-1") {
		t.Errorf("delete calls = %q, want one for coi-abc12345-1", calls)
	}
}

func TestShutdown_DeleteFailsOnAlreadyRemovedContainerSucceeds(t *testing.T) {
	fakeDeleteIncus(t, `  *"delete "*) exit 1 ;;`)

	if err := executeWithProfiles(t, nil, noSudoConfig, "shutdown", "--force", "coi-abc12345-1"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestShutdown_TargetNotShutDownFails(t *testing.T) {
	tests := []struct {
		name  string
		cases string
		args  []string
		want  string
	}{
		{
			"delete fails and the container stays",
			`  *"delete "*) exit 1 ;;
  *"--columns=n") echo coi-abc12345-1 ;;`,
			[]string{"shutdown", "--force", "coi-abc12345-1"},
			"failed to shut down 1 of 1 container(s): coi-abc12345-1",
		},
		{
			"state check fails",
			`  *"--columns=ns4") exit 1 ;;`,
			[]string{"shutdown", "--force", "coi-abc12345-1"},
			"failed to shut down 1 of 1 container(s): coi-abc12345-1",
		},
		{
			"--all and every listed container is gone",
			"",
			[]string{"shutdown", "--all", "--force"},
			"failed to shut down 1 of 1 container(s): coi-abc12345-9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDeleteIncus(t, tt.cases, "coi-abc12345-9")

			err := executeWithProfiles(t, nil, noSudoConfig, tt.args...)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("coi %v = %v, want %q", tt.args, err, tt.want)
			}
		})
	}
}

func TestShutdown_DuplicateTargetShutDownOnce(t *testing.T) {
	logPath := fakeDeleteIncus(t, "")

	if err := executeWithProfiles(t, nil, noSudoConfig, "shutdown", "--force", "coi-abc12345-1", "coi-abc12345-1"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 {
		t.Errorf("delete calls = %q, want one", calls)
	}
}
