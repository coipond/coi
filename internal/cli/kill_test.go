package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noSudoConfig keeps kill's firewall cleanup from running sudo nft.
const noSudoConfig = "[network]\nuse_sudo = false\n"

// fakeKillIncus puts an incus script on PATH on which only coi-abc12345-1
// exists, and `incus list --format=json` lists listed. cases, a shell case
// body, is matched first. It logs every call and returns the log path.
func fakeKillIncus(t *testing.T, cases string, listed ...string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	var entries []string
	for _, name := range listed {
		entries = append(entries, `{"name":"`+name+`","status":"Running"}`)
	}
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
` + cases + `
  *"--format=json"*) echo '[` + strings.Join(entries, ",") + `]' ;;
  *"^coi-abc12345-1\$ --format=csv --columns=ns4"*) echo 'coi-abc12345-1,RUNNING,' ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// deleteCalls returns the logged `incus delete` calls.
func deleteCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	var calls []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "delete ") {
			calls = append(calls, line)
		}
	}
	return calls
}

func TestKill_RejectsUsageErrorsBeforeIncus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"slot flag", []string{"kill", "--slot", "2", "myproj"}, "does not take --slot"},
		{"names with --all", []string{"kill", "--all", "--force", "coi-abc12345-1"}, "not both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := fakeKillIncus(t, "", "coi-abc12345-1")

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

func TestKill_MissingNamedTargetFailsAfterKillingTheRest(t *testing.T) {
	logPath := fakeKillIncus(t, "")

	err := executeWithProfiles(t, nil, noSudoConfig, "kill", "--force", "coi-abc12345-1", "coi-abc12345-9")
	if err == nil || ExitCodeFor(err) != ExitGeneric {
		t.Fatalf("err = %v, want a failure with exit code %d", err, ExitGeneric)
	}
	if want := "failed to kill 1 of 2 container(s): coi-abc12345-9"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 || !strings.Contains(calls[0], "coi-abc12345-1") {
		t.Errorf("delete calls = %q, want one for coi-abc12345-1", calls)
	}
}

// With --all, a listed container that is gone by the kill is no failure.
func TestKill_AllToleratesContainerGoneSinceList(t *testing.T) {
	logPath := fakeKillIncus(t, "", "coi-abc12345-1", "coi-abc12345-9")

	if err := executeWithProfiles(t, nil, noSudoConfig, "kill", "--all", "--force"); err != nil {
		t.Fatalf("coi kill --all --force = %v, want nil", err)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 || !strings.Contains(calls[0], "coi-abc12345-1") {
		t.Errorf("delete calls = %q, want one for coi-abc12345-1", calls)
	}
}

func TestKill_TargetNotKilledFails(t *testing.T) {
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
			[]string{"kill", "--force", "coi-abc12345-1"},
			"failed to kill 1 of 1 container(s): coi-abc12345-1",
		},
		{
			"state check fails",
			`  *"--columns=ns4") exit 1 ;;`,
			[]string{"kill", "--force", "coi-abc12345-1"},
			"failed to kill 1 of 1 container(s): coi-abc12345-1",
		},
		{
			"--all and every listed container is gone",
			"",
			[]string{"kill", "--all", "--force"},
			"failed to kill 1 of 1 container(s): coi-abc12345-9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKillIncus(t, tt.cases, "coi-abc12345-9")

			err := executeWithProfiles(t, nil, noSudoConfig, tt.args...)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("coi %v = %v, want %q", tt.args, err, tt.want)
			}
		})
	}
}

func TestKill_DuplicateTargetKilledOnce(t *testing.T) {
	logPath := fakeKillIncus(t, "")

	if err := executeWithProfiles(t, nil, noSudoConfig, "kill", "--force", "coi-abc12345-1", "coi-abc12345-1"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if calls := deleteCalls(t, logPath); len(calls) != 1 {
		t.Errorf("delete calls = %q, want one", calls)
	}
}
