package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

// notFoundCase answers `config set` the way Incus does for a container it
// deleted on the stop (ephemeral).
const notFoundCase = `  *"config set "*) echo 'Error: Failed to fetch instance "coi-abc12345-1" in project "default": Instance not found' >&2; exit 1 ;;
`

const reasonSet = "config set coi-abc12345-1 user.coi.state_reason=user user.coi.state_reason_at="

func TestContainerStop_RecordsUserReason(t *testing.T) {
	logPath := fakeDeleteIncus(t, "")

	stderr := captureOutput(t, &os.Stderr, func() {
		if err := executeWithProfiles(t, nil, noSudoConfig, "container", "stop", "coi-abc12345-1"); err != nil {
			t.Error(err)
		}
	})

	b, _ := os.ReadFile(logPath)
	stop, set := strings.Index(string(b), "stop coi-abc12345-1"), strings.Index(string(b), reasonSet)
	if stop < 0 || set < stop {
		t.Errorf("want the user reason after the stop; calls:\n%s", b)
	}
	if strings.Contains(stderr, "Warning") {
		t.Errorf("stderr = %q, want no warning", stderr)
	}
}

func TestShutdown_RecordsUserReasonBeforeDelete(t *testing.T) {
	logPath := fakeDeleteIncus(t, "")

	if err := executeWithProfiles(t, nil, noSudoConfig, "shutdown", "--force", "coi-abc12345-1"); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	set, del := strings.Index(string(b), reasonSet), strings.Index(string(b), "delete coi-abc12345-1")
	if set < 0 || del < set {
		t.Errorf("want the user reason before the delete; calls:\n%s", b)
	}
}

func TestUserStop_ContainerGoneGivesNoWarning(t *testing.T) {
	for _, args := range [][]string{
		{"container", "stop", "coi-abc12345-1"},
		{"shutdown", "--force", "coi-abc12345-1"},
	} {
		t.Run(args[0], func(t *testing.T) {
			fakeDeleteIncus(t, notFoundCase)

			stderr := captureOutput(t, &os.Stderr, func() {
				if err := executeWithProfiles(t, nil, noSudoConfig, args...); err != nil {
					t.Error(err)
				}
			})
			if strings.Contains(stderr, "stop reason") {
				t.Errorf("stderr = %q, want no stop-reason warning", stderr)
			}
		})
	}
}

func TestUserStop_OtherFailureWarns(t *testing.T) {
	fakeDeleteIncus(t, `  *"config set "*) echo 'Error: boom' >&2; exit 1 ;;
`)

	stderr := captureOutput(t, &os.Stderr, func() {
		if err := executeWithProfiles(t, nil, noSudoConfig, "container", "stop", "coi-abc12345-1"); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(stderr, "Warning: Failed to record the stop reason") || !strings.Contains(stderr, "boom") {
		t.Errorf("stderr = %q, want a warning with Incus's message", stderr)
	}
}

const reasonConfig = "config:\n  user.coi.state_reason: user\n  user.coi.state_reason_at: \"2026-11-28T03:00:00Z\"\ndevices: {}\n"

func TestContainerStart_ClearsReason(t *testing.T) {
	setupProfilesHome(t, nil, "[network]\nmode = \"open\"\nuse_sudo = false\n")
	logPath := fakeIncusCases(t, "coi-abc12345-1", reasonConfig, "RUNNING", "")

	if err := executeArgs(t, "container", "start", "coi-abc12345-1"); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	start := strings.Index(string(b), "start coi-abc12345-1")
	unset := strings.Index(string(b), "config unset coi-abc12345-1 user.coi.state_reason\n")
	unsetAt := strings.Index(string(b), "config unset coi-abc12345-1 user.coi.state_reason_at\n")
	if start < 0 || unset < start || unsetAt < start {
		t.Errorf("want both keys unset after the start; calls:\n%s", b)
	}
}

func TestLaunchContainerRunPhase_RestartClearsReason(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	logPath := fakeStoppedIncus(t, "run-reason",
		"config:\n  user.coi.state_reason: max_duration\n  user.coi.state_reason_at: \"2026-11-28T03:00:00Z\"\ndevices:\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n")
	cfg := config.GetDefaultConfig()
	cfg.Network.Mode = config.NetworkModeOpen
	cfg.Security.DisableProtection = true
	cfg.Limits = config.LimitsConfig{}
	a := &App{cfg: cfg, persistent: true}
	s := &runState{absWorkspace: ws, containerName: "run-reason", img: "coi-default", slot: 1}

	if _, err := a.launchContainerRunPhase(s).Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	start := strings.Index(string(b), "start run-reason")
	unset := strings.Index(string(b), "config unset run-reason user.coi.state_reason\n")
	unsetAt := strings.Index(string(b), "config unset run-reason user.coi.state_reason_at\n")
	if start < 0 || unset < start || unsetAt < start {
		t.Errorf("want both keys unset after the restart; calls:\n%s", b)
	}
}
