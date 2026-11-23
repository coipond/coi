package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// passwordless_sudo = false: one root exec parks the rule, leaves the sudo
// group and checks `sudo -n true` is refused; a failure stops the session.
func TestPhaseSudoPolicy_DisableFailsClosed(t *testing.T) {
	r := &guestOpsRecorder{}
	st := &setupState{
		opts:   SetupOptions{Logger: func(string) {}, Security: SecurityOptions{NoSudo: true}},
		result: &SetupResult{Manager: r},
	}
	if _, err := st.phaseSudoPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.execs) != 1 {
		t.Fatalf("want one exec, got %d", len(r.execs))
	}
	for _, want := range []string{"'/etc/sudoers.d/code' '/etc/sudoers.d/code.coi-disabled'", "gpasswd -d 'code' sudo", "! runuser -u 'code' -- sudo -n true"} {
		if !strings.Contains(r.execs[0], want) {
			t.Errorf("disable exec missing %q:\n%s", want, r.execs[0])
		}
	}

	r = &guestOpsRecorder{execErr: errors.New("exit status 1")}
	st.result.Manager = r
	if _, err := st.phaseSudoPolicy(context.Background()); err == nil {
		t.Error("a failed sudo removal must fail the session")
	}
}

// Sudo on: nothing runs on a fresh container; a reused one queues the
// restore op for the context exec.
func TestPhaseSudoPolicy_Restore(t *testing.T) {
	r := &guestOpsRecorder{}
	st := &setupState{opts: SetupOptions{Logger: func(string) {}}, result: &SetupResult{Manager: r}}
	if _, err := st.phaseSudoPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.execs) != 0 || len(st.pendingGuestOps) != 0 {
		t.Errorf("fresh container: want no work, got execs=%d ops=%d", len(r.execs), len(st.pendingGuestOps))
	}

	st.skipLaunch = true
	if _, err := st.phaseSudoPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.execs) != 0 || len(st.pendingGuestOps) != 1 || !strings.Contains(st.pendingGuestOps[0].cmd, "usermod -aG sudo 'code'") {
		t.Errorf("reused container: want one queued restore op, got execs=%d ops=%+v", len(r.execs), st.pendingGuestOps)
	}
}

// The run path restores sudo in its timezone exec, on reuse only.
func TestConfigureTimezoneAndMiseTrust_RestoresSudo(t *testing.T) {
	for _, tc := range []struct {
		newContainer, passwordless, want bool
	}{
		{false, true, true},
		{true, true, false},
		{false, false, false},
	} {
		r := &guestOpsRecorder{}
		ConfigureTimezoneAndMiseTrust(r, "", "/workspace", nil, tc.newContainer, tc.passwordless, func(string) {})
		if got := strings.Contains(r.execs[0], sudoRestoreFailedMarker); got != tc.want {
			t.Errorf("new=%v passwordless=%v: restore op present = %v, want %v", tc.newContainer, tc.passwordless, got, tc.want)
		}
	}
}

// A failed restore is logged, not fatal.
func TestReportSudoRestore(t *testing.T) {
	var logs []string
	reportSudoRestore("ok", func(m string) { logs = append(logs, m) })
	if len(logs) != 0 {
		t.Errorf("no marker must log nothing, got %v", logs)
	}
	reportSudoRestore(sudoRestoreFailedMarker+"\n", func(m string) { logs = append(logs, m) })
	if len(logs) != 1 {
		t.Errorf("marker must log one warning, got %v", logs)
	}
}

// Setup runs the sudo policy after the code user is known and before any
// phase that runs something as the code user.
func TestSetupPhases_SudoPolicyOrder(t *testing.T) {
	st := &setupState{}
	pos := map[string]int{}
	for i, p := range st.phases() {
		pos[p.Name()] = i
	}
	sudo, ok := pos["sudo-policy"]
	if !ok {
		t.Fatal("Setup must run the sudo-policy phase")
	}
	if sudo < pos["detect-user"] || sudo < pos["remap-uid"] {
		t.Error("sudo-policy must run after detect-user and remap-uid")
	}
	if sudo > pos["forward-sockets"] {
		t.Error("sudo-policy must run before the session's code-user phases")
	}
}

// No code user: the session would run as root, so passwordless_sudo = false
// refuses it without touching the container.
func TestPhaseSudoPolicy_RefusesRoot(t *testing.T) {
	r := &guestOpsRecorder{}
	st := &setupState{
		opts:   SetupOptions{Logger: func(string) {}, Security: SecurityOptions{NoSudo: true}},
		result: &SetupResult{Manager: r, RunAsRoot: true},
	}
	if _, err := st.phaseSudoPolicy(context.Background()); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("want a run-as-root error, got %v", err)
	}
	if len(r.execs) != 0 {
		t.Errorf("want no exec, got %d", len(r.execs))
	}
}

// The disable command itself also fails without a code user (the run path).
func TestDisableSudoCmd_RequiresCodeUser(t *testing.T) {
	if !strings.HasPrefix(disableSudoCmd(), "id -u 'code' >/dev/null && ") {
		t.Errorf("disable must first check the code user exists:\n%s", disableSudoCmd())
	}
}

// The context says there is no sudo and no Docker with sudo off.
func TestContextInfo_SudoOff(t *testing.T) {
	info := contextInfoFor(&SetupResult{}, SetupOptions{Security: SecurityOptions{Docker: true, NoSudo: true}})
	if !info.SudoUnavailable {
		t.Error("NoSudo must reach the context")
	}
	if !info.DockerUnavailable {
		t.Error("no sudo must also mean no Docker")
	}
	if contextInfoFor(&SetupResult{}, SetupOptions{Security: SecurityOptions{Docker: true}}).SudoUnavailable {
		t.Error("sudo on by default")
	}
}

// runningFake is a running, existing container with no devices.
type runningFake struct {
	container.ContainerManager
}

func (runningFake) Exists() (bool, error)          { return true, nil }
func (runningFake) Running() (bool, error)         { return true, nil }
func (runningFake) ListDevices() ([]string, error) { return nil, nil }

// A no-sudo session refuses to attach to a running container that still has
// Docker (nesting), also with an explicit --container; with sudo, or without
// Docker, the attach goes ahead.
func TestPhaseReconcileExisting_RunningDockerWithoutSudo(t *testing.T) {
	orig := effectiveDockerKeys
	t.Cleanup(func() { effectiveDockerKeys = orig })
	var violations []string
	calls := 0
	effectiveDockerKeys = func(string) ([]string, error) {
		calls++
		return violations, nil
	}
	newState := func(noSudo bool) *setupState {
		return &setupState{
			opts: SetupOptions{
				ContainerName: "c1",
				Logger:        func(string) {},
				Security:      SecurityOptions{Docker: true, NoSudo: noSudo},
			},
			result: &SetupResult{Manager: runningFake{}, ContainerName: "c1"},
		}
	}

	violations = []string{"security.nesting=true"}
	_, err := newState(true).phaseReconcileExisting(context.Background())
	if err == nil || !strings.Contains(err.Error(), "security.nesting=true") || !strings.Contains(err.Error(), "coi shutdown c1") {
		t.Errorf("want a refusal naming nesting and coi shutdown, got %v", err)
	}

	violations = nil
	if _, err := newState(true).phaseReconcileExisting(context.Background()); err != nil {
		t.Errorf("no Docker left: want the attach, got %v", err)
	}

	calls = 0
	violations = []string{"security.nesting=true"}
	if _, err := newState(false).phaseReconcileExisting(context.Background()); err != nil {
		t.Errorf("sudo on: want the attach, got %v", err)
	}
	if calls != 0 {
		t.Errorf("sudo on: the config must not be read, got %d reads", calls)
	}
}

// stoppedFake is a stopped, existing container.
type stoppedFake struct {
	container.ContainerManager
}

func (stoppedFake) Exists() (bool, error)  { return true, nil }
func (stoppedFake) Running() (bool, error) { return false, nil }

// A stopped container named with --container skips the kernel-surface
// reconcile, so a no-sudo session refuses it while it still has Docker,
// before starting it.
func TestPhaseReconcileExisting_StoppedContainerDockerWithoutSudo(t *testing.T) {
	orig := effectiveDockerKeys
	t.Cleanup(func() { effectiveDockerKeys = orig })
	effectiveDockerKeys = func(string) ([]string, error) {
		return []string{"security.nesting=true"}, nil
	}
	st := &setupState{
		opts: SetupOptions{
			ContainerName: "c1",
			Logger:        func(string) {},
			Security:      SecurityOptions{Docker: true, NoSudo: true},
		},
		result: &SetupResult{Manager: stoppedFake{}, ContainerName: "c1"},
	}
	_, err := st.phaseReconcileExisting(context.Background())
	if err == nil || !strings.Contains(err.Error(), "security.nesting=true") || !strings.Contains(err.Error(), "incus config unset c1") {
		t.Errorf("want a refusal naming nesting and the unset, got %v", err)
	}
}

// The check reads nothing with sudo on and reports a read failure.
func TestRefuseDockerWithoutSudo(t *testing.T) {
	orig := effectiveDockerKeys
	t.Cleanup(func() { effectiveDockerKeys = orig })
	effectiveDockerKeys = func(string) ([]string, error) {
		return nil, errors.New("incus down")
	}
	if err := refuseDockerWithoutSudo("c1", container.HardeningPolicy{Docker: true}, "x"); err != nil {
		t.Errorf("sudo on: want no read, got %v", err)
	}
	if err := refuseDockerWithoutSudo("c1", container.HardeningPolicy{NoSudo: true}, "x"); err == nil || !strings.Contains(err.Error(), "incus down") {
		t.Errorf("a failed read must fail closed, got %v", err)
	}
}
