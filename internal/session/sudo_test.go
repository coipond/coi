package session

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// passwordless_sudo = false: one root exec parks the rule, leaves the sudo
// group and checks `sudo -n true` is refused; a failure stops the session.
func TestPhaseSudoPolicy_DisableFailsClosed(t *testing.T) {
	r := &guestOpsRecorder{}
	st := &setupState{
		opts:   SetupOptions{Logger: func(string) {}, Security: SecurityOptions{DisableSudo: true}},
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
