package container

import (
	"testing"
)

// When the guard env var is set (we've already re-executed), MaybeReexec must
// short-circuit immediately and never probe or exec — the loop backstop.
func TestMaybeReexec_GuardShortCircuits(t *testing.T) {
	t.Setenv(incusGroupReexecGuard, "1")

	probed, execed := false, false
	origProbe, origExec := reexecProbe, reexecExec
	reexecProbe = func(_, _ string) bool { probed = true; return true }
	reexecExec = func(_ string, _ []string, _ []string) error { execed = true; return nil }
	t.Cleanup(func() { reexecProbe, reexecExec = origProbe, origExec })

	MaybeReexecUnderIncusGroup()

	if probed {
		t.Error("guard set: must not probe sudo")
	}
	if execed {
		t.Error("guard set: must not re-exec")
	}
}

// The re-exec command line must be exactly:
//
//	sudo -n -u <user> env COI_INCUS_GROUP_REEXEC=1 <exe> <original args...>
//
// -n (no prompt), same-user (initgroups activates the group), guard set to
// prevent recursion, and the user's original args preserved verbatim.
func TestBuildReexecArgv(t *testing.T) {
	got := buildReexecArgv("/usr/bin/sudo", "ubuntu", "/usr/local/bin/coi",
		[]string{"HTTPS_PROXY=http://p:8080", "COI_X=1"}, []string{"build", "--slot", "2"})
	want := []string{
		"/usr/bin/sudo", "-n", "-u", "ubuntu",
		"env", "HTTPS_PROXY=http://p:8080", "COI_X=1", "COI_INCUS_GROUP_REEXEC=1",
		"/usr/local/bin/coi", "build", "--slot", "2",
	}
	if len(got) != len(want) {
		t.Fatalf("argv length: got %d %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
	// The forwarded environment must come BEFORE the guard, and the guard BEFORE
	// the exe — otherwise env would treat the exe as an assignment or vice versa.
	guardIdx, exeIdx := -1, -1
	for i, a := range got {
		if a == incusGroupReexecGuard+"=1" {
			guardIdx = i
		}
		if a == "/usr/local/bin/coi" {
			exeIdx = i
		}
	}
	if guardIdx <= 0 || exeIdx != guardIdx+1 {
		t.Errorf("guard must immediately precede the exe; guardIdx=%d exeIdx=%d argv=%v", guardIdx, exeIdx, got)
	}
}

// With no forwarded env and no args (bare `coi`), argv is just the preamble.
func TestBuildReexecArgv_NoEnvNoArgs(t *testing.T) {
	got := buildReexecArgv("/usr/bin/sudo", "me", "/opt/coi", nil, nil)
	want := []string{"/usr/bin/sudo", "-n", "-u", "me", "env", "COI_INCUS_GROUP_REEXEC=1", "/opt/coi"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// On a host without Incus / the incus-admin group / an active membership (the
// case in this test environment), MaybeReexec must be a best-effort no-op: it
// must never re-exec. This guards the "never make things worse" contract.
func TestMaybeReexec_NoIncusOrGroup_DoesNotExec(t *testing.T) {
	// Ensure the guard is not set so we exercise the real gates.
	t.Setenv(incusGroupReexecGuard, "")

	execed := false
	origProbe, origExec := reexecProbe, reexecExec
	// If the gates somehow pass in this env, the probe returns false so we still
	// don't exec; assert exec is never reached regardless.
	reexecProbe = func(_, _ string) bool { return false }
	reexecExec = func(_ string, _ []string, _ []string) error { execed = true; return nil }
	t.Cleanup(func() { reexecProbe, reexecExec = origProbe, origExec })

	MaybeReexecUnderIncusGroup()

	if execed {
		t.Error("no active incus-admin membership (or no incus/sudo): must not re-exec")
	}
}
