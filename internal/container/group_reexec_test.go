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
