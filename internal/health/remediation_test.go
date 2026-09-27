package health

import (
	"errors"
	"testing"
)

// withRegistry swaps the remediation registry and the command executor for a
// test, returning a restore func and a pointer to the slice of recorded argvs.
func withRegistry(t *testing.T, reg []Remediation) *[][]string {
	t.Helper()
	var recorded [][]string
	origList := remediationList
	origRun := runFixCommand
	remediationList = func() []Remediation { return reg }
	runFixCommand = func(argv []string) error {
		recorded = append(recorded, argv)
		return nil
	}
	t.Cleanup(func() {
		remediationList = origList
		runFixCommand = origRun
	})
	return &recorded
}

func resultWith(checks ...HealthCheck) *HealthResult {
	m := make(map[string]HealthCheck, len(checks))
	for _, c := range checks {
		m[c.Name] = c
	}
	r := &HealthResult{Checks: m}
	r.Summary = calculateSummary(m)
	r.Status = determineStatus(m)
	return r
}

func TestRunFixes_DryRunDoesNotExecuteOrMutate(t *testing.T) {
	recalled := 0
	recorded := withRegistry(t, []Remediation{{
		Check:   "demo",
		Summary: "demo fix",
		Class:   FixSafe,
		Argv:    func() ([]string, error) { return []string{"do-thing"}, nil },
		Recheck: func() HealthCheck { recalled++; return HealthCheck{Name: "demo", Status: StatusOK} },
	}})

	res := resultWith(HealthCheck{Name: "demo", Status: StatusFailed, Message: "broken"})
	outcomes := RunFixes(res, FixOptions{DryRun: true})

	if len(outcomes) != 1 || outcomes[0].Status != FixPlanned {
		t.Fatalf("expected one planned outcome, got %+v", outcomes)
	}
	if len(*recorded) != 0 {
		t.Errorf("dry-run must not execute any command, ran %v", *recorded)
	}
	if recalled != 0 {
		t.Errorf("dry-run must not recheck, recheck ran %d times", recalled)
	}
	if got := res.Checks["demo"].Status; got != StatusFailed {
		t.Errorf("dry-run must not mutate check status, got %s", got)
	}
}

func TestRunFixes_AppliesAndRechecksToOK(t *testing.T) {
	recorded := withRegistry(t, []Remediation{{
		Check:      "demo",
		Summary:    "demo fix",
		Class:      FixSafe,
		Privileged: true,
		Argv:       func() ([]string, error) { return []string{"enable-thing"}, nil },
		Recheck:    func() HealthCheck { return HealthCheck{Name: "demo", Status: StatusOK, Message: "fixed"} },
	}})

	res := resultWith(HealthCheck{Name: "demo", Status: StatusFailed})
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 1 || outcomes[0].Status != FixApplied {
		t.Fatalf("expected applied outcome, got %+v", outcomes)
	}
	// Privileged commands must run via sudo.
	if len(*recorded) != 1 || (*recorded)[0][0] != "sudo" || (*recorded)[0][1] != "enable-thing" {
		t.Errorf("expected sudo-prefixed command, got %v", *recorded)
	}
	if res.Checks["demo"].Status != StatusOK {
		t.Errorf("recheck result should replace the check, got %s", res.Checks["demo"].Status)
	}
	if res.Status != OverallHealthy {
		t.Errorf("overall status should be recomputed to healthy, got %s", res.Status)
	}
}

func TestRunFixes_ReloginRequiredWhenRecheckStaysNonOK(t *testing.T) {
	withRegistry(t, []Remediation{{
		Check:       "permissions",
		Summary:     "add to group",
		Class:       FixSafe,
		Privileged:  true,
		ShouldApply: func(c HealthCheck) bool { return c.Status == StatusFailed },
		Argv:        func() ([]string, error) { return []string{"usermod"}, nil },
		// Command succeeds but membership isn't active until re-login.
		Recheck: func() HealthCheck {
			return HealthCheck{Name: "permissions", Status: StatusWarning, Message: "needs re-login"}
		},
		PostNote: "log out and back in",
	}})

	res := resultWith(HealthCheck{Name: "permissions", Status: StatusFailed})
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 1 || outcomes[0].Status != FixReloginRequired {
		t.Fatalf("expected relogin_required, got %+v", outcomes)
	}
	if outcomes[0].Note != "log out and back in" {
		t.Errorf("expected PostNote to be surfaced, got %q", outcomes[0].Note)
	}
}

func TestRunFixes_ShouldApplyFalseIsSkippedSilently(t *testing.T) {
	recorded := withRegistry(t, []Remediation{{
		Check:       "permissions",
		Summary:     "add to group",
		Class:       FixSafe,
		ShouldApply: func(c HealthCheck) bool { return c.Status == StatusFailed },
		Argv:        func() ([]string, error) { return []string{"usermod"}, nil },
		PostNote:    "log out and back in",
	}})

	// WARNING state: already in group file, only a re-login helps. A safe fix
	// that can't improve the state must be skipped without an outcome line and
	// without running its command — the table's own message carries guidance.
	res := resultWith(HealthCheck{Name: "permissions", Status: StatusWarning})
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 0 {
		t.Fatalf("expected no outcome for a non-applicable safe fix, got %+v", outcomes)
	}
	if len(*recorded) != 0 {
		t.Errorf("non-applicable remediation must not run, ran %v", *recorded)
	}
}

func TestRunFixes_ManualClassNeverRuns(t *testing.T) {
	recorded := withRegistry(t, []Remediation{{
		Check:   "storage",
		Summary: "repoint profile",
		Class:   FixManual,
		Argv:    func() ([]string, error) { return []string{"incus", "profile", "device", "set"}, nil },
	}})

	res := resultWith(HealthCheck{Name: "storage", Status: StatusFailed})
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 1 || outcomes[0].Status != FixManualRequired {
		t.Fatalf("expected manual_required, got %+v", outcomes)
	}
	if len(outcomes[0].Command) == 0 {
		t.Error("manual outcome should still report the command for the operator")
	}
	if len(*recorded) != 0 {
		t.Errorf("manual class must never execute, ran %v", *recorded)
	}
}

func TestRunFixes_SkipsOKAndUnregistered(t *testing.T) {
	withRegistry(t, []Remediation{{
		Check:   "demo",
		Summary: "demo fix",
		Class:   FixSafe,
		Argv:    func() ([]string, error) { return []string{"x"}, nil },
		Recheck: func() HealthCheck { return HealthCheck{Name: "demo", Status: StatusOK} },
	}})

	res := resultWith(
		HealthCheck{Name: "demo", Status: StatusOK},      // registered but already OK
		HealthCheck{Name: "other", Status: StatusFailed}, // failing but no remediation
	)
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 0 {
		t.Fatalf("expected no outcomes (OK skipped, unregistered ignored), got %+v", outcomes)
	}
}

func TestRunFixes_ArgvBuildErrorIsFailed(t *testing.T) {
	recorded := withRegistry(t, []Remediation{{
		Check:   "demo",
		Summary: "demo fix",
		Class:   FixSafe,
		Argv:    func() ([]string, error) { return nil, errors.New("cannot resolve user") },
	}})

	res := resultWith(HealthCheck{Name: "demo", Status: StatusFailed})
	outcomes := RunFixes(res, FixOptions{})

	if len(outcomes) != 1 || outcomes[0].Status != FixFailed {
		t.Fatalf("expected failed outcome, got %+v", outcomes)
	}
	if outcomes[0].Err == nil {
		t.Error("expected the build error to be reported")
	}
	if len(*recorded) != 0 {
		t.Errorf("a build failure must not execute anything, ran %v", *recorded)
	}
}

// The nft-sudoers remediation must fire ONLY for the specific failure "nft
// installed but passwordless sudo not configured", never for the other nft
// states (a sudoers rule wouldn't fix them).
func TestNftRemediation_ShouldApplyGating(t *testing.T) {
	var nft *Remediation
	reg := remediationList()
	for i := range reg {
		if reg[i].Check == "nft" {
			nft = &reg[i]
			break
		}
	}
	if nft == nil {
		t.Fatal("no remediation registered for the nft check")
	}
	if nft.ShouldApply == nil {
		t.Fatal("nft remediation must gate with ShouldApply")
	}

	det := func(installed, available bool) map[string]interface{} {
		return map[string]interface{}{"nft_installed": installed, "nft_available": available}
	}
	cases := []struct {
		name string
		c    HealthCheck
		want bool
	}{
		{"installed-but-no-sudo", HealthCheck{Status: StatusFailed, Details: det(true, false)}, true},
		{"not-installed", HealthCheck{Status: StatusFailed, Details: det(false, false)}, false},
		{"already-available", HealthCheck{Status: StatusFailed, Details: det(true, true)}, false},
		{"warning-use-sudo-false", HealthCheck{Status: StatusWarning, Details: det(true, false)}, false},
		{"ok", HealthCheck{Status: StatusOK, Details: det(true, true)}, false},
		{"failed-no-details", HealthCheck{Status: StatusFailed}, false},
	}
	for _, tc := range cases {
		if got := nft.ShouldApply(tc.c); got != tc.want {
			t.Errorf("%s: ShouldApply = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The real registry must be internally consistent: every entry must be able to
// build its argv (given the current host) or fail cleanly, and must carry a
// recheck so RunFixes verifies rather than assumes.
func TestDefaultRegistryIsWellFormed(t *testing.T) {
	for _, r := range remediations() {
		if r.Check == "" {
			t.Errorf("remediation with empty Check: %+v", r)
		}
		if r.Summary == "" {
			t.Errorf("remediation %q has no Summary", r.Check)
		}
		if r.Class == FixSafe && r.Recheck == nil {
			t.Errorf("safe remediation %q must have a Recheck so --fix verifies it", r.Check)
		}
		if r.Argv == nil {
			t.Errorf("remediation %q has no Argv", r.Check)
			continue
		}
		if _, err := r.Argv(); err != nil {
			t.Logf("remediation %q argv build returned error (acceptable on this host): %v", r.Check, err)
		}
	}
}
