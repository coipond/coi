package health

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Tripwire coupling the registry to the Python dry-run read-only contract:
// tests/health/health_fix_flag.py::_snapshot_fix_targets hardcodes the durable
// write targets of the CURRENT remediations (the coi-nft and coi-iptables
// sudoers drop-ins and the incus-admin /etc/group line). A new remediation's writes would silently
// escape that contract, so growing the registry must fail here until the
// snapshot (and this pin) are updated together.
func TestRegistrySizeIsPinnedToDryRunSnapshot(t *testing.T) {
	const pinned = 4 // permissions, ip_forwarding, nft, iptables_sudo
	if got := len(remediations()); got != pinned {
		t.Fatalf("remediation registry has %d entries (pinned: %d) — extend "+
			"_snapshot_fix_targets in tests/health/health_fix_flag.py to cover the "+
			"new remediation's write target, then bump this pin", got, pinned)
	}
}

// The nft recheck must bypass sudo's credential cache: the fix just ran sudo
// (usually with a password), so a plain `sudo -n` would succeed for ~15 minutes
// regardless of whether the sudoers drop-in actually took effect.
func TestRecheckNftSudo_IgnoresCachedCredentials(t *testing.T) {
	var got []string
	orig := runRecheckCommand
	t.Cleanup(func() { runRecheckCommand = orig })
	runRecheckCommand = func(argv []string) error { got = argv; return nil }

	if c := recheckNftSudo(); c.Status != StatusOK {
		t.Fatalf("expected OK when the probe succeeds, got %s", c.Status)
	}
	if len(got) < 4 || got[0] != "sudo" || got[1] != "-k" || got[2] != "-n" {
		t.Fatalf("recheck must run `sudo -k -n nft ...`, got %v", got)
	}
	if got[len(got)-2] != "list" || got[len(got)-1] != "ruleset" {
		t.Errorf("recheck must probe `nft list ruleset`, got %v", got)
	}

	runRecheckCommand = func([]string) error { return errors.New("a password is required") }
	if c := recheckNftSudo(); c.Status != StatusFailed {
		t.Errorf("expected FAILED when the probe fails, got %s", c.Status)
	}
}

// runNftSudoersScript executes the nft remediation's install script for real,
// against a temp target, with `visudo` resolved from PATH (stubbed or real).
func runNftSudoersScript(t *testing.T, pathDir, rule, target string) (string, error) {
	t.Helper()
	argv := sudoersDropinArgv(1000, "/usr/sbin/nft", target)
	argv[4] = rule
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "PATH="+pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeStubVisudo(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	if err := os.WriteFile(filepath.Join(dir, "visudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The rule names the user by numeric UID: a directory-service username with a
// space ("John Doe") is a sudoers syntax error that would break every sudo.
func TestNftSudoersArgv_UsesNumericUID(t *testing.T) {
	argv := sudoersDropinArgv(411531718, "/usr/sbin/nft", "/etc/sudoers.d/coi-nft")
	if len(argv) != 6 || argv[0] != "sh" || argv[1] != "-c" {
		t.Fatalf("unexpected argv shape: %q", argv)
	}
	if want := "#411531718 ALL=(ALL) NOPASSWD: /usr/sbin/nft"; argv[4] != want {
		t.Errorf("rule = %q, want %q", argv[4], want)
	}
	if argv[5] != "/etc/sudoers.d/coi-nft" {
		t.Errorf("target = %q", argv[5])
	}
	if strings.Contains(argv[2], "411531718") || strings.Contains(argv[2], "/usr/sbin/nft") {
		t.Error("rule/path must be passed as positional args, not spliced into the script")
	}
}

// A valid rule is validated, then lands at the target with mode 0440 and no
// temp file left behind.
func TestNftSudoersScript_InstallsValidatedRule(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "coi-nft")
	rule := "#1000 ALL=(ALL) NOPASSWD: /usr/sbin/nft"
	if out, err := runNftSudoersScript(t, writeStubVisudo(t, 0), rule, target); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rule+"\n" {
		t.Errorf("content = %q", got)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o440 {
		t.Errorf("mode = %o, want 0440", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

// When visudo rejects the rule, nothing is written over the target (an existing
// drop-in survives), no temp file remains, and the command fails.
func TestNftSudoersScript_InvalidRuleLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "coi-nft")
	if err := os.WriteFile(target, []byte("previous\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	out, err := runNftSudoersScript(t, writeStubVisudo(t, 1), "John Doe ALL=(ALL) NOPASSWD: /usr/sbin/nft", target)
	if err == nil {
		t.Fatalf("expected failure when visudo rejects the rule; out:\n%s", out)
	}
	if !strings.Contains(out, "refusing to install an invalid sudoers rule") {
		t.Errorf("missing refusal message; out:\n%s", out)
	}
	if got, _ := os.ReadFile(target); string(got) != "previous\n" {
		t.Errorf("target was modified: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
}

// With the real visudo (when installed), the generated #uid rule parses, and the
// username-with-space form it replaces is rejected.
func TestNftSudoersRule_RealVisudo(t *testing.T) {
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		if _, statErr := os.Stat("/usr/sbin/visudo"); statErr != nil {
			t.Skip("visudo not installed")
		}
		visudo = "/usr/sbin/visudo"
	}
	check := func(rule string) error {
		f := filepath.Join(t.TempDir(), "rule")
		if err := os.WriteFile(f, []byte(rule+"\n"), 0o440); err != nil {
			t.Fatal(err)
		}
		return exec.Command(visudo, "-cf", f).Run()
	}
	if err := check(sudoersDropinArgv(411531718, "/usr/sbin/nft", "")[4]); err != nil {
		t.Errorf("generated rule rejected by visudo: %v", err)
	}
	if err := check("John Doe ALL=(ALL) NOPASSWD: /usr/sbin/nft"); err == nil {
		t.Error("sanity: visudo should reject a username containing a space")
	}
}

// The iptables_sudo check's copy-paste hint was replaced by `coi health --fix`,
// so a remediation must exist: it fires only on the WARNING (installed, no
// passwordless sudo), installs via the validated sudoers writer with a #uid
// rule, and rechecks with `sudo -k -n`.
func TestIptablesSudoRemediation(t *testing.T) {
	var r *Remediation
	reg := remediationList()
	for i := range reg {
		if reg[i].Check == "iptables_sudo" {
			r = &reg[i]
			break
		}
	}
	if r == nil {
		t.Fatal("no remediation registered for the iptables_sudo check")
	}
	if r.Class != FixSafe || !r.Privileged || r.Recheck == nil {
		t.Errorf("iptables_sudo remediation must be a privileged FixSafe with a recheck: %+v", r)
	}
	if !r.ShouldApply(HealthCheck{Status: StatusWarning}) {
		t.Error("must apply on the WARNING (passwordless sudo not configured)")
	}
	if r.ShouldApply(HealthCheck{Status: StatusOK}) {
		t.Error("must not apply when OK (macOS, use_sudo=false, not installed, configured)")
	}

	// iptables lives in /usr/sbin, often off a non-root PATH.
	t.Setenv("PATH", os.Getenv("PATH")+string(os.PathListSeparator)+"/usr/sbin:/sbin")
	if p, err := exec.LookPath("iptables"); err != nil {
		t.Log("iptables not installed; skipping argv/recheck assertions")
	} else {
		argv, err := r.Argv()
		if err != nil {
			t.Fatalf("Argv: %v", err)
		}
		if argv[2] != sudoersDropinScript {
			t.Error("must install through the validated sudoers writer")
		}
		if want := fmt.Sprintf("#%d ALL=(ALL) NOPASSWD: %s", os.Getuid(), p); argv[4] != want {
			t.Errorf("rule = %q, want %q", argv[4], want)
		}
		if argv[5] != iptablesSudoersPath {
			t.Errorf("target = %q, want %q", argv[5], iptablesSudoersPath)
		}

		var got []string
		orig := runRecheckCommand
		t.Cleanup(func() { runRecheckCommand = orig })
		runRecheckCommand = func(argv []string) error { got = argv; return nil }
		if c := recheckIptablesSudo(); c.Status != StatusOK {
			t.Errorf("recheck should be OK when the probe succeeds, got %s", c.Status)
		}
		if len(got) < 3 || got[0] != "sudo" || got[1] != "-k" || got[2] != "-n" {
			t.Errorf("recheck must run `sudo -k -n iptables ...`, got %v", got)
		}
		runRecheckCommand = func([]string) error { return errors.New("password required") }
		if c := recheckIptablesSudo(); c.Status == StatusOK {
			t.Error("recheck must not be OK when the probe fails")
		}
	}
}
