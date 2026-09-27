package health

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// FixClass classifies how a remediation may be applied by `coi health --fix`.
type FixClass int

const (
	// FixSafe is an additive, idempotent change (create something missing,
	// enable a flag). `--fix` applies these automatically.
	FixSafe FixClass = iota
	// FixManual is a change that is destructive or ambiguous (e.g. repointing an
	// existing profile, or a choice between two pools). `--fix` never runs these;
	// it prints the command for the operator to run deliberately. This mirrors
	// the #823 rule: never guess between two valid resources.
	FixManual
)

// Remediation describes how to repair a single failing health check. It is
// intentionally the inverse of a HealthCheck: a check reports a fact, a
// Remediation knows how to change that fact and then how to re-verify it.
//
// Design note: Argv covers every remediation we ship today (each is a single
// command). A future fix that is not expressible as one command (e.g. the
// #823 `incus admin init --preseed` flow) can grow an alternative Apply func;
// the RunFixes loop below is written so that extension is additive.
type Remediation struct {
	// Check is the HealthCheck.Name this remediation repairs.
	Check string
	// Summary is a human-readable description of what applying the fix does.
	Summary string
	// Class gates whether --fix will run the fix or only print it.
	Class FixClass
	// Privileged marks a fix that must run as root; RunFixes prefixes it with
	// sudo so a normal user is prompted once rather than failing opaquely.
	Privileged bool
	// ShouldApply decides, given the current check result, whether there is
	// anything to do. It lets a remediation opt out of a check state it cannot
	// improve (e.g. "in the group file but the session hasn't reloaded" — only
	// a re-login fixes that, not another usermod). Nil means "any non-OK state".
	ShouldApply func(HealthCheck) bool
	// Argv returns the command to run to apply the fix (without any sudo
	// prefix). It is used for both the dry-run display and execution.
	Argv func() ([]string, error)
	// Recheck re-runs the underlying check after applying, so the outcome
	// reflects reality rather than an assumption that the command worked.
	Recheck func() HealthCheck
	// PostNote, when set, is shown after a successful apply — used to explain a
	// step the tool cannot do for the user (e.g. "log out and back in").
	PostNote string
}

// FixStatus is the result of attempting one remediation.
type FixStatus string

const (
	// FixPlanned: --dry-run only; the command was not run.
	FixPlanned FixStatus = "planned"
	// FixApplied: the command ran and the check now passes.
	FixApplied FixStatus = "applied"
	// FixReloginRequired: the command ran successfully but the check still
	// isn't OK in this session because a re-login (or newgrp) is required.
	FixReloginRequired FixStatus = "relogin_required"
	// FixManualRequired: the fix is FixManual, or ShouldApply returned false —
	// the operator must act. The command (if any) is reported for them.
	FixManualRequired FixStatus = "manual_required"
	// FixFailed: the command was run but errored, or building it failed.
	FixFailed FixStatus = "failed"
)

// FixOutcome records what RunFixes did (or would do) for one check.
type FixOutcome struct {
	Check   string
	Summary string
	Class   FixClass
	Command []string
	Status  FixStatus
	Note    string
	Err     error
}

// FixOptions controls RunFixes behavior.
type FixOptions struct {
	// DryRun reports the plan without running any command.
	DryRun bool
}

// runFixCommand executes a remediation command. It is a package var so unit
// tests can swap it out and assert on the argv without touching the host.
var runFixCommand = func(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // argv comes from a fixed in-repo remediation registry, not user input
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// remediationList is the source of the fix registry used by RunFixes and
// remediationFor. It is a package var (defaulting to remediations) so unit
// tests can substitute a deterministic set without touching the host.
var remediationList = remediations

// remediations returns the registry of known fixes. Keeping it a function
// (rather than a package-level map) means each call re-reads live state such as
// the current user and executable path, so a fix built here is always current.
func remediations() []Remediation {
	return []Remediation{
		{
			Check:      "permissions",
			Summary:    "Add the current user to the incus-admin group",
			Class:      FixSafe,
			Privileged: true,
			// Only usermod when the group exists and the user is genuinely absent
			// from it. Two states are deliberately excluded:
			//   - WARNING ("in the group file, session not reloaded") — only a
			//     re-login fixes that, not another usermod.
			//   - FAILED because the incus-admin group does not exist at all —
			//     that means Incus isn't installed yet, so usermod would just
			//     fail; the real prerequisite is installing Incus first.
			ShouldApply: func(c HealthCheck) bool {
				if c.Status != StatusFailed {
					return false
				}
				_, err := user.LookupGroup("incus-admin")
				return err == nil
			},
			Argv: func() ([]string, error) {
				u, err := user.Current()
				if err != nil {
					return nil, fmt.Errorf("could not determine current user: %w", err)
				}
				return []string{"usermod", "-aG", "incus-admin", u.Username}, nil
			},
			Recheck:  func() HealthCheck { return CheckPermissions() },
			PostNote: "Log out and back in (or run: newgrp incus-admin) for incus-admin membership to take effect.",
		},
		{
			Check:       "ip_forwarding",
			Summary:     "Enable IPv4 forwarding (net.ipv4.ip_forward=1)",
			Class:       FixSafe,
			Privileged:  true,
			ShouldApply: func(c HealthCheck) bool { return c.Status != StatusOK },
			Argv: func() ([]string, error) {
				return []string{"sysctl", "-w", "net.ipv4.ip_forward=1"}, nil
			},
			Recheck: func() HealthCheck { return CheckIPForwarding() },
		},
		{
			Check:      "nft",
			Summary:    "Configure passwordless sudo for nft (needed for restricted/allowlist network isolation)",
			Class:      FixSafe,
			Privileged: true,
			// Only when nft is installed but passwordless sudo isn't configured
			// (the "nft installed but passwordless sudo not configured" failure).
			// Other nft-check failures — not installed, masquerade off, or the
			// use_sudo=false opt-out (a WARNING) — are not fixed by a sudoers rule.
			ShouldApply: func(c HealthCheck) bool {
				if c.Status != StatusFailed {
					return false
				}
				installed, _ := c.Details["nft_installed"].(bool)
				available, _ := c.Details["nft_available"].(bool)
				return installed && !available
			},
			Argv: func() ([]string, error) {
				u, err := user.Current()
				if err != nil {
					return nil, fmt.Errorf("could not determine current user: %w", err)
				}
				// Write the drop-in and lock its perms in one privileged shell
				// (the framework prefixes sudo). Username/path are system values
				// with no quote chars, so single-quoting the line is safe.
				line := u.Username + " ALL=(ALL) NOPASSWD: " + nftBinaryPath()
				script := "echo '" + line + "' > /etc/sudoers.d/coi-nft && chmod 0440 /etc/sudoers.d/coi-nft"
				return []string{"sh", "-c", script}, nil
			},
			Recheck: recheckNftSudo,
		},
	}
}

// nftBinaryPath resolves the nft binary, falling back to its usual location
// (nft lives in /usr/sbin, which isn't always on a non-root user's PATH).
func nftBinaryPath() string {
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	return "/usr/sbin/nft"
}

// recheckNftSudo reports whether passwordless `sudo -n nft` works now — the
// exact condition the nft-sudoers remediation fixes. It is config-independent
// (sudoers is read per invocation, so no re-login is needed): if
// `sudo -n nft list ruleset` succeeds, the drop-in is in effect.
func recheckNftSudo() HealthCheck {
	if exec.Command("sudo", "-n", nftBinaryPath(), "list", "ruleset").Run() == nil {
		return HealthCheck{Name: "nft", Status: StatusOK, Message: "Passwordless sudo for nft configured"}
	}
	return HealthCheck{Name: "nft", Status: StatusFailed, Message: "Passwordless sudo for nft still not configured"}
}

// RunFixes attempts to remediate every non-OK check in result that has a
// registered fix, following a detect → act → re-check loop per fix. It updates
// result in place (rechecked checks replace their prior entry, and the summary
// and overall status are recomputed) so the caller's exit code reflects the
// post-fix reality. It returns one FixOutcome per check it considered, in the
// registry's declared order, so output is deterministic.
func RunFixes(result *HealthResult, opts FixOptions) []FixOutcome {
	var outcomes []FixOutcome

	for _, r := range remediationList() {
		check, ok := result.Checks[r.Check]
		if !ok || check.Status == StatusOK {
			continue // nothing wrong with this check (or it wasn't run)
		}

		outcome := FixOutcome{Check: r.Check, Summary: r.Summary, Class: r.Class}

		// Build the command up front so both dry-run and apply can show it, and
		// so a build error (e.g. can't resolve the user) is surfaced clearly.
		var argv []string
		if r.Argv != nil {
			built, err := r.Argv()
			if err != nil {
				outcome.Status = FixFailed
				outcome.Err = err
				outcomes = append(outcomes, outcome)
				continue
			}
			argv = built
		}
		outcome.Command = displayCommand(argv, r.Privileged)

		// A deliberately manual/destructive fix is reported with its command so
		// the operator can run it, but --fix never runs it (the #823 rule:
		// never guess between valid resources, never silently repoint).
		if r.Class == FixManual {
			outcome.Status = FixManualRequired
			outcome.Note = r.PostNote
			outcomes = append(outcomes, outcome)
			continue
		}

		// A safe remediation that can't improve this particular state (e.g.
		// group membership that only a re-login activates, or a group that
		// doesn't exist because Incus isn't installed) is skipped without a
		// line: running its command wouldn't help, and the check's own message
		// in the table below already carries the right guidance.
		if r.ShouldApply != nil && !r.ShouldApply(check) {
			continue
		}

		if opts.DryRun {
			outcome.Status = FixPlanned
			outcome.Note = r.PostNote
			outcomes = append(outcomes, outcome)
			continue
		}

		if err := runFixCommand(execArgv(argv, r.Privileged)); err != nil {
			outcome.Status = FixFailed
			outcome.Err = err
			outcomes = append(outcomes, outcome)
			continue
		}

		// Re-verify against reality rather than assuming success.
		if r.Recheck != nil {
			rechecked := r.Recheck()
			result.Checks[r.Check] = rechecked
			if rechecked.Status == StatusOK {
				outcome.Status = FixApplied
			} else {
				// The command succeeded but the check still isn't green — the
				// canonical case is group membership needing a re-login.
				outcome.Status = FixReloginRequired
				outcome.Note = r.PostNote
			}
		} else {
			outcome.Status = FixApplied
		}
		outcomes = append(outcomes, outcome)
	}

	// Reflect any rechecked results in the summary and overall status.
	result.Summary = calculateSummary(result.Checks)
	result.Status = determineStatus(result.Checks)

	return outcomes
}

// execArgv prefixes a privileged command with sudo for execution.
func execArgv(argv []string, privileged bool) []string {
	if privileged {
		return append([]string{"sudo"}, argv...)
	}
	return argv
}

// displayCommand renders a command for human display (dry-run / reports),
// including the sudo prefix so what is printed matches what would run.
func displayCommand(argv []string, privileged bool) []string {
	if len(argv) == 0 {
		return nil
	}
	return execArgv(argv, privileged)
}
