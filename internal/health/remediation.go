package health

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"

	"github.com/coipond/coi/internal/network"
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
	// FixPlanned means --dry-run only; the command was not run.
	FixPlanned FixStatus = "planned"
	// FixApplied means the command ran and the check now passes.
	FixApplied FixStatus = "applied"
	// FixReloginRequired means the command ran successfully but the check still
	// isn't OK in this session because a re-login (or newgrp) is required.
	FixReloginRequired FixStatus = "relogin_required"
	// FixManualRequired means the fix is FixManual: --fix never runs it, and
	// the operator must act. The command (if any) is reported for them. (A fix
	// whose ShouldApply returns false produces no outcome at all.)
	FixManualRequired FixStatus = "manual_required"
	// FixFailed means the command was run but errored, or building it failed.
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
				return sudoersDropinArgv(os.Getuid(), nftBinaryPath(), nftSudoersPath), nil
			},
			Recheck: recheckNftSudo,
		},
		{
			Check:   "iptables_sudo",
			Summary: "Configure passwordless sudo for iptables (bridge FORWARD rule management)",
			// FixManual: `NOPASSWD: iptables` with any arguments is effectively
			// root (iptables can be pointed at an arbitrary --modprobe helper),
			// so --fix prints the command for the operator to run deliberately
			// instead of granting it silently.
			Class:      FixManual,
			Privileged: true,
			// Only when sudo stopped at a password prompt. If iptables itself
			// fails even via sudo, a sudoers rule can't help.
			ShouldApply: func(c HealthCheck) bool {
				needs, _ := c.Details["sudo_password_required"].(bool)
				return c.Status == StatusWarning && needs
			},
			PostNote: "This grants passwordless root-equivalent access to iptables; only run it if you need Coi's bridge FORWARD rule management.",
			Argv: func() ([]string, error) {
				p, err := exec.LookPath("iptables")
				if err != nil {
					return nil, fmt.Errorf("iptables not found: %w", err)
				}
				return sudoersDropinArgv(os.Getuid(), p, iptablesSudoersPath), nil
			},
			Recheck: recheckIptablesSudo,
		},
	}
}

// Drop-ins the passwordless-sudo remediations install.
const (
	nftSudoersPath      = "/etc/sudoers.d/coi-nft"
	iptablesSudoersPath = "/etc/sudoers.d/coi-iptables"
)

// sudoersDropinScript installs a sudoers drop-in without ever leaving a broken
// file where sudo reads it: the rule ($1) goes to a dot-named temp file in the
// target's directory (sudo's includedir skips names containing '.'), is
// syntax-checked with visudo, and only then renamed over the target ($2). A
// syntax error in /etc/sudoers.d makes every sudo on the host fail — including
// the one needed to repair it — so an unchecked in-place write is a lockout risk.
// The rule and path are positional args, never spliced into the script.
// Mirrors install_sudoers_dropin (install.sh) and scripts/install-sudoers-dropin.sh.
const sudoersDropinScript = `PATH="$PATH:/usr/sbin:/sbin"
if ! command -v visudo >/dev/null 2>&1; then
	echo "coi: visudo not found — can't validate the sudoers rule, so not installing it" >&2
	exit 1
fi
tmp="$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX")" || exit 1
if printf '%s\n' "$1" > "$tmp" && chmod 0440 "$tmp" && visudo -cf "$tmp" >/dev/null; then
	mv -f "$tmp" "$2"
else
	rm -f "$tmp"
	echo "coi: refusing to install an invalid sudoers rule: $1" >&2
	exit 1
fi`

// sudoersDropinArgv builds the (unprivileged) argv that installs a rule giving
// uid passwordless sudo for binPath, at path. The user is named by numeric UID
// (`#1000`), not username: a directory-service name containing a space or quote
// (SSSD/AD "John Doe") is a sudoers syntax error, while `#uid` is always valid.
func sudoersDropinArgv(uid int, binPath, path string) []string {
	rule := fmt.Sprintf("#%d ALL=(ALL) NOPASSWD: %s", uid, binPath)
	return []string{"sh", "-c", sudoersDropinScript, "sh", rule, path}
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
// `sudo -k -n nft list ruleset` succeeds, the drop-in is in effect. -k is
// essential: the fix itself just ran sudo (usually with a password), so the
// cached credential would make a plain `sudo -n` pass whatever the drop-in says.
func recheckNftSudo() HealthCheck {
	if _, err := runProbe(nftSudoRecheckArgv()); err == nil {
		return HealthCheck{Name: "nft", Status: StatusOK, Message: "Passwordless sudo for nft configured"}
	}
	return HealthCheck{Name: "nft", Status: StatusFailed, Message: "Passwordless sudo for nft still not configured"}
}

// nftSudoRecheckArgv is the probe recheckNftSudo runs: -k ignores (without
// clearing) the cached sudo credential, -n forbids prompting.
func nftSudoRecheckArgv() []string {
	return []string{"sudo", "-k", "-n", nftBinaryPath(), "list", "ruleset"}
}

// recheckIptablesSudo mirrors recheckNftSudo for the iptables drop-in, probing
// with -k so the credential cached by the fix can't mask a non-working rule.
func recheckIptablesSudo() HealthCheck {
	p, err := exec.LookPath("iptables")
	if err == nil {
		_, err = runProbe([]string{"sudo", "-k", "-n", p, "-L", "FORWARD", "-n"})
	}
	if err == nil {
		return HealthCheck{Name: "iptables_sudo", Status: StatusOK, Message: "Passwordless sudo configured for iptables"}
	}
	return HealthCheck{Name: "iptables_sudo", Status: StatusWarning, Message: "Passwordless sudo for iptables still not configured"}
}

// runProbe runs a sudo probe (detection checks and post-fix rechecks) and
// returns its combined output; a package var so unit tests can observe the
// argv without invoking sudo.
// The probe runs in the C locale: sudoNeedsPassword matches sudo's English
// message, and a translated one ("Ein Passwort ist notwendig") would be
// misread as "iptables itself fails", so the fix would never be offered.
var runProbe = func(argv []string) ([]byte, error) {
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // fixed argv from the health probes
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANGUAGE=")
	return cmd.CombinedOutput()
}

// nftPasswordlessSudo is network.NftPasswordlessSudo; a package var so tests
// can stub it.
var nftPasswordlessSudo = network.NftPasswordlessSudo

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

		// A safe remediation that can't improve this particular state (e.g.
		// group membership that only a re-login activates, or a group that
		// doesn't exist because Incus isn't installed) is skipped without a
		// line: running its command wouldn't help, and the check's own message
		// in the table below already carries the right guidance.
		if r.ShouldApply != nil && !r.ShouldApply(check) {
			continue
		}

		// A deliberately manual/destructive fix is reported with its command so
		// the operator can run it, but --fix never runs it (the #823 rule:
		// never guess between valid resources, never silently repoint). It
		// comes after ShouldApply so a manual fix that can't help this state
		// isn't offered either.
		if r.Class == FixManual {
			outcome.Status = FixManualRequired
			outcome.Note = r.PostNote
			outcomes = append(outcomes, outcome)
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
