package session

import (
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// codeSudoersPath is the image's NOPASSWD rule for the code user
// (internal/image/build.sh, create_code_user).
func codeSudoersPath() string { return "/etc/sudoers.d/" + container.CodeUser }

// codeSudoersDisabledPath holds the rule while sudo is off. sudo's
// @includedir skips file names containing a dot, so the rule stays inert
// there and a later session with sudo on can move it back.
func codeSudoersDisabledPath() string { return codeSudoersPath() + ".coi-disabled" }

// disableSudoCmd takes sudo away from the code user: it fails when there is
// no code user (the session would run as root), parks the NOPASSWD rule,
// drops the user from the sudo group, then fails unless `sudo -n true` as the
// code user is refused, so a sudo grant from anywhere else (a custom image,
// /etc/sudoers itself) stops the session instead of passing silently.
func disableSudoCmd() string {
	return fmt.Sprintf(
		`id -u %[3]s >/dev/null && `+
			`{ [ ! -e %[1]s ] || mv -f %[1]s %[2]s; } && `+
			`{ ! id -nG %[3]s 2>/dev/null | grep -qw sudo || gpasswd -d %[3]s sudo >/dev/null; } && `+
			`! runuser -u %[3]s -- sudo -n true >/dev/null 2>&1`,
		shellEscape(codeSudoersPath()), shellEscape(codeSudoersDisabledPath()), shellEscape(container.CodeUser))
}

// sudoRestoreFailedMarker is what restoreSudoOp prints when it fails.
const sudoRestoreFailedMarker = "coi:sudo-restore-failed"

// restoreSudoOp undoes disableSudoCmd on a persistent container that ran a
// session with sudo off. It is a no-op when the rule was never parked, and it
// never fails the batch it rides in: a failure prints sudoRestoreFailedMarker.
func restoreSudoOp() guestOp {
	return guestCmd(fmt.Sprintf(
		`[ ! -e %[1]s ] || { mv -f %[1]s %[2]s && usermod -aG sudo %[3]s; } || echo %[4]s`,
		shellEscape(codeSudoersDisabledPath()), shellEscape(codeSudoersPath()), shellEscape(container.CodeUser),
		sudoRestoreFailedMarker))
}

// reportSudoRestore logs a restoreSudoOp failure from a batched exec's output.
func reportSudoRestore(out string, logger func(string)) {
	if strings.Contains(out, sudoRestoreFailedMarker) {
		logger(fmt.Sprintf("Warning: Failed to restore sudo for the %s user", container.CodeUser))
	}
}

// effectiveKernelSurfaceViolations is container.EffectiveKernelSurfaceViolations,
// a seam for tests.
var effectiveKernelSurfaceViolations = container.EffectiveKernelSurfaceViolations

// refuseRunningDockerWithoutSudo fails a no-sudo session that would attach to
// a RUNNING container still set up for Docker: its nesting cannot be changed
// while it runs, and the docker socket (group code) gives root back.
func refuseRunningDockerWithoutSudo(containerName string, p container.HardeningPolicy) error {
	if !p.NoSudo {
		return nil
	}
	v, err := effectiveKernelSurfaceViolations(containerName, p)
	if err != nil {
		return fmt.Errorf("security.passwordless_sudo = false: could not read the Docker settings of running container %s: %w", containerName, err)
	}
	if len(v) > 0 {
		return fmt.Errorf("security.passwordless_sudo = false: running container %s still has Docker support (%s), and the docker socket gives root; stop it (coi shutdown %s) and launch again",
			containerName, strings.Join(v, ", "), containerName)
	}
	return nil
}

// DisableSudo runs the session without sudo for the code user ([security]
// passwordless_sudo = false). Fail closed: an error means the code user may
// still have sudo, and the session must not start.
func DisableSudo(mgr container.ContainerManager, logger func(string)) error {
	if _, err := mgr.ExecCommand(disableSudoCmd(), container.ExecCommandOptions{Capture: true}); err != nil {
		return fmt.Errorf("security.passwordless_sudo = false: could not remove sudo from the %s user (or the image has no such user): %w", container.CodeUser, err)
	}
	logger(fmt.Sprintf("Sudo disabled for the %s user", container.CodeUser))
	return nil
}
