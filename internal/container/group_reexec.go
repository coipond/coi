package container

import (
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
)

// incusGroupReexecGuard, when set in the environment, means we have already
// re-executed under the incus-admin group — the loop backstop so a re-exec can
// never recurse.
const incusGroupReexecGuard = "COI_INCUS_GROUP_REEXEC"

// reexecProbe / reexecExec are indirections so tests can exercise the decision
// logic without actually shelling out to sudo or replacing the process.
var (
	// reexecProbe reports whether `sudo -n -u <user> true` succeeds — i.e. the
	// sudo re-exec would be seamless (passwordless). Overridable in tests.
	reexecProbe = func(sudoPath, username string) bool {
		return exec.Command(sudoPath, "-n", "-u", username, "true").Run() == nil
	}
	// reexecExec replaces the current process with argv (via execve). On success
	// it does not return. Overridable in tests.
	reexecExec = func(path string, argv []string, env []string) error {
		return syscall.Exec(path, argv, env)
	}
)

// MaybeReexecUnderIncusGroup re-executes coi as the current user through sudo
// when the user belongs to the incus-admin group in /etc/group but the current
// login session has not activated it yet — the window right after
// `usermod -aG incus-admin` (e.g. immediately after install.sh), before the
// user has logged out and back in.
//
// sudo runs initgroups(3) for the target user, so the re-executed coi inherits
// the user's full, current supplementary group list — including the freshly
// added incus-admin — and can reach the Incus socket. This removes the
// "log out and back in" step without reintroducing sg/newgrp (deliberately
// dropped in #360 because they are root-restricted on some distros); sudo is
// the portable privileged path.
//
// It is strictly best-effort and never makes things worse: it returns (letting
// the caller proceed to the normal, clear-error path) whenever a seamless
// re-exec is unnecessary or impossible —
//   - already re-executed (guard set), or not Linux,
//   - incus / sudo not installed, or the incus-admin group is absent,
//   - the group is already active in this session,
//   - the user is not actually a member in /etc/group,
//   - Incus is already reachable (the inactive group isn't actually blocking),
//   - passwordless `sudo -u` is not available (so it would prompt/hang).
//
// On a successful re-exec the process image is replaced and this never returns.
func MaybeReexecUnderIncusGroup() {
	if os.Getenv(incusGroupReexecGuard) != "" {
		return
	}
	if runtime.GOOS != "linux" {
		return
	}
	if _, err := exec.LookPath("incus"); err != nil {
		return
	}

	grp, err := user.LookupGroup("incus-admin")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(grp.Gid)
	if err != nil {
		return
	}

	// Already active in this session? Nothing to do.
	if active, err := os.Getgroups(); err == nil {
		for _, g := range active {
			if g == gid {
				return
			}
		}
	}

	// Must be a member in /etc/group — otherwise sudo could not grant it and a
	// re-exec would be pointless (and this is not the state we handle).
	cur, err := user.Current()
	if err != nil || !UserInGroupFile(cur.Username, "incus-admin") {
		return
	}

	// If Incus is already reachable, there is nothing to fix — do NOT re-exec.
	// The group being inactive only matters when it actually blocks socket
	// access; when the socket is reachable another way (e.g. a 0666 socket, or
	// access granted out of band) a re-exec would be pointless and could perturb
	// the environment (sudo resets it) for a command that already works. This
	// keeps the re-exec strictly to the genuine "can't reach the daemon because
	// the group isn't active yet" case.
	if Available() {
		return
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}

	// Only hijack the process if passwordless sudo -u actually works; otherwise
	// fall through so the caller can print the clear re-login guidance instead
	// of surfacing a raw sudo password prompt or error.
	if !reexecProbe(sudoPath, cur.Username) {
		return
	}

	argv := buildReexecArgv(sudoPath, cur.Username, exe, os.Args[1:])

	// If exec fails for any reason, just return and let normal flow continue.
	_ = reexecExec(sudoPath, argv, os.Environ())
}

// buildReexecArgv assembles the sudo command line that re-runs coi under the
// user's full group set:
//
//		sudo -n -u <user> env <guard>=1 <exe> <original args...>
//
//	  - -n            never prompt (callers probe passwordless sudo first)
//	  - -u <user>     run as the SAME user -> initgroups activates incus-admin
//	  - env <guard>=1 survives sudo's env_reset and stops any re-exec recursion
//
// Kept as a pure function so the exact form is unit-tested without shelling out.
func buildReexecArgv(sudoPath, username, exe string, args []string) []string {
	argv := []string{sudoPath, "-n", "-u", username, "env", incusGroupReexecGuard + "=1", exe}
	return append(argv, args...)
}
