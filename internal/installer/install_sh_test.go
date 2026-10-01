package installer_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// installShPath returns the absolute path to install.sh at the repo root.
func installShPath(t *testing.T) string {
	t.Helper()
	// Walk up from this test file to repo root
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(wd, "..", "..")
	path := filepath.Join(root, "install.sh")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("install.sh not found at %s: %v", path, err)
	}
	return path
}

// runBashSnippet runs a bash snippet that sources the install.sh functions and
// returns stdout, stderr, and the exit code. The snippet runs with
// NONINTERACTIVE=1 by default unless overridden via env.
func runBashSnippet(t *testing.T, snippet string, env ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", snippet)
	cmd.Env = append(os.Environ(), env...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run snippet: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// When stdin is not a terminal (piped input), install.sh should detect non-interactive
// mode automatically via the `! [ -t 0 ]` check in the NONINTERACTIVE detection block.
func TestInstallSh_DetectsNonInteractiveWhenPiped(t *testing.T) {
	script := installShPath(t)

	// Source install.sh functions and check the NONINTERACTIVE variable.
	// We pipe through bash (simulating curl|bash) so stdin is not a TTY.
	snippet := `
		# Source just the variable/function definitions (stop before main runs)
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		echo "NONINTERACTIVE=$NONINTERACTIVE"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "NONINTERACTIVE=1") {
		t.Errorf("expected NONINTERACTIVE=1 when piped, got: %s", strings.TrimSpace(stdout))
	}
}

// When NONINTERACTIVE=1 is set explicitly, prompt_continue should abort with a
// clear message instead of trying to read from the terminal.
func TestInstallSh_PromptContinueAbortsNonInteractive(t *testing.T) {
	script := installShPath(t)

	snippet := `
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		prompt_continue "Continue anyway?"
		echo "SHOULD_NOT_REACH"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode == 0 {
		t.Errorf("expected non-zero exit code from prompt_continue in non-interactive mode")
	}
	if strings.Contains(stdout, "SHOULD_NOT_REACH") {
		t.Errorf("prompt_continue should have exited, but execution continued")
	}
	if !strings.Contains(stdout, "Non-interactive mode") {
		t.Errorf("expected non-interactive warning message, got: %s", stdout)
	}
}

// When NONINTERACTIVE=1 is set, prompt_choice should return the default value
// without attempting to read from the terminal.
func TestInstallSh_PromptChoiceUsesDefaultNonInteractive(t *testing.T) {
	script := installShPath(t)

	snippet := `
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		prompt_choice "Pick one: " "1"
		echo "REPLY=$REPLY"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "REPLY=1") {
		t.Errorf("expected REPLY=1 (default), got: %s", strings.TrimSpace(stdout))
	}
}

// When CI=true is set, install.sh should detect non-interactive mode even
// without piped stdin or explicit NONINTERACTIVE flag.
func TestInstallSh_DetectsCI(t *testing.T) {
	script := installShPath(t)

	snippet := `
		export CI=true
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		echo "NONINTERACTIVE=$NONINTERACTIVE"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "CI=true")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "NONINTERACTIVE=1") {
		t.Errorf("expected NONINTERACTIVE=1 with CI=true, got: %s", strings.TrimSpace(stdout))
	}
}

// In non-interactive mode, check_nft should complete without hanging.
func TestInstallSh_NftAutoSetup_NonInteractive(t *testing.T) {
	script := installShPath(t)

	snippet := `
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		check_nft
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("check_nft exited with %d in non-interactive mode; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("check_nft did not complete in non-interactive mode; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Errorf("check_nft tried to prompt in non-interactive mode; stdout: %s", stdout)
	}
	t.Logf("check_nft non-interactive output:\n%s", stdout)
}

// prompt_choice should use a non-default value ("2") when that is passed as default.
func TestInstallSh_PromptChoiceCustomDefault(t *testing.T) {
	script := installShPath(t)

	snippet := `
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		prompt_choice "Pick one: " "2"
		echo "REPLY=$REPLY"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "REPLY=2") {
		t.Errorf("expected REPLY=2, got: %s", strings.TrimSpace(stdout))
	}
}

// When incus is not installed, ensure_incus_initialized should be a silent no-op.
func TestInstallSh_EnsureIncusInitialized_SkipsWhenIncusMissing(t *testing.T) {
	script := installShPath(t)

	// Use a PATH that definitely does not contain incus
	snippet := `
		export NONINTERACTIVE=1
		export PATH=/usr/bin:/bin
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		echo "EXIT=$?"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1", "PATH=/usr/bin:/bin")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "EXIT=0") {
		t.Errorf("expected clean exit, got: %s", strings.TrimSpace(stdout))
	}
	// Should produce no output (silent skip)
	if strings.Contains(stdout, "Incus") {
		t.Errorf("expected no Incus messages when incus is missing, got: %s", stdout)
	}
}

// When incus reports networks exist, ensure_incus_initialized should be a silent no-op
// (Incus is already initialized).
func TestInstallSh_EnsureIncusInitialized_SkipsWhenAlreadyInitialized(t *testing.T) {
	if _, err := exec.LookPath("incus"); err != nil {
		t.Skip("incus not found, skipping")
	}

	script := installShPath(t)

	// Stub incus: when called with "network list", return a fake MANAGED network
	// line (column 3 = YES). This simulates an already-initialized Incus without
	// needing a real one.
	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	echo "incusbr0,bridge,YES,10.87.0.1/24,,,3,RUNNING"
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// Should NOT attempt initialization
	if strings.Contains(stdout, "has not been initialized") {
		t.Errorf("should skip when networks exist, got: %s", stdout)
	}
}

// When incus reports no networks, ensure_incus_initialized should run
// `sudo incus admin init --auto` and print a styled success message.
func TestInstallSh_EnsureIncusInitialized_RunsInitWhenNoNetworks(t *testing.T) {
	script := installShPath(t)

	// Stub both incus and sudo:
	// - incus network list returns empty (no networks → not initialized)
	// - sudo incus admin init --auto succeeds
	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	# Empty output = no networks
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		export COI_TEST_MARKER="$tmpdir/init_called"
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"incus admin init --auto"* ]]; then
	touch "$COI_TEST_MARKER"
	exit 0
fi
# Pass through other sudo calls
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		# Check the marker file
		if [ -f "$COI_TEST_MARKER" ]; then
			echo "INIT_WAS_CALLED"
		fi
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// Should print the initialization message
	if !strings.Contains(stdout, "has not been initialized") {
		t.Errorf("expected 'has not been initialized' message, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Incus initialized") {
		t.Errorf("expected success message, got: %s", stdout)
	}
	// Verify sudo was called with the right command
	if !strings.Contains(stdout, "INIT_WAS_CALLED") {
		t.Errorf("expected sudo incus admin init --auto to be called; stdout: %s", stdout)
	}
}

// #703: on a real host, `incus network list` is never empty even before
// `incus admin init` has run, because it also lists unmanaged physical and
// loopback interfaces. ensure_incus_initialized must still run
// `sudo incus admin init --auto` in that case rather than treating a
// non-empty-but-all-unmanaged list as "already initialized".
func TestInstallSh_EnsureIncusInitialized_RunsInitWhenOnlyUnmanagedNetworksExist(t *testing.T) {
	script := installShPath(t)

	// Stub incus network list with the exact CSV shape reported in #703: a
	// physical NIC and loopback, both unmanaged (column 3, MANAGED, is NO).
	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	printf 'enp7s0,physical,NO,,,,0,\n'
	printf 'lo,loopback,NO,,,,0,\n'
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		export COI_TEST_MARKER="$tmpdir/init_called"
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"incus admin init --auto"* ]]; then
	touch "$COI_TEST_MARKER"
	exit 0
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		if [ -f "$COI_TEST_MARKER" ]; then
			echo "INIT_WAS_CALLED"
		fi
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "has not been initialized") {
		t.Errorf("expected 'has not been initialized' message when only unmanaged networks exist, got: %s", stdout)
	}
	if !strings.Contains(stdout, "INIT_WAS_CALLED") {
		t.Errorf("expected sudo incus admin init --auto to be called when only unmanaged networks exist (#703); stdout: %s", stdout)
	}
}

// A host can be initialized with an existing/custom network and no managed
// bridge, so the network list holds only unmanaged interfaces. `incus admin
// init --auto` always creates a storage pool too, so a non-empty storage list
// must count as "already initialized" and skip re-running init - otherwise the
// installer prints a false "not initialized" warning and fires a doomed
// `sudo incus admin init --auto` (which refuses on a configured host).
func TestInstallSh_EnsureIncusInitialized_SkipsWhenOnlyStoragePoolExists(t *testing.T) {
	script := installShPath(t)

	// incus network list returns only unmanaged interfaces (MANAGED=NO), but
	// storage list returns a pool - the reliable signal of prior init.
	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	printf 'enp7s0,physical,NO,,,,0,\n'
	printf 'lo,loopback,NO,,,,0,\n'
	exit 0
fi
if [[ "$*" == *"storage list"* ]]; then
	echo "default,zfs,,,3,CREATED"
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		export COI_TEST_MARKER="$tmpdir/init_called"
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"incus admin init --auto"* ]]; then
	touch "$COI_TEST_MARKER"
	exit 0
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		if [ -f "$COI_TEST_MARKER" ]; then
			echo "INIT_WAS_CALLED"
		fi
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "has not been initialized") {
		t.Errorf("should skip init when a storage pool exists, got: %s", stdout)
	}
	if strings.Contains(stdout, "INIT_WAS_CALLED") {
		t.Errorf("must not run sudo incus admin init --auto when a storage pool already exists; stdout: %s", stdout)
	}
}

// When `sudo incus admin init --auto` fails, ensure_incus_initialized should
// print a warning with the error output and return non-zero.
func TestInstallSh_EnsureIncusInitialized_HandlesInitFailure(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"incus admin init --auto"* ]]; then
	echo "Error: something went wrong"
	exit 1
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		echo "SHOULD_NOT_REACH"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode == 0 {
		t.Errorf("expected non-zero exit from init failure, got 0; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "SHOULD_NOT_REACH") {
		t.Errorf("function should have returned non-zero; stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "initialization failed") {
		t.Errorf("expected failure warning, got: %s", stdout)
	}
	if !strings.Contains(stdout, "something went wrong") {
		t.Errorf("expected error output to be shown, got: %s", stdout)
	}
}

// When `incus network list` itself fails (daemon down, permission denied),
// ensure_incus_initialized should warn and return non-zero instead of
// incorrectly triggering init.
func TestInstallSh_EnsureIncusInitialized_WarnsOnQueryFailure(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"network list"* ]]; then
	echo "Error: not authorized" >&2
	exit 1
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"
		# install.sh runs these queries as ` + "`sudo incus ...`" + `; real sudo resets PATH
		# to secure_path, which would bypass the stub and hit a host's real
		# incus (making this test pass/fail depending on the machine).
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [ "$1" = "incus" ]; then exec "$@"; fi
exit 0
STUB
		chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"

		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		ensure_incus_initialized
		echo "SHOULD_NOT_REACH"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode == 0 {
		t.Errorf("expected non-zero exit on query failure, got 0; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "SHOULD_NOT_REACH") {
		t.Errorf("function should have returned non-zero; stdout: %s", stdout)
	}
	// Should warn about inability to query, NOT attempt init
	if !strings.Contains(stdout, "Unable to determine") {
		t.Errorf("expected query failure warning, got: %s", stdout)
	}
	if strings.Contains(stdout, "has not been initialized") {
		t.Errorf("should NOT attempt init when query fails; stdout: %s", stdout)
	}
}

// Verify that `incus storage create` output is captured (not printed to terminal)
// on success.
func TestInstallSh_SetupZfsStorage_SuppressesOutputOnSuccess(t *testing.T) {
	script := installShPath(t)

	// Stub incus and sudo to simulate successful storage + profile setup.
	// The key test: sudo incus storage create prints a hint that should NOT
	// appear in output.
	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage list"* ]]; then
	# No zfs-pool exists yet
	echo ""
	exit 0
fi
if [[ "$*" == *"profile device set"* ]]; then
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage create"* ]]; then
	echo "If this is your first time running Incus, you should also run: incus admin init"
	exit 0
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"

		cat > "$tmpdir/zfs" <<'STUB'
#!/bin/bash
exit 0
STUB
		chmod +x "$tmpdir/zfs"

		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_zfs_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// The raw Incus hint should NOT appear in output
	if strings.Contains(stdout, "first time running Incus") {
		t.Errorf("raw Incus hint should be suppressed on success, got: %s", stdout)
	}
	// Success messages should appear
	if !strings.Contains(stdout, "ZFS storage pool created") {
		t.Errorf("expected success message, got: %s", stdout)
	}
}

// unameStub returns a bash snippet fragment that puts a `uname` stub on PATH
// reporting the given kernel release for `uname -r` and delegating everything
// else to the real binary. `tmpdir` must already be set and on PATH.
func unameStub(release string) string {
	return `
		cat > "$tmpdir/uname" <<STUB
#!/bin/bash
if [[ "\$*" == *"-r"* ]]; then
	echo "` + release + `"
	exit 0
fi
exec /usr/bin/uname "\$@"
STUB
		chmod +x "$tmpdir/uname"
	`
}

// is_orbstack keys off the kernel release, the same signal
// internal/vmhost/vmhost.go uses. OrbStack's release string contains "orbstack".
func TestInstallSh_IsOrbstack_DetectsKernelRelease(t *testing.T) {
	script := installShPath(t)

	cases := []struct {
		name    string
		release string
		want    string
	}{
		{"orbstack kernel", "7.0.11-orbstack-00360-gc9bc4d96ac70", "ORBSTACK=yes"},
		{"orbstack uppercase", "7.0.11-OrbStack-00360", "ORBSTACK=yes"},
		{"stock ubuntu kernel", "6.8.0-51-generic", "ORBSTACK=no"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snippet := `
				tmpdir=$(mktemp -d)
				trap "rm -rf $tmpdir" EXIT
			` + unameStub(tc.release) + `
				export PATH="$tmpdir:$PATH"
				export NONINTERACTIVE=1
				source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
				if is_orbstack; then echo "ORBSTACK=yes"; else echo "ORBSTACK=no"; fi
			`
			stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
			if exitCode != 0 {
				t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("expected %s for release %q, got: %s", tc.want, tc.release, strings.TrimSpace(stdout))
			}
		})
	}
}

// storageStubs returns a bash snippet fragment stubbing incus/sudo/zfs/mkfs.btrfs
// for storage setup tests. zfsCreateExit controls whether the ZFS pool creation
// succeeds; btrfs pool creation always succeeds. `tmpdir` must already be set.
func storageStubs(zfsCreateExit int) string {
	return `
		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage list"* ]]; then
	# No pools exist yet
	echo ""
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		cat > "$tmpdir/sudo" <<STUB
#!/bin/bash
if [[ "\$*" == *"storage create"* && "\$*" == *" zfs "* ]]; then
	echo "Error: Failed to create storage pool: modprobe: FATAL: Module zfs not found"
	exit ` + strconv.Itoa(zfsCreateExit) + `
fi
if [[ "\$*" == *"storage create"* ]]; then
	exit 0
fi
# Forward sudo-incus calls (storage list, profile device set, ...) to the
# PATH-mocked incus; install.sh now sudo-runs them (#823).
if [ "\$1" = "incus" ]; then exec "\$@"; fi
exec /usr/bin/sudo "\$@"
STUB
		chmod +x "$tmpdir/sudo"

		# Userspace tools present — mirrors the OrbStack case, where zfsutils-linux
		# installs fine but the kernel module does not exist.
		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/zfs"
		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/mkfs.btrfs"
		chmod +x "$tmpdir/zfs" "$tmpdir/mkfs.btrfs"
	`
}

// On OrbStack, ZFS can never work (no kernel headers or module tree), so
// setup_fast_storage should skip it entirely with an explanatory message and set
// up btrfs instead.
func TestInstallSh_SetupFastStorage_SkipsZfsOnOrbStack(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT
	` + unameStub("7.0.11-orbstack-00360-gc9bc4d96ac70") + storageStubs(0) + `
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_fast_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// ZFS should not even be attempted
	if strings.Contains(stdout, "Setting up fast storage (ZFS)") {
		t.Errorf("ZFS setup should be skipped on OrbStack, got: %s", stdout)
	}
	if !strings.Contains(stdout, "not supported on OrbStack") {
		t.Errorf("expected an explanation of why ZFS was skipped, got: %s", stdout)
	}
	if !strings.Contains(stdout, "btrfs storage pool created") {
		t.Errorf("expected btrfs pool to be created, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Default profile configured for btrfs") {
		t.Errorf("expected default profile to point at the btrfs pool, got: %s", stdout)
	}
}

// On a non-OrbStack host where ZFS is tried but the pool cannot be created
// (module missing, unsupported kernel), setup_fast_storage should fall back to
// btrfs rather than leaving containers on `dir`.
func TestInstallSh_SetupFastStorage_FallsBackToBtrfsWhenZfsFails(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT
	` + unameStub("6.8.0-51-generic") + storageStubs(1) + `
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_fast_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// ZFS is attempted first on a non-OrbStack host
	if !strings.Contains(stdout, "Setting up fast storage (ZFS)") {
		t.Errorf("expected ZFS to be attempted first, got: %s", stdout)
	}
	// The underlying reason should be surfaced, not swallowed
	if !strings.Contains(stdout, "Module zfs not found") {
		t.Errorf("expected the ZFS failure reason to be shown, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Falling back to btrfs") {
		t.Errorf("expected a btrfs fallback message, got: %s", stdout)
	}
	if !strings.Contains(stdout, "btrfs storage pool created") {
		t.Errorf("expected btrfs pool to be created, got: %s", stdout)
	}
	// Containers should not be left on the slow default pool
	if strings.Contains(stdout, "Containers will use default storage") {
		t.Errorf("btrfs succeeded, so the default-storage warning should not appear: %s", stdout)
	}
}

// An existing btrfs-pool should be left alone rather than re-created.
func TestInstallSh_SetupBtrfsStorage_SkipsWhenPoolExists(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage list"* ]]; then
	echo "btrfs-pool,btrfs,,,1,CREATED"
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage create"* ]]; then
	echo "SHOULD_NOT_CREATE"
	exit 0
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"

		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/mkfs.btrfs"
		chmod +x "$tmpdir/mkfs.btrfs"

		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_btrfs_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	if strings.Contains(stdout, "SHOULD_NOT_CREATE") {
		t.Errorf("existing btrfs-pool should not be re-created, got: %s", stdout)
	}
	if !strings.Contains(stdout, "btrfs storage pool already configured") {
		t.Errorf("expected already-configured message, got: %s", stdout)
	}
}

// restart_incus must wait for the daemon to accept connections again (via
// `incus admin waitready`) AFTER restarting the service, so callers that issue
// `incus` commands right after don't race the API socket coming back up.
func TestInstallSh_RestartIncus_WaitsReadyAfterRestart(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"systemctl restart incus"* ]]; then
	echo "STEP:RESTART"
	exit 0
fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"admin waitready"* ]]; then
	echo "STEP:WAITREADY"
	exit 0
fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		restart_incus
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	restart := strings.Index(stdout, "STEP:RESTART")
	waitready := strings.Index(stdout, "STEP:WAITREADY")
	if restart < 0 {
		t.Errorf("expected the service to be restarted, got: %s", stdout)
	}
	if waitready < 0 {
		t.Errorf("expected `incus admin waitready` to run after restart, got: %s", stdout)
	}
	if restart >= 0 && waitready >= 0 && waitready < restart {
		t.Errorf("waitready must run AFTER the restart; got restart@%d waitready@%d\n%s",
			restart, waitready, stdout)
	}
}

// On the btrfs fresh-install path, Incus is restarted to pick up the newly
// installed driver; the daemon must be waited on before the pool is created, or
// the create races the socket. Forces the install branch by excluding
// /usr/sbin (where mkfs.btrfs lives) from PATH, then asserts the ordering
// restart -> waitready -> create.
func TestInstallSh_SetupBtrfsStorage_WaitsReadyBeforeCreatingPool(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT

		# systemctl is-active --quiet incus.service -> active, so the restart runs.
		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/systemctl"
		chmod +x "$tmpdir/systemctl"

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
if [[ "$*" == *"apt-get install"* ]]; then exit 0; fi
if [[ "$*" == *"systemctl restart incus"* ]]; then echo "STEP:RESTART"; exit 0; fi
if [[ "$*" == *"storage create"* ]]; then exit 0; fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"

		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"admin waitready"* ]]; then echo "STEP:WAITREADY"; exit 0; fi
if [[ "$*" == *"storage list"* ]]; then echo ""; exit 0; fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		# No mkfs.btrfs stub, and /usr/sbin dropped from PATH, so command -v fails
		# and the install+restart branch runs. Keep coreutils (/usr/bin,/bin).
		export PATH="$tmpdir:/usr/bin:/bin"
		export PKG_MANAGER=apt
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_btrfs_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// The pool-create command's output is captured into a variable, so use the
	// message printed immediately before it as the "create attempted" marker.
	restart := strings.Index(stdout, "STEP:RESTART")
	waitready := strings.Index(stdout, "STEP:WAITREADY")
	create := strings.Index(stdout, "Creating btrfs storage pool")
	if restart < 0 || waitready < 0 || create < 0 {
		t.Fatalf("expected restart, waitready and pool-create to all happen; "+
			"got restart@%d waitready@%d create@%d\n%s", restart, waitready, create, stdout)
	}
	if restart >= waitready || waitready >= create {
		t.Errorf("expected order restart < waitready < create; "+
			"got restart@%d waitready@%d create@%d\n%s", restart, waitready, create, stdout)
	}
	if !strings.Contains(stdout, "btrfs storage pool created") {
		t.Errorf("expected the btrfs pool to be created; stdout: %s", stdout)
	}
}

// zfsAbsentStubs installs the binary stubs shared by the setup_fast_storage
// tests where ZFS must appear ABSENT: an `incus` stub (no pools exist yet), a
// `sudo` stub that flags any ZFS package install (so a test can assert it never
// happens) while letting `storage create` and the apt-get install succeed, and a
// present `mkfs.btrfs` so the btrfs path can complete. There is deliberately no
// `zfs` stub — callers must also restrict PATH to `"$tmpdir:/usr/bin:/bin"` so a
// real /usr/sbin/zfs on the runner is not picked up.
func zfsAbsentStubs() string {
	return `
		cat > "$tmpdir/incus" <<'STUB'
#!/bin/bash
if [[ "$*" == *"storage list"* ]]; then echo ""; exit 0; fi
exit 0
STUB
		chmod +x "$tmpdir/incus"

		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
# Flag any package install that mentions zfs so a test can assert it never runs
# (and stand in for a successful apt-get install of zfsutils-linux on apt).
if [[ "$*" == *"install"* && "$*" == *"zfs"* ]] || [[ "$*" == *"pacman"* && "$*" == *"zfs"* ]]; then
	echo "ZFS_INSTALL_ATTEMPTED"
	exit 0
fi
if [[ "$*" == *"storage create"* ]]; then exit 0; fi
# Forward sudo-incus calls to the PATH-mocked incus (install.sh now sudo-runs
# incus queries/config; real sudo would lose the test PATH). #823.
if [ "$1" = "incus" ]; then exec "$@"; fi
exec /usr/bin/sudo "$@"
STUB
		chmod +x "$tmpdir/sudo"

		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/mkfs.btrfs"
		chmod +x "$tmpdir/mkfs.btrfs"
	`
}

// #666: on a non-apt distro (e.g. Arch/EndeavourOS) where ZFS is not installed,
// the installer must NOT auto-install it — pulling in the ZFS packages there can
// trigger a dracut/initramfs rebuild that breaks the system. It must use btrfs
// (in-kernel, safe) instead. Reproduces the reporter's case (btrfs available).
func TestInstallSh_SetupFastStorage_SkipsZfsInstallOnNonApt(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT
	` + unameStub("6.12.4-arch1-1") + zfsAbsentStubs() + `
		# ZFS absent: no zfs stub, and /usr/sbin (where a real zfs would live) is
		# dropped from PATH. btrfs tools present (mkfs.btrfs stub).
		export PATH="$tmpdir:/usr/bin:/bin"
		export PKG_MANAGER=pacman
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_fast_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	// The regression guard: ZFS must never be installed on a non-apt distro.
	if strings.Contains(stdout, "ZFS_INSTALL_ATTEMPTED") {
		t.Errorf("ZFS must not be auto-installed on a non-apt distro (#666), got: %s", stdout)
	}
	if strings.Contains(stdout, "Installing ZFS") {
		t.Errorf("ZFS should not be installed, got: %s", stdout)
	}
	if strings.Contains(stdout, "Setting up fast storage (ZFS)") {
		t.Errorf("ZFS setup should be skipped when absent on a non-apt distro, got: %s", stdout)
	}
	// btrfs is used instead.
	if !strings.Contains(stdout, "using btrfs") {
		t.Errorf("expected the 'using btrfs' message, got: %s", stdout)
	}
	if !strings.Contains(stdout, "btrfs storage pool created") {
		t.Errorf("expected the btrfs pool to be created, got: %s", stdout)
	}
}

// On apt (Debian/Ubuntu) the ZFS install is a clean userspace op, so it is still
// auto-installed and used — the fast path is preserved where it's safe.
func TestInstallSh_SetupFastStorage_InstallsZfsOnApt(t *testing.T) {
	script := installShPath(t)

	snippet := `
		tmpdir=$(mktemp -d)
		trap "rm -rf $tmpdir" EXIT
	` + unameStub("6.8.0-51-generic") + zfsAbsentStubs() + `
		# ZFS absent so the (apt-only) install path runs; /usr/sbin dropped.
		export PATH="$tmpdir:/usr/bin:/bin"
		export PKG_MANAGER=apt
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_fast_storage
		echo "COMPLETED"
	`
	stdout, _, exitCode := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "COMPLETED") {
		t.Errorf("function did not complete; stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "Setting up fast storage (ZFS)") {
		t.Errorf("ZFS should be attempted on apt, got: %s", stdout)
	}
	if !strings.Contains(stdout, "ZFS storage pool created") {
		t.Errorf("ZFS pool should be created on apt, got: %s", stdout)
	}
}

// setup_nm_unmanaged_veths (#695) must install the veth exclusion when the NM
// conf dir exists, be idempotent, respect a pre-existing user rule covering
// veths, and no-op entirely when NetworkManager is absent. sudo/systemctl are
// stubbed to plain execution/no-ops so the real system is never touched.
func TestInstallSh_NMUnmanagedVeths(t *testing.T) {
	script := installShPath(t)
	confDir := t.TempDir()
	snippet := func(dir string) string {
		return `
			sudo() { "$@"; }        # run without privileges
			systemctl() { :; }      # never reload anything real
			source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
			COI_NM_CONF_DIR="` + dir + `" setup_nm_unmanaged_veths
		`
	}

	// 1. Fresh dir: file gets written.
	_, stderr, code := runBashSnippet(t, snippet(confDir))
	if code != 0 {
		t.Fatalf("setup failed: %s", stderr)
	}
	conf := filepath.Join(confDir, "99-coi-unmanaged.conf")
	data, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("conf file not written: %v", err)
	}
	// += appends to any user-set list (plain = would replace it under
	// NM's last-file-wins conf.d semantics).
	if !strings.Contains(string(data), "unmanaged-devices+=interface-name:veth*") {
		t.Errorf("conf missing the veth exclusion: %s", data)
	}

	// 2. Idempotent: second run leaves the file alone and succeeds.
	if _, stderr, code = runBashSnippet(t, snippet(confDir)); code != 0 {
		t.Fatalf("second run failed: %s", stderr)
	}

	// 3. Pre-existing user rule covering veths: no coi file is added.
	userDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(userDir, "50-user.conf"),
		[]byte("[keyfile]\nunmanaged-devices=interface-name:veth*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code = runBashSnippet(t, snippet(userDir)); code != 0 {
		t.Fatalf("user-rule run failed: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(userDir, "99-coi-unmanaged.conf")); err == nil {
		t.Error("coi conf must not be written when a user rule already covers veths")
	}

	// 4. NM absent (dir missing): silent no-op.
	if _, stderr, code = runBashSnippet(t, snippet(filepath.Join(confDir, "nope"))); code != 0 {
		t.Fatalf("absent-dir run should no-op, got: %s", stderr)
	}

	// 5. A COMMENTED-OUT veth rule must not suppress the real one.
	commentedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(commentedDir, "50-user.conf"),
		[]byte("[keyfile]\n#unmanaged-devices=interface-name:veth*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code = runBashSnippet(t, snippet(commentedDir)); code != 0 {
		t.Fatalf("commented-rule run failed: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(commentedDir, "99-coi-unmanaged.conf")); err != nil {
		t.Error("a commented-out user rule must not suppress installing the active exclusion")
	}

	// 6. COI_SKIP_NM_UNMANAGED=1 opts out entirely.
	skipDir := t.TempDir()
	if _, stderr, code = runBashSnippet(t, "COI_SKIP_NM_UNMANAGED=1\n"+snippet(skipDir)); code != 0 {
		t.Fatalf("skip-env run failed: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(skipDir, "99-coi-unmanaged.conf")); err == nil {
		t.Error("COI_SKIP_NM_UNMANAGED=1 must prevent the drop-in")
	}
}

// --- P2: unit coverage for the install-flow functions added recently ---------
// These source the real install.sh (main/ERR-trap stripped) and mock system
// commands via PATH stubs, the same idiom as the tests above. No Incus/root.

// pool_size_gib: half the disk backing /var/lib/incus, with a 50GiB floor.
func TestInstallSh_PoolSizeGib_HalfWithFloor(t *testing.T) {
	script := installShPath(t)
	run := func(totalKiB string) string {
		snippet := `
			tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
			cat > "$tmpdir/df" <<'STUB'
#!/bin/bash
echo "Filesystem 1024-blocks Used Available Capacity Mounted"
echo "/dev/x $FAKE_TOTAL_KIB 0 $FAKE_TOTAL_KIB 0% /"
STUB
			chmod +x "$tmpdir/df"
			export PATH="$tmpdir:$PATH"
			export NONINTERACTIVE=1
			source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
			pool_size_gib
		`
		out, _, code := runBashSnippet(t, snippet, "NONINTERACTIVE=1", "FAKE_TOTAL_KIB="+totalKiB)
		if code != 0 {
			t.Fatalf("pool_size_gib exited %d; out: %s", code, out)
		}
		return strings.TrimSpace(out)
	}
	// 200 GiB -> 100; 500 GiB -> 250; 80 GiB -> 50 (floor); unknown -> 50.
	cases := map[string]string{
		"209715200": "100",
		"524288000": "250",
		"83886080":  "50",
		"":          "50",
	}
	for kib, want := range cases {
		if got := run(kib); got != want {
			t.Errorf("total=%qKiB: pool_size_gib=%q, want %q", kib, got, want)
		}
	}
}

// install_incus_zabbly: writes the Zabbly apt source (with the host codename)
// and installs incus. All privileged calls go through a recording sudo shim.
func TestInstallSh_InstallIncusZabbly_WritesSourceAndInstalls(t *testing.T) {
	script := installShPath(t)
	snippet := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		export SOURCES_OUT="$tmpdir/sources.out"
		# sudo shim: record args; for a tee call, capture stdin; curl/apt succeed.
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
echo "$*" >> "$SUDO_LOG"
case "$1" in
  tee)  cat > "$SOURCES_OUT" ;;   # capture the .sources body
  *)    : ;;                      # curl / mkdir / apt-get -> no-op success
esac
exit 0
STUB
		chmod +x "$tmpdir/sudo"
		# dpkg stub so arch resolves deterministically
		printf '#!/bin/bash\necho amd64\n' > "$tmpdir/dpkg"; chmod +x "$tmpdir/dpkg"
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		install_incus_zabbly
		echo "===RC=$?==="
		echo "===SOURCES==="; cat "$SOURCES_OUT"
		echo "===SUDO==="; cat "$SUDO_LOG"
	`
	out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if !strings.Contains(out, "===RC=0===") {
		t.Fatalf("install_incus_zabbly should succeed; out:\n%s", out)
	}
	if !strings.Contains(out, "URIs: https://pkgs.zabbly.com/incus/stable") {
		t.Errorf("Zabbly source not written correctly; out:\n%s", out)
	}
	if !strings.Contains(out, "apt-get install -y incus") {
		t.Errorf("expected `apt-get install -y incus`; out:\n%s", out)
	}
}

// check_group: with consent (COI_ASSUME_YES in non-interactive), a user not in
// the group is added via usermod; declining prints the manual instruction.
func TestInstallSh_CheckGroup_AddsOnConsent(t *testing.T) {
	script := installShPath(t)
	base := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		printf '#!/bin/bash\necho "$*" >> "$SUDO_LOG"; exit 0\n' > "$tmpdir/sudo"; chmod +x "$tmpdir/sudo"
		# groups stub: user is NOT in incus-admin
		printf '#!/bin/bash\necho "user sudo"\n' > "$tmpdir/groups"; chmod +x "$tmpdir/groups"
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		check_group
		echo "===SUDO==="; cat "$SUDO_LOG"
	`
	// Consent granted.
	out, _, _ := runBashSnippet(t, base, "NONINTERACTIVE=1", "COI_ASSUME_YES=1")
	if !strings.Contains(out, "usermod -aG incus-admin") {
		t.Errorf("with consent, check_group should run usermod; out:\n%s", out)
	}
	// Consent withheld (no COI_ASSUME_YES): no usermod runs, manual guidance shown.
	out, _, _ = runBashSnippet(t, base, "NONINTERACTIVE=1")
	sudoLog := out
	if i := strings.Index(out, "===SUDO==="); i >= 0 {
		sudoLog = out[i:]
	}
	if strings.Contains(sudoLog, "usermod") {
		t.Errorf("without consent, check_group must not run usermod; out:\n%s", out)
	}
	if !strings.Contains(out, "Add yourself with") {
		t.Errorf("without consent, expected manual guidance; out:\n%s", out)
	}
}

// setup_nft_sudoers: with consent, writes /etc/sudoers.d/coi-nft; declining
// skips it and prints how to enable it later.
func TestInstallSh_SetupNftSudoers_ConsentAndDecline(t *testing.T) {
	script := installShPath(t)
	base := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		export NFT_LINE="$tmpdir/nft.line"
		cat > "$tmpdir/sudo" <<'STUB'
#!/bin/bash
echo "$*" >> "$SUDO_LOG"
# install_sudoers_dropin runs: sudo sh -c SCRIPT sh RULE TARGET
case "$1" in
  sh)   printf '%s\n' "$5" > "$NFT_LINE" ;;
  *)    : ;;
esac
exit 0
STUB
		chmod +x "$tmpdir/sudo"
		# nft present, and the coi-nft drop-in absent (checked by absolute path)
		printf '#!/bin/bash\nexit 0\n' > "$tmpdir/nft"; chmod +x "$tmpdir/nft"
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		setup_nft_sudoers
		echo "===NFT==="; cat "$NFT_LINE" 2>/dev/null
	`
	// Consent: writes the NOPASSWD line for nft.
	out, _, _ := runBashSnippet(t, base, "NONINTERACTIVE=1", "COI_ASSUME_YES=1")
	if !strings.Contains(out, "NOPASSWD:") || !strings.Contains(out, "nft") {
		t.Errorf("with consent, setup_nft_sudoers should write the NOPASSWD nft rule; out:\n%s", out)
	}
	// The user is named by numeric UID: a username with a space is a sudoers
	// syntax error that would break every sudo on the host.
	if !strings.Contains(out, fmt.Sprintf("#%d ALL=(ALL) NOPASSWD:", os.Getuid())) {
		t.Errorf("sudoers rule should name the user by #uid; out:\n%s", out)
	}
	// Decline: skip + guidance, no drop-in written.
	out, _, _ = runBashSnippet(t, base, "NONINTERACTIVE=1")
	if !strings.Contains(out, "Skipped") {
		t.Errorf("without consent, setup_nft_sudoers should skip with a message; out:\n%s", out)
	}
}

// restore_incus_config_ownership: chowns ~/.config/incus back to the user when
// present, and is a no-op when it isn't.
func TestInstallSh_RestoreIncusConfigOwnership(t *testing.T) {
	script := installShPath(t)
	snippet := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		printf '#!/bin/bash\necho "$*" >> "$SUDO_LOG"; exit 0\n' > "$tmpdir/sudo"; chmod +x "$tmpdir/sudo"
		export HOME="$tmpdir/home"; export USER="tester"
		mkdir -p "$HOME/.config/incus"
		echo "x" > "$HOME/.config/incus/config.yml"
		# getent/id stubs so the fake user resolves to our temp home + a group
		printf '#!/bin/bash\necho "tester:x:1000:1000::%s:/bin/bash"\n' "$HOME" > "$tmpdir/getent"; chmod +x "$tmpdir/getent"
		printf '#!/bin/bash\necho tester\n' > "$tmpdir/id"; chmod +x "$tmpdir/id"
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		restore_incus_config_ownership
		echo "===SUDO==="; cat "$SUDO_LOG"
	`
	out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if !strings.Contains(out, "chown -R tester:") || !strings.Contains(out, ".config/incus") {
		t.Errorf("expected chown of ~/.config/incus back to the user; out:\n%s", out)
	}
}

// ensure_build_deps: no-op when git+make+gcc are present; declining consent
// exits non-zero with a clear message.
func TestInstallSh_EnsureBuildDeps_PresentIsNoop(t *testing.T) {
	script := installShPath(t)
	snippet := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		printf '#!/bin/bash\necho "$*" >> "$SUDO_LOG"; exit 0\n' > "$tmpdir/sudo"; chmod +x "$tmpdir/sudo"
		# all three tools present
		for t in git make gcc cc; do printf '#!/bin/bash\nexit 0\n' > "$tmpdir/$t"; chmod +x "$tmpdir/$t"; done
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		declare -f ensure_build_deps >/dev/null || { echo "===SKIP==="; exit 0; }
		ensure_build_deps
		echo "===RC=$?==="; echo "===SUDO==="; cat "$SUDO_LOG"
	`
	out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	if strings.Contains(out, "===SKIP===") {
		t.Skip("ensure_build_deps not present on this branch (lands with the build-deps PR)")
	}
	if !strings.Contains(out, "===RC=0===") {
		t.Fatalf("ensure_build_deps should be a no-op when tools present; out:\n%s", out)
	}
	if strings.Contains(out, "install") {
		t.Errorf("no install expected when tools present; out:\n%s", out)
	}
}

// On apt, ensure_build_deps must refresh the package lists before installing:
// fresh container/minimal images ship with empty lists, so a bare
// ` + "`apt-get install`" + ` fails "Unable to locate package". A failed install must
// still reach the actionable "Building from source needs:" message instead of
// tripping set -e / the generic ERR trap.
func TestInstallSh_EnsureBuildDeps_AptUpdatesBeforeInstall(t *testing.T) {
	script := installShPath(t)
	snippet := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		# sudo stub: log every call; the install itself fails (as on an image
		# whose lists couldn't be refreshed) and installs nothing.
		printf '#!/bin/bash\necho "$*" >> "$SUDO_LOG"\n[[ "$*" == *" install "* ]] && exit 100\nexit 0\n' > "$tmpdir/sudo"
		chmod +x "$tmpdir/sudo"
		export NONINTERACTIVE=1 COI_ASSUME_YES=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		PKG_MANAGER=apt
		# Restrict PATH so git/make/gcc are genuinely absent.
		PATH="$tmpdir"
		# Bare subshell keeps install.sh's set -e live inside it (an || list
		# would disable it); set +e only so the parent survives the exit.
		set +e; ( set -e; ensure_build_deps ); rc=$?
		echo "===RC=$rc==="; echo "===SUDO==="; /bin/cat "$SUDO_LOG"
	`
	out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	idxUpdate := strings.Index(out, "apt-get update")
	idxInstall := strings.Index(out, "apt-get install -y git build-essential")
	if idxUpdate < 0 || idxInstall < 0 || idxUpdate > idxInstall {
		t.Errorf("expected apt-get update before apt-get install; out:\n%s", out)
	}
	if !strings.Contains(out, "Building from source needs:") {
		t.Errorf("failed install should reach the actionable message; out:\n%s", out)
	}
	if strings.Contains(out, "===RC=0===") {
		t.Errorf("expected non-zero exit when deps are still missing; out:\n%s", out)
	}
}

// pkg_install on apt refreshes the lists exactly once per run.
func TestInstallSh_PkgInstall_AptUpdatesOnce(t *testing.T) {
	script := installShPath(t)
	snippet := `
		tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
		export SUDO_LOG="$tmpdir/sudo.log"; : > "$SUDO_LOG"
		printf '#!/bin/bash\necho "$*" >> "$SUDO_LOG"; exit 0\n' > "$tmpdir/sudo"; chmod +x "$tmpdir/sudo"
		export PATH="$tmpdir:$PATH"
		export NONINTERACTIVE=1
		source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
		PKG_MANAGER=apt
		pkg_install foo
		pkg_install bar
		cat "$SUDO_LOG"
	`
	out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
	want := "apt-get update -qq\napt-get install -y foo\napt-get install -y bar\n"
	if out != want {
		t.Errorf("unexpected sudo calls:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// install_sudoers_dropin validates the rule with visudo before it can reach the
// target: a rejected rule leaves the existing drop-in untouched and no temp file
// behind (a broken file in /etc/sudoers.d disables sudo host-wide); an accepted
// one lands with mode 0440.
func TestInstallSh_InstallSudoersDropin_ValidatesBeforeInstall(t *testing.T) {
	script := installShPath(t)
	run := func(visudoExit int) string {
		snippet := `
			tmpdir=$(mktemp -d); trap "rm -rf $tmpdir" EXIT
			mkdir "$tmpdir/bin" "$tmpdir/sudoers.d"
			# sudo stub runs the command unprivileged; visudo stub accepts/rejects.
			printf '#!/bin/bash\nexec "$@"\n' > "$tmpdir/bin/sudo"
			printf '#!/bin/sh\nexit ` + fmt.Sprint(visudoExit) + `\n' > "$tmpdir/bin/visudo"
			chmod +x "$tmpdir/bin/sudo" "$tmpdir/bin/visudo"
			export PATH="$tmpdir/bin:$PATH"
			echo previous > "$tmpdir/sudoers.d/coi-nft"
			export NONINTERACTIVE=1
			source <(sed '/^main "\$@"/d; /^trap error_handler ERR/d' "` + script + `")
			set +e
			install_sudoers_dropin "#1000 ALL=(ALL) NOPASSWD: /usr/sbin/nft" "$tmpdir/sudoers.d/coi-nft"
			echo "===RC=$?==="
			echo "===CONTENT==="; cat "$tmpdir/sudoers.d/coi-nft"
			echo "===MODE=$(stat -c %a "$tmpdir/sudoers.d/coi-nft")==="
			echo "===FILES=$(ls -A "$tmpdir/sudoers.d" | wc -l)==="
		`
		out, _, _ := runBashSnippet(t, snippet, "NONINTERACTIVE=1")
		return out
	}

	out := run(1)
	if !strings.Contains(out, "===RC=1===") {
		t.Errorf("rejected rule must fail; out:\n%s", out)
	}
	if !strings.Contains(out, "===CONTENT===\nprevious\n") {
		t.Errorf("rejected rule must leave the existing drop-in untouched; out:\n%s", out)
	}
	if !strings.Contains(out, "===FILES=1===") {
		t.Errorf("rejected rule must not leave a temp file behind; out:\n%s", out)
	}

	out = run(0)
	if !strings.Contains(out, "===RC=0===") {
		t.Errorf("valid rule must install; out:\n%s", out)
	}
	if !strings.Contains(out, "===CONTENT===\n#1000 ALL=(ALL) NOPASSWD: /usr/sbin/nft\n") {
		t.Errorf("valid rule not written to target; out:\n%s", out)
	}
	if !strings.Contains(out, "===MODE=440===") || !strings.Contains(out, "===FILES=1===") {
		t.Errorf("valid rule must land with mode 0440 and no temp file; out:\n%s", out)
	}
}
