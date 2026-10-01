package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/coipond/coi/internal/timing"
	"golang.org/x/sys/unix"
)

// incusBinary is the incus executable name, resolved from $PATH by exec.Command.
const incusBinary = "incus"

var (
	CodeUID      = 1000
	CodeUser     = "code"
	IncusProject = "default"
)

// Configure sets the package-level Incus configuration variables.
// This should be called after loading the config file to apply user settings.
func Configure(project, codeUser string, codeUID int) {
	IncusProject = project
	CodeUser = codeUser
	CodeUID = codeUID
}

// execIncusCommand creates an exec.Cmd that runs the incus binary directly with
// the given argv (no intermediate shell). The user must be in the incus-admin
// group in their current session (log out / log back in after usermod -aG).
func execIncusCommand(argv []string) *exec.Cmd {
	return exec.Command(incusBinary, argv...)
}

// execIncusCommandContext creates a context-aware exec.Cmd that runs the incus
// binary directly with the given argv (no intermediate shell).
//
// WaitDelay is set so that when the context is cancelled, cmd.Wait returns
// promptly instead of blocking until all child-process pipes are closed.
func execIncusCommandContext(ctx context.Context, argv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, incusBinary, argv...)
	cmd.WaitDelay = time.Second
	return cmd
}

// runIncus runs an incus subprocess, recording its wall time when COI_TIMING_DEBUG is
// set. Every incus invocation in this package goes through here (or
// outputIncus) so the timing report accounts for all subprocess time without
// each call site having to opt in.
func runIncus(cmd *exec.Cmd) error {
	defer timing.Start(timing.CatIncus, incusLabel(cmd))()
	return cmd.Run()
}

// outputIncus is runIncus for the CombinedOutput form.
func outputIncus(cmd *exec.Cmd) ([]byte, error) {
	defer timing.Start(timing.CatIncus, incusLabel(cmd))()
	return cmd.CombinedOutput()
}

// incusLabel is the timing label for a command built by buildIncusCommand: the
// argv joined with spaces and the constant "incus --project <project>" prefix
// stripped, so the report shows "init <image> <name>" rather than the noise.
func incusLabel(cmd *exec.Cmd) string {
	if !timing.Enabled() || len(cmd.Args) == 0 {
		return ""
	}
	// Drop the leading "incus --project <project>" that buildIncusCommand adds;
	// anything else (a direct exec.Command) keeps its full argv.
	args := cmd.Args
	if len(args) >= 3 && args[0] == incusBinary && args[1] == "--project" && args[2] == IncusProject {
		args = args[3:]
	}
	return strings.Join(args, " ")
}

// IncusExecContext executes an Incus command with context support
func IncusExecContext(ctx context.Context, args ...string) error {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, cmdArgs)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return runIncus(cmd)
}

// IncusExec executes an Incus command
func IncusExec(args ...string) error {
	return IncusExecContext(context.Background(), args...)
}

// IncusExecInteractive executes an Incus command with stdin/stdout/stderr attached
func IncusExecInteractive(args ...string) error {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommand(cmdArgs)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return runIncus(cmd)
}

// IncusExecQuietContext runs an Incus command without writing to the terminal,
// but still reports WHY it failed.
//
// "Quiet" previously meant discarding stderr outright, so a failure surfaced as
// a bare "exit status 1" with the cause thrown away — `coi kill` could only tell
// you "Failed to delete <container>: exit status 1", which is not something
// anyone can act on. Incus's message is captured and attached to the error
// instead; callers that want silence get silence, callers that hit an error get
// the reason.
func IncusExecQuietContext(ctx context.Context, args ...string) error {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, cmdArgs)

	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr

	if err := runIncus(cmd); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return ClassifyIncusErr(err, msg)
	}
	return nil
}

// IncusExecQuiet executes an Incus command silently (suppress stdout/stderr)
func IncusExecQuiet(args ...string) error {
	return IncusExecQuietContext(context.Background(), args...)
}

// ImportImage imports a container image into Incus from a metadata tarball and
// a rootfs squashfs file, assigning the given alias.
// Equivalent to: incus --project <project> image import <lxdTar> <squashfs> --alias <alias>
func ImportImage(lxdTar, squashfs, alias string) error {
	cmdStr := buildIncusCommand("image", "import", lxdTar, squashfs, "--alias", alias)
	cmd := execIncusCommand(cmdStr)
	if out, err := outputIncus(cmd); err != nil {
		return fmt.Errorf("incus image import failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IncusOutputContext executes an Incus command with context support and returns the output (trimmed)
// toExitError wraps a failed incus command's error as *ExitError when it is an
// *exec.ExitError (capturing the exit code and the given stderr), and returns
// the original error unchanged otherwise. Pass "" for stderr when none was
// captured separately (e.g. combined stdout+stderr, or streamed output).
func toExitError(err error, stderr string) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return ClassifyIncusErr(&ExitError{ExitCode: exitErr.ExitCode(), Err: err, Stderr: stderr}, stderr)
	}
	return ClassifyIncusErr(err, stderr)
}

func IncusOutputContext(ctx context.Context, args ...string) (string, error) {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, cmdArgs)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := runIncus(cmd)
	output := strings.TrimSpace(stdout.String())

	if err != nil {
		return output, toExitError(err, strings.TrimSpace(stderr.String()))
	}

	return output, nil
}

// IncusOutput executes an Incus command and returns the output (trimmed)
func IncusOutput(args ...string) (string, error) {
	return IncusOutputContext(context.Background(), args...)
}

// IncusOutputRawContext executes an Incus command with context support and returns the output (not trimmed)
func IncusOutputRawContext(ctx context.Context, args ...string) (string, error) {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, cmdArgs)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := runIncus(cmd)
	output := stdout.String()

	if err != nil {
		return output, toExitError(err, strings.TrimSpace(stderr.String()))
	}

	return output, nil
}

// IncusOutputRaw executes an Incus command and returns the output (not trimmed)
func IncusOutputRaw(args ...string) (string, error) {
	return IncusOutputRawContext(context.Background(), args...)
}

// IncusOutputWithStderrContext executes an Incus command with context support and returns combined stdout+stderr
func IncusOutputWithStderrContext(ctx context.Context, args ...string) (string, error) {
	cmdArgs := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, cmdArgs)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	err := runIncus(cmd)
	output := strings.TrimSpace(combined.String())

	if err != nil {
		return output, toExitError(err, "")
	}

	return output, nil
}

// IncusOutputWithStderr executes an Incus command and returns combined stdout+stderr
// This is useful when error messages from Incus need to be inspected (e.g., "already frozen")
func IncusOutputWithStderr(args ...string) (string, error) {
	return IncusOutputWithStderrContext(context.Background(), args...)
}

// IncusOutputWithArgsContext executes incus with raw args and context support (no additional wrapping)
func IncusOutputWithArgsContext(ctx context.Context, args ...string) (string, error) {
	incusCmd := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, incusCmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := runIncus(cmd)
	output := strings.TrimSpace(stdout.String())

	if err != nil {
		return output, toExitError(err, strings.TrimSpace(stderr.String()))
	}

	return output, nil
}

// IncusOutputWithArgs executes incus with raw args (no additional wrapping)
func IncusOutputWithArgs(args ...string) (string, error) {
	return IncusOutputWithArgsContext(context.Background(), args...)
}

// StdinIsTerminal reports whether os.Stdin is connected to a real terminal.
// Uses TIOCGWINSZ rather than ModeCharDevice because /dev/null is also a
// character device on Linux, causing false positives with the stat approach.
func StdinIsTerminal() bool {
	_, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	return err == nil
}

// streamedStdin returns the stdin to attach for a streamed exec: piped or
// redirected input is passed through so `cat data | coi run -- ...` works,
// but an interactive terminal is NOT attached. Attaching a TTY would flip
// `incus exec` into interactive PTY mode (raw terminal, Ctrl+C forwarded into
// the container instead of signaling coi, stdin-reading commands blocking on
// the keyboard instead of seeing EOF, SIGTTIN stops for backgrounded runs);
// leaving it nil preserves the previous /dev/null semantics for TTY runs.
func streamedStdin() *os.File {
	if StdinIsTerminal() {
		return nil
	}
	return os.Stdin
}

// IncusExecStreamedContext executes incus with raw args, streaming the child's
// output directly to the caller's terminal: output appears live (not buffered
// until exit). Piped/redirected stdin is connected (see streamedStdin); an
// interactive terminal is not. The in-container exit code is preserved via
// *ExitError so callers can propagate it. Stderr is not captured (it streams),
// so ExitError.Stderr is empty on this path. On context cancellation the incus
// client gets SIGINT first (a chance to detach cleanly) and is killed only
// after WaitDelay.
func IncusExecStreamedContext(ctx context.Context, args ...string) error {
	incusCmd := buildIncusCommand(args...)
	cmd := execIncusCommandContext(ctx, incusCmd)
	if in := streamedStdin(); in != nil {
		cmd.Stdin = in
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Cancel = func() error {
		// Default Cancel sends SIGKILL; SIGINT lets the incus client wind
		// down (WaitDelay in execIncusCommandContext escalates to kill).
		return cmd.Process.Signal(os.Interrupt)
	}

	err := runIncus(cmd)
	if err != nil {
		return toExitError(err, "")
	}
	return nil
}

// IncusFilePushContext pushes a file into a container with context support
func IncusFilePushContext(ctx context.Context, source, destination string) error {
	cmdArgs := buildIncusCommand("file", "push", source, destination)
	cmd := execIncusCommandContext(ctx, cmdArgs)
	return runIncus(cmd)
}

// IncusFilePush pushes a file into a container
func IncusFilePush(source, destination string) error {
	return IncusFilePushContext(context.Background(), source, destination)
}

// IncusFilePushWithOwnerContext pushes a file into a container with explicit
// ownership and mode applied by the push itself. Without these flags incus
// preserves the SOURCE file's owner and mode (--uid/--gid default to -1), so
// a pushed host temp file lands owned by the host UID with its restrictive
// mode — unreadable by other container users. Pushing with the flags leaves
// no window or failure path where the file exists with the wrong attributes.
func IncusFilePushWithOwnerContext(ctx context.Context, source, destination string, uid, gid int, mode string) error {
	cmdArgs := buildIncusCommand("file", "push",
		"--uid", fmt.Sprintf("%d", uid), "--gid", fmt.Sprintf("%d", gid), "--mode", mode,
		source, destination)
	cmd := execIncusCommandContext(ctx, cmdArgs)
	return runIncus(cmd)
}

// IncusFilePushWithOwner pushes a file into a container with explicit
// ownership and mode.
func IncusFilePushWithOwner(source, destination string, uid, gid int, mode string) error {
	return IncusFilePushWithOwnerContext(context.Background(), source, destination, uid, gid, mode)
}

// startCapture runs `incus start`, capturing stderr into the returned error so
// the start fallbacks can inspect WHY start failed — in particular the idmapped
// ("shift") mount failure some guest kernels raise (#678). Plain IncusExec sends
// stderr straight to the terminal and returns a bare exit error, which can't be
// matched on. `incus start` prints nothing useful on success, so nothing is lost.
func startCapture(containerName string) error {
	return IncusExecQuietContext(context.Background(), "start", containerName)
}

// isIdmapMountUnsupported reports whether err is the failure Incus raises when a
// shift=true (idmapped) disk device can't be materialized because the guest
// kernel lacks idmapped-mount support. Observed on some OrbStack kernels (#678):
// "Failed to setup device mount \"workspace\": idmapping abilities are required
// but aren't supported on system".
func isIdmapMountUnsupported(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "idmapping abilities are required")
}

// shiftEnabledDiskDevices returns the names of the container's disk devices that
// have shift=true set — the ones that would fail on a host without idmapped-mount
// support and need converting to a raw.idmap workspace mapping instead.
func shiftEnabledDiskDevices(containerName string) []string {
	out, err := IncusOutput("config", "device", "list", containerName)
	if err != nil {
		return nil
	}
	var shifted []string
	for _, name := range strings.Fields(out) {
		if typ, _ := IncusOutput("config", "device", "get", containerName, name, "type"); strings.TrimSpace(typ) != "disk" {
			continue
		}
		if sh, _ := IncusOutput("config", "device", "get", containerName, name, "shift"); strings.TrimSpace(sh) == "true" {
			shifted = append(shifted, name)
		}
	}
	return shifted
}

// ConvertShiftedDiskDevices sets shift=false on every shift=true disk device
// of the (stopped) container, reporting how many conversions succeeded and how
// many failed — a failed one leaves raw.idmap combined with a shift=true
// device, which fails the start with an error none of the fallbacks match, so
// callers must not report failure as success. Callers pair it with raw.idmap:
// reactively via fallbackShiftToRawIdmap after a #678 start failure, or
// proactively on reuse when the mapping decision has changed to raw.idmap
// since the container was created (#683 — OrbStack ≥2.2.2 never produces the
// start failure the reactive path keys on, so creation-time shift=true devices
// must be converted before start).
func ConvertShiftedDiskDevices(containerName string) (converted, failed int) {
	for _, d := range shiftEnabledDiskDevices(containerName) {
		if err := IncusExecQuiet("config", "device", "set", containerName, d, "shift=false"); err != nil {
			failed++
			continue
		}
		converted++
	}
	return converted, failed
}

// fallbackShiftToRawIdmap converts every shift=true disk device on the (stopped)
// container to shift=false and sets raw.idmap="both <hostUID> <codeUID>" — the
// exact mapping decideUIDMapping applies for a manual `disable_shift`. This is
// the reactive recovery for a host whose kernel can't do idmapped mounts (#678):
// try shift, and only if start fails on it, drop to raw.idmap. Returns true if it
// changed anything, so the caller knows a retry is worthwhile.
func fallbackShiftToRawIdmap(containerName string) bool {
	converted, failed := ConvertShiftedDiskDevices(containerName)
	if converted+failed == 0 {
		return false
	}
	_ = IncusExecQuiet("config", "set", containerName, "raw.idmap", fmt.Sprintf("both %d %d", os.Getuid(), CodeUID))
	return true
}

// withDisableShiftHint wraps err with actionable guidance for the case where a
// host can't do idmapped mounts and coi's automatic raw.idmap fallback did not
// recover (#678). Callers apply it only when the failure is the idmapping error.
func withDisableShiftHint(err error) error {
	return fmt.Errorf("%w -- this host's kernel can't set up idmapped (\"shift\") mounts and coi's "+
		"automatic raw.idmap fallback did not recover; set `[incus] disable_shift = true` in "+
		"~/.coi/config.toml (or your active profile) to use raw.idmap for the workspace mount instead", err)
}

// startRetryError decides what error a start-retry branch returns. A successful
// retry (nil) returns nil. When the retry also fails, a #678 idmapped-mount
// failure — identified from the ORIGINAL start error — gets the disable_shift
// hint; any other failure is returned unchanged. Shared by the ephemeral
// recreate-after-deletion and the unset-isolation branches so their hint
// routing can't drift (#716). Kept pure so the decision is unit-tested without
// the live-Incus retry paths.
func startRetryError(firstErr, retryErr error) error {
	if retryErr == nil {
		return nil
	}
	if isIdmapMountUnsupported(firstErr) {
		return withDisableShiftHint(retryErr)
	}
	return retryErr
}

// ContainerUsesRawIdmap reports whether the container already has raw.idmap set,
// i.e. its workspace UID mapping is on the non-shift path — either because the
// config asked for it (disable_shift, a host/code UID mismatch) or because
// fallbackShiftToRawIdmap healed it after a #678 start failure. The reuse path
// checks this so a session doesn't re-arm shift=true on a container that has
// already been established as unable to use it (#685).
func ContainerUsesRawIdmap(containerName string) bool {
	out, err := IncusOutput("config", "get", containerName, "raw.idmap")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) != ""
}

// startWithIdmapRecovery is the start sequence shared by every non-ephemeral
// start path: start, poll, retry, and on a #678 idmapped-mount failure convert
// the shift mounts to raw.idmap and retry again. Returns nil once the container
// is running; otherwise the ORIGINAL start error, which is the useful diagnostic
// and what callers match on to decide whether a further fallback applies.
//
// On some hosts (nested containers, CI runners), forkstart exits non-zero even
// though the LXC process started successfully, so ContainerRunning is polled for
// up to 5 s before deciding the container failed to start.
func startWithIdmapRecovery(containerName string) error {
	firstErr := startCapture(containerName)
	if firstErr == nil {
		return nil
	}
	// Poll: maybe it came up despite the forkstart error (soft error on some hosts).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if running, _ := ContainerRunning(containerName); running {
			return nil
		}
	}
	// Retry once unchanged: transient failures (incusd blip, slow storage)
	// recover here, before anything touches the container's configuration.
	if retryErr := startCapture(containerName); retryErr == nil {
		return nil
	}
	if running, _ := ContainerRunning(containerName); running {
		return nil
	}

	// #678: a shift=true (idmapped) workspace mount the guest kernel can't do —
	// observed on some OrbStack kernels — fails the START. Convert the shift
	// mounts to raw.idmap (the same mapping a manual disable_shift produces) on
	// the stopped container and retry.
	if isIdmapMountUnsupported(firstErr) && fallbackShiftToRawIdmap(containerName) {
		fmt.Fprintf(os.Stderr, "Warning: this host can't do idmapped (shift) mounts; using raw.idmap for the workspace and retrying\n")
		if retryErr := startCapture(containerName); retryErr == nil {
			return nil
		}
		if running, _ := ContainerRunning(containerName); running {
			return nil
		}
	}
	return firstErr
}

// StartWithIdmapFallback starts a container with only the #678 shift→raw.idmap
// recovery, for callers whose container never had security.idmap.isolated set:
// the non-isolated fresh-launch branch and `coi container start`. Those callers
// must not go through StartWithIsolationFallback, which would print a misleading
// "UID namespace isolation not available" warning — and unset a key that was
// never set — for any unrelated permanent failure.
func StartWithIdmapFallback(containerName string) error {
	firstErr := startWithIdmapRecovery(containerName)
	if firstErr == nil {
		return nil
	}
	// The raw.idmap conversion didn't recover: point at the escape hatch rather
	// than leave the user with the raw Incus error (#678).
	if isIdmapMountUnsupported(firstErr) {
		return withDisableShiftHint(firstErr)
	}
	return firstErr
}

// StartWithIsolationFallback starts a non-ephemeral container that may have
// security.idmap.isolated set, with automatic fallback if the host doesn't
// support it. Intended for non-ephemeral containers (setup.go path, run's
// persistent reuse) — stopped containers are not deleted, so unset+retry works.
//
// The idmapped-mount recovery in startWithIdmapRecovery runs first: that failure
// is a different code path, and unsetting isolation would not fix it.
//
// The isolation fallback is careful not to downgrade a container it didn't help:
//   - startWithIdmapRecovery's second attempt runs with isolation INTACT, so
//     transient failures recover without touching the security posture;
//   - the prior isolated state is captured, and restored if the post-unset
//     retry fails too — an unrelated permanent failure (corrupt rootfs, missing
//     mount source) must not leave a persistent container silently un-isolated
//     for every future session.
func StartWithIsolationFallback(containerName string) error {
	firstErr := startWithIdmapRecovery(containerName)
	if firstErr == nil {
		return nil
	}

	// Persistent failure — isolation may genuinely be unsupported. Surface the
	// original error so a non-isolation root cause isn't misattributed, capture
	// the prior flag state, then unset and retry.
	fmt.Fprintf(os.Stderr, "Container start failed: %v\n", firstErr)
	wasIsolated := false
	if out, err := IncusOutput("config", "get", containerName, "security.idmap.isolated"); err == nil {
		wasIsolated = strings.TrimSpace(out) == "true"
	}
	fmt.Fprintf(os.Stderr, "Warning: UID namespace isolation not available in this environment, disabling and retrying\n")
	_ = IncusExecQuiet("config", "unset", containerName, "security.idmap.isolated")
	if retryErr := startCapture(containerName); retryErr != nil {
		if running, _ := ContainerRunning(containerName); running {
			return nil
		}
		// The fallback didn't help — the failure is not isolation-related.
		// Restore the container's isolation so the failed run leaves no trace.
		if wasIsolated {
			_ = IncusExecQuiet("config", "set", containerName, "security.idmap.isolated=true")
		}
		// If the root cause was an unsupported idmapped mount that the raw.idmap
		// fallback couldn't recover, point the user at the disable_shift escape
		// hatch instead of the raw Incus error (#678).
		if isIdmapMountUnsupported(firstErr) {
			return withDisableShiftHint(retryErr)
		}
		return retryErr
	}
	return nil
}

func startWithIsolationFallback(containerName string) error {
	return StartWithIsolationFallback(containerName)
}

// LaunchContainer launches an ephemeral container on the given storage pool.
// An empty pool means "use Incus's default pool".
// Uses init+configure+start (not launch) so security flags are set before first boot.
func LaunchContainer(imageAlias, containerName, pool string) error {
	return LaunchContainerWithPreStart(imageAlias, containerName, pool, true, nil)
}

// LaunchContainerPersistent launches a non-ephemeral container on the given
// storage pool. An empty pool means "use Incus's default pool".
// Uses init+configure+start (not launch) so security flags are set before first boot.
func LaunchContainerPersistent(imageAlias, containerName, pool string) error {
	return LaunchContainerWithPreStart(imageAlias, containerName, pool, false, nil)
}

// LaunchContainerWithPreStart is LaunchContainer/LaunchContainerPersistent with
// an optional preStart hook that runs AFTER `incus init` (+ config flags) but
// BEFORE the container is started. It applies the DEFAULT hardening policy;
// callers that honor [container] docker / [security] reduce_kernel_surface use
// LaunchContainerWithPreStartPolicy instead. A nil preStart is a no-op.
func LaunchContainerWithPreStart(imageAlias, containerName, pool string, ephemeral bool, preStart func() error) error {
	return LaunchContainerWithPreStartPolicy(imageAlias, containerName, pool, ephemeral, preStart, DefaultHardeningPolicy())
}

// LaunchContainerWithPreStartPolicy is LaunchContainerWithPreStart with an
// explicit kernel-surface policy applied once at init (before first boot, as
// the seccomp profile requires). This is where start-time-only instance
// settings such as raw.idmap must be applied (issue #530): the run pipeline
// needs the workspace UID mapping set before first boot, and `incus launch`
// would start too early. A nil preStart is a no-op.
func LaunchContainerWithPreStartPolicy(imageAlias, containerName, pool string, ephemeral bool, preStart func() error, policy HardeningPolicy) error {
	if err := initAndConfigureContainer(imageAlias, containerName, pool, ephemeral, preStart, policy); err != nil {
		return err
	}
	// Non-fatal: unset and retry at start time if the environment lacks subuid space.
	_ = IsolateUIDNamespace(containerName)
	if !ephemeral {
		return startWithIsolationFallback(containerName)
	}
	firstErr := startCapture(containerName)
	if firstErr == nil {
		return nil
	}
	// Start failed. Poll briefly to distinguish a soft forkstart error (container
	// comes up anyway) from Incus async cleanup (ephemeral container gets deleted).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if running, _ := ContainerRunning(containerName); running {
			return nil // soft forkstart error; container is up
		}
		// Check for deletion: stopped ephemeral containers are deleted by Incus.
		out, err := IncusOutput("list", "^"+containerName+"$", "--format=csv", "--columns=n")
		if err == nil && strings.TrimSpace(out) == "" {
			// Incus deleted the ephemeral container after the start failure.
			// Recreate + start fresh (preStart re-runs so raw.idmap is re-applied);
			// initConfigureAndStart does not set security.idmap.isolated, so the
			// retry drops isolation. State that neutrally rather than asserting
			// isolation was unsupported — the recreate *succeeding* is what would
			// prove that, and an idmapped-mount failure (#678) is a different
			// class entirely (#716).
			fmt.Fprintf(os.Stderr, "Warning: container start failed; recreating without UID namespace isolation and retrying\n")
			recreateErr := initConfigureAndStart(imageAlias, containerName, pool, true, preStart, policy)
			// The recreate's start (a plain `incus start`) can soft-fail —
			// forkstart exits non-zero though the container came up — on the same
			// nested/CI hosts the initial start does; treat a running container as
			// success before reporting failure, matching the other retry branches.
			if recreateErr != nil {
				if running, _ := ContainerRunning(containerName); running {
					return nil
				}
			}
			return startRetryError(firstErr, recreateErr)
		}
	}

	// #678: an idmapped ("shift") workspace mount the guest kernel can't do fails
	// the start and leaves the ephemeral container stopped (not deleted). Convert
	// its shift mounts to raw.idmap and retry — the isolation unset below can't fix
	// this, it's a different code path.
	if isIdmapMountUnsupported(firstErr) && fallbackShiftToRawIdmap(containerName) {
		fmt.Fprintf(os.Stderr, "Warning: this host can't do idmapped (shift) mounts; using raw.idmap for the workspace and retrying\n")
		if retryErr := startCapture(containerName); retryErr == nil {
			return nil
		}
		if running, _ := ContainerRunning(containerName); running {
			return nil
		}
	}

	// Container exists but didn't start; unset isolation and retry.
	fmt.Fprintf(os.Stderr, "Warning: UID namespace isolation not supported in this environment, retrying\n")
	_ = IncusExecQuiet("config", "unset", containerName, "security.idmap.isolated")
	if retryErr := startCapture(containerName); retryErr != nil {
		if running, _ := ContainerRunning(containerName); running {
			return nil
		}
		return startRetryError(firstErr, retryErr)
	}
	return nil
}

// initAndConfigureContainer creates a container, applies the kernel-surface
// policy and other required config flags, and runs the optional preStart hook
// (used for start-time-only settings like raw.idmap) before the caller starts
// the container. The policy is applied once here, before first boot, so no
// caller needs to patch it on afterward.
func initAndConfigureContainer(imageAlias, containerName, pool string, ephemeral bool, preStart func() error, policy HardeningPolicy) error {
	args := []string{"init", imageAlias, containerName}
	if ephemeral {
		args = append(args, "--ephemeral")
	}
	if pool != "" {
		args = append(args, "-s", pool)
	}
	if err := IncusExec(args...); err != nil {
		return err
	}
	if err := ApplyKernelSurfacePolicy(containerName, policy); err != nil {
		return err
	}
	// Fail closed BEFORE first boot when an attached Incus profile pins a key
	// the policy needs unset (e.g. security.nesting=true from a Docker-in-Incus
	// default profile): the instance-local unset above cannot override it, and
	// booting anyway would silently defeat the requested hardening. Free for
	// the default (docker-on) policy — no reads are performed.
	if err := VerifyKernelSurfacePolicy(containerName, policy); err != nil {
		return err
	}
	if err := DisableGuestAPI(containerName); err != nil {
		return err
	}
	if err := CheckNotPrivileged(containerName); err != nil {
		return err
	}
	if preStart != nil {
		return preStart()
	}
	return nil
}

// initConfigureAndStart creates, configures, and starts a container without
// security.idmap.isolated — used as the isolation-unsupported fallback path.
func initConfigureAndStart(imageAlias, containerName, pool string, ephemeral bool, preStart func() error, policy HardeningPolicy) error {
	if err := initAndConfigureContainer(imageAlias, containerName, pool, ephemeral, preStart, policy); err != nil {
		return err
	}
	return IncusExec("start", containerName)
}

// DisableGuestAPI prevents the Incus guest API (/dev/incus) from being
// accessible inside the container. The guest API exposes host source paths
// in the device topology, leaking the host username and workspace layout
// (see FLAWS.md Finding 3). Coi communicates with containers via the host
// admin socket and does not need the guest API.
func DisableGuestAPI(containerName string) error {
	return IncusExec("config", "set", containerName, "security.guestapi=false")
}

// IsolateUIDNamespace enables UID/GID namespace isolation for the container.
// When multiple containers run simultaneously, each gets a unique, non-overlapping
// slice of the host UID/GID space. Without this flag all unprivileged containers
// share the same host-side UID range (typically 100000–165535), so a file
// written by one container as host UID 100000 is readable by another container
// whose UID 0 maps to the same host UID. This must be set before the container
// starts — changing it on a running container has no effect.
func IsolateUIDNamespace(containerName string) error {
	return IncusExec("config", "set", containerName, "security.idmap.isolated=true")
}

// EnableNICSecurity hardens the container's primary bridge NIC (eth0) against
// network-isolation bypass. It MUST be applied before the container's first boot
// — Incus wires the bridge-port filters when the NIC is brought up.
//
// Coi's egress allowlist is enforced by host nftables rules that match the
// container's source IP (`ip saddr <containerIP>`) in a chain whose default
// policy is accept. Without anti-spoofing, in-container root (which holds
// CAP_NET_ADMIN over its own netns) can add a second source IP or spoof its
// MAC so packets miss every saddr-keyed rule and fall through to the accept
// policy. This sets, on eth0:
//
//   - security.ipv4_filtering=true : the bridge drops any packet whose source IP
//     is not the container's DHCP-leased address (defeats source-IP spoofing).
//   - security.mac_filtering=true  : same for the source MAC (implied by
//     ipv4_filtering but set explicitly for clarity/robustness).
//   - security.port_isolation=true : the bridge blocks this port from talking to
//     OTHER ports on the same bridge (sibling Coi containers), preventing L2
//     lateral movement that the routed-path nft rules never observe.
//
// eth0 is inherited from the default profile, so it is first overridden onto the
// instance (Incus refuses `config device set` on a profile-supplied device).
// Returns an error if any key cannot be set; callers treat it as non-fatal so
// unmanaged/static/macvlan NICs degrade to nft-only enforcement.
func EnableNICSecurity(containerName string) error {
	const nic = "eth0"
	// Materialize the profile NIC at the instance level so device keys can be
	// set on it. Ignored on failure: a re-run (e.g. persistent container that
	// was already overridden) reports "already exists", and the explicit
	// `config device set` calls below surface any real problem.
	_ = IncusExecQuiet("config", "device", "override", containerName, nic)
	for _, kv := range []string{
		"security.ipv4_filtering=true",
		"security.mac_filtering=true",
		"security.port_isolation=true",
	} {
		if err := IncusExec("config", "device", "set", containerName, nic, kv); err != nil {
			return fmt.Errorf("failed to set %s on %s: %w", kv, nic, err)
		}
	}
	return nil
}

// DisableIPv6AtBoot disables IPv6 inside the container from the kernel's first
// instant by setting the disable_ipv6 sysctls as Incus config before boot. This
// closes the IPv6 egress window that otherwise exists between container start and
// the host-side IPv6 nft drop being installed by the network manager.
//
// It is defence-in-depth only: in-container root can re-enable IPv6 at runtime,
// which is why the host-side ip6 drop (network.ApplyIPv6BlockForContainer) is the
// actual enforced boundary. Must be set before first boot.
func DisableIPv6AtBoot(containerName string) error {
	if err := IncusExec("config", "set", containerName,
		"linux.sysctl.net.ipv6.conf.all.disable_ipv6=1"); err != nil {
		return err
	}
	return IncusExec("config", "set", containerName,
		"linux.sysctl.net.ipv6.conf.default.disable_ipv6=1")
}

// networkdConfigFilename is the on-disk name of the coi networkd config. The
// 05- prefix must sort before netplan's generated 10-netplan-eth0.network so
// systemd-networkd prefers this one (both live in the search path; only the
// first-sorting match per link is applied).
const networkdConfigFilename = "05-coi-ipv4-only.network"

// networkdIPv4OnlyConfig manages eth0 as IPv4-only. Because networkd applies only
// the first-matching .network per link (no merge), this fully supersedes netplan's
// generated eth0 config — so it re-requests the DHCP-supplied MTU (UseMTU) and
// search domains (UseDomains), which networkd would otherwise default to off,
// to avoid silently dropping them relative to netplan (PMTU black-holing / broken
// short-name DNS on overlay bridges).
const networkdIPv4OnlyConfig = `# Installed by coi in restricted/allowlist mode (issue #548).
# coi disables IPv6 in the container; without this, systemd-networkd keeps
# failing to add the IPv6 link-local address, the link never leaves the
# "configuring" state, and systemd-networkd-wait-online (hence
# network-online.target and everything ordered after it, e.g. docker.service)
# hangs forever. Declaring eth0 IPv4-only lets the link reach "configured".
[Match]
Name=eth0

[Network]
DHCP=ipv4
LinkLocalAddressing=no
IPv6AcceptRA=no

[DHCPv4]
UseMTU=true
UseDomains=yes

[Link]
RequiredFamilyForOnline=ipv4
`

// ConfigureNetworkdIPv4Only writes a high-priority networkd config that manages
// eth0 as IPv4-only, so the link reaches "configured" even though coi disables
// IPv6 (issue #548). It MUST be pushed before the container starts (networkd
// reads it on first boot) — callers invoke it from their pre-start hook. Only
// meaningful in restricted/allowlist mode, where coi disables IPv6; in open mode
// IPv6 is left working and this is not applied.
func ConfigureNetworkdIPv4Only(containerName string) error {
	tmp, err := os.CreateTemp("", "coi-networkd-*.network")
	if err != nil {
		return fmt.Errorf("create temp networkd config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(networkdIPv4OnlyConfig); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp networkd config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp networkd config: %w", err)
	}
	dest := containerName + "/etc/systemd/network/" + networkdConfigFilename
	if err := IncusExec("file", "push", "--create-dirs", "--mode=0644", tmp.Name(), dest); err != nil {
		return fmt.Errorf("push networkd config to %s: %w", dest, err)
	}
	return nil
}

// StopContainer stops a container
func StopContainer(containerName string) error {
	return IncusExec("stop", containerName, "--force")
}

// StopContainerQuiet stops a container while CAPTURING the incus subprocess
// output instead of streaming it to os.Stdout/os.Stderr. It is the
// terminal-safe stop primitive for code that may run while a session is
// interactively attached (the runtime-limit watchdog, the threat responder):
// there the process's os.Stdout/os.Stderr are the user's terminal, so the
// streaming Manager.Stop/StopContainer would corrupt the TUI (issue #372).
// The captured stdout is returned, and on failure the *ExitError carries the
// subprocess stderr, so the caller can route both to the session log.
func StopContainerQuiet(ctx context.Context, containerName string, force bool) (string, error) {
	args := []string{"stop", containerName}
	if force {
		args = append(args, "--force")
	}
	return IncusOutputContext(ctx, args...)
}

// DeleteContainer deletes a container forcefully
func DeleteContainer(containerName string) error {
	return IncusExecQuiet("delete", containerName, "--force")
}

// ContainerRunning checks if a container is running
func ContainerRunning(containerName string) (bool, error) {
	output, err := IncusOutput("list", containerName, "--format=json")
	if err != nil {
		return false, err
	}

	var containers []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}

	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return false, err
	}

	for _, c := range containers {
		if c.Name == containerName && StatusIsRunning(c.Status) {
			return true, nil
		}
	}

	return false, nil
}

// PublishContainer publishes a stopped container as an image
func PublishContainer(containerName, aliasName, description, compression string) (string, error) {
	// Stop container if running (ignore error if already stopped)
	running, _ := ContainerRunning(containerName)
	if running {
		if err := StopContainer(containerName); err != nil {
			return "", err
		}
	}

	// Build publish command
	args := []string{"publish", containerName, "--alias", aliasName}
	if compression != "" {
		args = append(args, "--compression", compression)
	}
	if description != "" {
		args = append(args, fmt.Sprintf("description=%s", description))
	}

	// Execute and capture output
	output, err := IncusOutput(args...)
	if err != nil {
		return "", err
	}

	// Extract fingerprint from output
	re := regexp.MustCompile(`fingerprint:\s*([a-f0-9]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract fingerprint from output")
	}

	fingerprint := matches[1]

	// Cleanup container after successful publish
	if err := DeleteContainer(containerName); err != nil {
		return fingerprint, err // Return fingerprint even if cleanup fails
	}

	return fingerprint, nil
}

// DeleteImage deletes an image by alias
func DeleteImage(aliasName string) error {
	return IncusExecQuiet("image", "delete", aliasName)
}

// ImageExists checks if an image with the given alias exists
func ImageExists(aliasName string) (bool, error) {
	output, err := IncusOutput("image", "list", "--format=json")
	if err != nil {
		return false, err
	}

	var images []struct {
		Aliases []struct {
			Name string `json:"name"`
		} `json:"aliases"`
	}

	if err := json.Unmarshal([]byte(output), &images); err != nil {
		return false, err
	}

	for _, img := range images {
		for _, alias := range img.Aliases {
			if alias.Name == aliasName {
				return true, nil
			}
		}
	}

	return false, nil
}

// ListContainers lists all containers matching a name pattern
func ListContainers(pattern string) ([]string, error) {
	output, err := IncusOutput("list", "--format=json")
	if err != nil {
		return nil, err
	}

	var containers []struct {
		Name string `json:"name"`
	}

	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, err
	}

	// Compile pattern as regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	var matching []string
	for _, c := range containers {
		if re.MatchString(c.Name) {
			matching = append(matching, c.Name)
		}
	}

	return matching, nil
}

// buildIncusCommand builds the incus argv (project flag first, then args). The
// result is passed straight to exec.Command — no shell parses it, so arguments
// need no quoting or escaping regardless of the characters they contain.
func buildIncusCommand(args ...string) []string {
	return append([]string{"--project", IncusProject}, args...)
}

// ConfigSet sets a configuration key on a container.
func ConfigSet(ctx context.Context, containerName, key, value string) error {
	return IncusExecContext(ctx, "config", "set", containerName, key+"="+value)
}

// ConfigGet returns the value of a configuration key on a container (trimmed).
// An unset key yields an empty string with no error, matching `incus config get`.
func ConfigGet(ctx context.Context, containerName, key string) (string, error) {
	out, err := IncusOutputContext(ctx, "config", "get", containerName, key)
	return strings.TrimSpace(out), err
}

// ConfigUnset removes a configuration key from a container.
func ConfigUnset(ctx context.Context, containerName, key string) error {
	return IncusExecContext(ctx, "config", "unset", containerName, key)
}

// ConfigShow returns the container's YAML configuration.
// If expanded is true, profile-inherited devices and config are included.
func ConfigShow(ctx context.Context, containerName string, expanded bool) (string, error) {
	args := []string{"config", "show"}
	if expanded {
		args = append(args, "--expanded")
	}
	args = append(args, containerName)
	return IncusOutputContext(ctx, args...)
}

// DeviceAdd adds a device to a container.
// Returns the combined stdout+stderr output and a nil error.
// If the device already exists, a nil error is returned (idempotent).
func DeviceAdd(ctx context.Context, containerName string, deviceArgs ...string) (string, error) {
	args := append([]string{"config", "device", "add", containerName}, deviceArgs...)
	out, err := IncusOutputWithStderrContext(ctx, args...)
	if err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) && strings.Contains(strings.ToLower(out), "already") {
			return out, nil
		}
	}
	return out, err
}

// DeviceSet sets a device-level configuration key on a container.
// Returns the combined stdout+stderr output (useful for error inspection) and any error.
func DeviceSet(ctx context.Context, containerName, device, keyValue string) (string, error) {
	return IncusOutputWithStderrContext(ctx, "config", "device", "set", containerName, device, keyValue)
}

// SnapshotCreate creates a snapshot of a container
func SnapshotCreate(containerName, snapshotName string, stateful bool) error {
	args := []string{"snapshot", "create", containerName, snapshotName}
	if stateful {
		args = append(args, "--stateful")
	}
	return IncusExec(args...)
}

// SnapshotList lists snapshots for a container in JSON format
func SnapshotList(containerName string) (string, error) {
	return IncusOutput("snapshot", "list", containerName, "--format=json")
}

// SnapshotRestore restores a container from a snapshot
func SnapshotRestore(containerName, snapshotName string, stateful bool) error {
	args := []string{"snapshot", "restore", containerName, snapshotName}
	if stateful {
		args = append(args, "--stateful")
	}
	return IncusExec(args...)
}

// SnapshotDelete deletes a snapshot from a container
func SnapshotDelete(containerName, snapshotName string) error {
	return IncusExec("snapshot", "delete", containerName, snapshotName)
}
