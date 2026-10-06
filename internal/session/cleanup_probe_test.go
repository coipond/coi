package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/container"
)

// fakeProber scripts successive probe answers; Running answers come from a
// function of the call index so tests can flip state mid-flight.
type fakeProber struct {
	outs     []string
	errs     []error
	execs    int
	running  func(call int) (bool, error)
	runCalls int
}

func (f *fakeProber) ExecCommand(_ string, _ container.ExecCommandOptions) (string, error) {
	i := f.execs
	f.execs++
	var out string
	var err error
	if i < len(f.outs) {
		out = f.outs[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return out, err
}

func (f *fakeProber) Running() (bool, error) {
	i := f.runCalls
	f.runCalls++
	if f.running == nil {
		return true, nil
	}
	return f.running(i)
}

func busDownErr() error {
	return &container.ExitError{ExitCode: 1, Stderr: "Failed to connect to bus: Host is down"}
}

func noSystemdErr() error {
	return &container.ExitError{ExitCode: 127, Stderr: "bash: line 1: systemctl: command not found"}
}

func TestGuestShutdownInProgress_Stopping(t *testing.T) {
	f := &fakeProber{outs: []string{"stopping"}}
	if !guestShutdownInProgress(f) {
		t.Error("'stopping' must classify as shutdown in progress")
	}
	if f.execs != 1 {
		t.Errorf("one probe should suffice, got %d", f.execs)
	}
}

// fastShutdown runs the detector with tiny timing so tests never sleep the real
// window, while exercising the same logic (and the same healthyConfirmChecks).
func fastShutdown(f *fakeProber) bool {
	return shutdownInProgress(f, time.Millisecond, 100*time.Millisecond, healthyConfirmChecks)
}

func TestGuestShutdownInProgress_HealthyStatesAreUserExit(t *testing.T) {
	for _, state := range []string{"running", "degraded", "maintenance", "initializing", "starting"} {
		// A healthy state must classify as a normal exit — but only after it
		// PERSISTS (healthyConfirmChecks in a row), so a close's brief pre-stopping
		// "running" can't be mistaken for it (issue #616).
		outs := make([]string, healthyConfirmChecks)
		for i := range outs {
			outs[i] = state
		}
		f := &fakeProber{outs: outs}
		if fastShutdown(f) {
			t.Errorf("%q sustained must classify as a normal exit", state)
		}
	}
}

func TestGuestShutdownInProgress_BusDownIsShutdown(t *testing.T) {
	// systemctl ran but systemd's bus is gone while the container still
	// reports Running: the shutdown tail.
	f := &fakeProber{outs: []string{""}, errs: []error{busDownErr()}}
	if !guestShutdownInProgress(f) {
		t.Error("an answered-but-bus-down probe must classify as shutdown")
	}
}

func TestGuestShutdownInProgress_NoSystemdFastExit(t *testing.T) {
	// An image that can never answer must not burn the retry budget on
	// every session exit.
	f := &fakeProber{outs: []string{""}, errs: []error{noSystemdErr()}}
	start := time.Now()
	if guestShutdownInProgress(f) {
		t.Error("missing systemctl must classify as a normal exit")
	}
	if f.execs != 1 {
		t.Errorf("no-systemd must be decided on the first probe, got %d probes", f.execs)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("no-systemd classification took %v, must not sleep", elapsed)
	}
}

func TestGuestShutdownInProgress_AmbiguousThenStopped(t *testing.T) {
	// "unknown"/"offline" (late-poweroff tail) is ambiguous; the container
	// stopping during the observation window resolves it as a shutdown.
	f := &fakeProber{
		outs:    []string{"unknown", "offline"},
		running: func(call int) (bool, error) { return call < 1, nil },
	}
	if !fastShutdown(f) {
		t.Error("ambiguous states with the container then stopping must classify as shutdown")
	}
}

func TestGuestShutdownInProgress_TransportErrorOnLiveContainer(t *testing.T) {
	// Exec yields nothing, container stays verifiably running: user exit
	// (after the bounded retries) — a broken exec must not delete containers.
	f := &fakeProber{errs: repeatErr(errors.New("x"), 200)}
	if fastShutdown(f) {
		t.Error("a persistently unanswerable probe on a running container must classify as a normal exit")
	}
}

func TestGuestShutdownInProgress_RunningErrorDoesNotCountAsStopped(t *testing.T) {
	// Incus daemon errors during the ambiguous branch must NOT be read as
	// "container stopped" (the swallowed-error chain from the review).
	f := &fakeProber{
		outs:    make([]string, 200), // all "" -> no-answer, ambiguous
		running: func(int) (bool, error) { return false, errors.New("incus daemon restarting") },
	}
	for i := range f.outs {
		f.outs[i] = "unknown"
	}
	if fastShutdown(f) {
		t.Error("a Running() error must not be treated as evidence of a shutdown")
	}
}

func TestContainerRunning_ErrorIsUnknownNotStopped(t *testing.T) {
	f := &fakeProber{running: func(int) (bool, error) { return false, errors.New("boom") }}
	if _, ok := containerRunning(f); ok {
		t.Error("persistent Running() errors must report state as unknown")
	}

	// A transient error followed by a clean answer resolves.
	f2 := &fakeProber{running: func(call int) (bool, error) {
		if call == 0 {
			return false, errors.New("blip")
		}
		return true, nil
	}}
	running, ok := containerRunning(f2)
	if !ok || !running {
		t.Errorf("expected (running=true, ok=true) after a transient blip, got (%v, %v)", running, ok)
	}
}

func TestWaitForStopped(t *testing.T) {
	// Stops on the second poll.
	f := &fakeProber{running: func(call int) (bool, error) { return call < 1, nil }}
	stopped, interrupted := waitForStopped(f, 5*time.Second)
	if !stopped || interrupted {
		t.Errorf("expected (stopped=true, interrupted=false), got (%v, %v)", stopped, interrupted)
	}

	// Never stops: times out, and daemon errors are not "stopped".
	f2 := &fakeProber{running: func(int) (bool, error) { return false, errors.New("err") }}
	stopped, _ = waitForStopped(f2, time.Second)
	if stopped {
		t.Error("Running() errors must not satisfy the stopped condition")
	}
}

// ---- issue #616: `close` (systemctl --force poweroff) mislabeled "kept running" ----

func repeatErr(err error, n int) []error {
	out := make([]error, n)
	for i := range out {
		out[i] = err
	}
	return out
}

// Repro A — the pre-"stopping" race. `close` execs `systemctl --force poweroff`,
// which ENQUEUES the poweroff and exits, ending the session before systemd flips
// its manager state to "stopping". The first probe therefore catches a healthy
// "running", and the container stops a moment later. Detection must not conclude
// "normal exit" from that single hasty probe.
func TestGuestShutdownInProgress_ClosePreStoppingRace_Regression(t *testing.T) {
	f := &fakeProber{
		outs:    []string{"running", "running", "running"},             // systemd not yet in "stopping"
		running: func(call int) (bool, error) { return call < 2, nil }, // stops shortly after
	}
	if !fastShutdown(f) {
		t.Error("issue #616: a close caught during systemd's pre-stopping window " +
			"(probe says running, container then stops) must be detected as a shutdown, not 'kept running'")
	}
}

// Repro B — the exec-goes-dark race. During `--force poweroff` the guest exec
// transport is torn down before incus marks the container stopped, so the probe
// returns no answer while Running() still reports true, and the container only
// reaches "stopped" AFTER the old fixed 3s (6x500ms) retry budget. Detection must
// observe the outside state long enough to see it stop.
func TestGuestShutdownInProgress_CloseExecGoesDark_Regression(t *testing.T) {
	const stopAfter = 10 // stops on the 11th Running() check — past the old 6-retry budget
	f := &fakeProber{
		errs:    repeatErr(errors.New("exec: connection reset by peer"), 60),
		running: func(call int) (bool, error) { return call < stopAfter, nil },
	}
	if !fastShutdown(f) {
		t.Error("issue #616: a close whose container reaches 'stopped' after the old retry budget " +
			"must still be detected — observe the outside (incus) state until it stops")
	}
}

// ---- marker-aware probe: one probe instead of a 3x500ms confirmation ----

func TestClassifyGuestProbe(t *testing.T) {
	cases := []struct {
		name, out string
		err       error
		state     string
		capable   bool
	}{
		{"healthy capable", "running\ncoi:marker-capable\n", nil, "running", true},
		{"healthy legacy image", "running\n", nil, "running", false},
		{"close marker", "running\ncoi:marker\ncoi:marker-capable\n", errors.New("exit 1"), guestStateShutdownRequested, true},
		{"queued poweroff job", "running\ncoi:queued\n", nil, guestStateShutdownRequested, false},
		{"stopping", "stopping\ncoi:marker-capable\n", nil, "stopping", true},
		{"bus down", "", busDownErr(), guestStateBusDown, false},
		{"bus down, flags only", "coi:marker-capable\n", busDownErr(), guestStateBusDown, true},
		{"no systemd", "", noSystemdErr(), guestStateNoSystemd, false},
		{"transport error", "", errors.New("connection reset"), guestStateNoAnswer, false},
	}
	for _, c := range cases {
		got := classifyGuestProbe(c.out, c.err)
		if got.state != c.state || got.markerCapable != c.capable {
			t.Errorf("%s: got %+v, want state=%q capable=%v", c.name, got, c.state, c.capable)
		}
	}
}

// On a marker-capable image a healthy answer with no marker is a plain exit:
// decided on the first probe, with no confirmation sleeps.
func TestGuestShutdownInProgress_MarkerCapableHealthyExitsFast(t *testing.T) {
	f := &fakeProber{outs: []string{"running\ncoi:marker-capable"}}
	if shutdownInProgress(f, time.Hour, time.Hour, healthyConfirmChecks) {
		t.Error("healthy, no marker, capable image: must be a normal exit")
	}
	if f.execs != 1 {
		t.Errorf("one probe should suffice on a marker-capable image, got %d", f.execs)
	}
}

// A close on a marker-capable image is caught on the first probe even while
// systemd still says "running" (the #616 pre-stopping window).
func TestGuestShutdownInProgress_MarkerDetectsCloseInPreStoppingWindow(t *testing.T) {
	f := &fakeProber{outs: []string{"running\ncoi:marker\ncoi:marker-capable"}}
	if !shutdownInProgress(f, time.Hour, time.Hour, healthyConfirmChecks) {
		t.Error("a fresh shutdown marker must classify as shutdown in progress")
	}
}

// The probe script must stay one exec and carry every signal the classifier
// expects.
func TestGuestProbeScriptSignals(t *testing.T) {
	for _, want := range []string{"systemctl is-system-running", ShutdownMarkerPath, "coi:marker", "coi:queued", "coi:marker-capable", "list-jobs"} {
		if !strings.Contains(guestProbeScript, want) {
			t.Errorf("probe script missing %q", want)
		}
	}
}
