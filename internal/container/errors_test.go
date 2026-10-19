package container

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

func TestClassifyIncusErr_ContainerNotFound(t *testing.T) {
	// Incus reports a missing instance only via stderr text.
	cases := []struct {
		name   string
		err    error
		stderr string
	}{
		{"in error message", errors.New("exit status 1: Error: Instance not found"), ""},
		{"in stderr param", errors.New("exit status 1"), "Error: Instance not found"},
		{"mixed case", errors.New("INSTANCE NOT FOUND"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyIncusErr(tc.err, tc.stderr)
			if !errors.Is(got, ErrContainerNotFound) {
				t.Errorf("expected ErrContainerNotFound, got %v", got)
			}
		})
	}
}

func TestClassifyIncusErr_IncusUnavailable(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		stderr string
	}{
		{"binary missing (exec.ErrNotFound)", fmt.Errorf("wrap: %w", exec.ErrNotFound), ""},
		{"executable file not found text", errors.New(`exec: "incus": executable file not found in $PATH`), ""},
		{"daemon unreachable", errors.New("exit status 1"), "Error: Cannot connect to Incus: is the daemon running?"},
		{"connection refused", errors.New("exit status 1: dial unix: connection refused"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyIncusErr(tc.err, tc.stderr)
			if !errors.Is(got, ErrIncusUnavailable) {
				t.Errorf("expected ErrIncusUnavailable, got %v", got)
			}
		})
	}
}

func TestClassifyIncusErr_Unrecognized(t *testing.T) {
	orig := errors.New("exit status 1: some other failure about an instance volume")
	got := ClassifyIncusErr(orig, "")
	if got != orig {
		t.Errorf("unrecognized error must be returned unchanged, got %v", got)
	}
	if errors.Is(got, ErrContainerNotFound) || errors.Is(got, ErrIncusUnavailable) {
		t.Error("unrecognized error must not carry a sentinel")
	}
}

func TestClassifyIncusErr_NilAndNoDoubleWrap(t *testing.T) {
	if ClassifyIncusErr(nil, "") != nil {
		t.Error("nil in must be nil out")
	}
	once := ClassifyIncusErr(errors.New("Instance not found"), "")
	twice := ClassifyIncusErr(once, "")
	if twice != once {
		t.Error("an error already carrying a sentinel must not be re-wrapped")
	}
}

// Classification must preserve the underlying *ExitError so callers can still
// recover the incus exit code via errors.As.
func TestClassifyIncusErr_PreservesExitError(t *testing.T) {
	exitErr := &ExitError{ExitCode: 1, Err: errors.New("boom"), Stderr: "Error: Instance not found"}
	got := ClassifyIncusErr(exitErr, exitErr.Stderr)

	if !errors.Is(got, ErrContainerNotFound) {
		t.Fatalf("expected ErrContainerNotFound, got %v", got)
	}
	var recovered *ExitError
	if !errors.As(got, &recovered) {
		t.Fatal("wrapped error must still expose *ExitError via errors.As")
	}
	if recovered.ExitCode != 1 {
		t.Errorf("exit code lost: got %d, want 1", recovered.ExitCode)
	}
}

func TestSentinelError(t *testing.T) {
	err := SentinelError(ErrContainerNotFound, "container 'x' not found")
	if err.Error() != "container 'x' not found" {
		t.Errorf("Error() = %q, want the message alone", err.Error())
	}
	if !errors.Is(fmt.Errorf("phase: %w", err), ErrContainerNotFound) {
		t.Error("wrapped SentinelError must match its sentinel")
	}
	if errors.Is(err, ErrIncusUnavailable) {
		t.Error("SentinelError must not match another sentinel")
	}
	if ClassifyIncusErr(err, "") != err {
		t.Error("ClassifyIncusErr must return a SentinelError unchanged")
	}
}

func TestIncusNotAvailableError_NotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := IncusNotAvailableError()
	if err.Error() != "incus is not installed — please install Incus first" {
		t.Errorf("Error() = %q", err.Error())
	}
	if !errors.Is(err, ErrIncusUnavailable) {
		t.Error("IncusNotAvailableError must match ErrIncusUnavailable")
	}
}
