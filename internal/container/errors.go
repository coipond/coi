package container

import (
	"errors"
	"os/exec"
	"strings"
)

// Sentinel errors classify the incus failures that callers act on. The incus
// CLI exits 1 for every failure and distinguishes them only in stderr text, so
// classification necessarily starts from that text — but it is done in exactly
// one place (ClassifyIncusErr) and exposed as sentinels, so the rest of the
// codebase matches with errors.Is instead of re-scanning stderr.
var (
	// ErrContainerNotFound means an incus operation targeted an instance that
	// does not exist.
	ErrContainerNotFound = errors.New("container not found")

	// ErrIncusUnavailable means the incus binary is not installed (not on PATH)
	// or the incus daemon cannot be reached.
	ErrIncusUnavailable = errors.New("incus is unavailable")
)

// ClassifyIncusErr wraps err with a sentinel (ErrContainerNotFound or
// ErrIncusUnavailable) when err — or the subprocess stderr captured alongside
// it — identifies a known incus failure, so callers can match it with
// errors.Is. Errors it does not recognize are returned unchanged, and errors
// already carrying a sentinel are returned as-is (no double wrapping). Pass ""
// for stderr when none was captured separately.
func ClassifyIncusErr(err error, stderr string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrContainerNotFound) || errors.Is(err, ErrIncusUnavailable) {
		return err
	}

	haystack := strings.ToLower(err.Error() + " " + stderr)
	switch {
	case strings.Contains(haystack, "instance not found"):
		// The exact phrase Incus emits, matched narrowly so an unrelated failure
		// that merely mentions an instance is not miscategorised as not-found.
		return wrap(ErrContainerNotFound, err)
	case errors.Is(err, exec.ErrNotFound),
		strings.Contains(haystack, "executable file not found"),
		strings.Contains(haystack, "connect to incus"), // "cannot connect to incus", "failed to connect to incusd"
		strings.Contains(haystack, "connection refused"),
		strings.Contains(haystack, "is the daemon running"):
		return wrap(ErrIncusUnavailable, err)
	}
	return err
}

// SentinelError is an error with its own message that matches a sentinel with
// errors.Is, for failures coi detects itself (not from incus stderr): the user
// sees msg alone, and the CLI still maps the sentinel to its exit code.
func SentinelError(sentinel error, msg string) error {
	return &sentinelError{sentinel: sentinel, msg: msg}
}

type sentinelError struct {
	sentinel error
	msg      string
}

func (e *sentinelError) Error() string { return e.msg }

func (e *sentinelError) Unwrap() error { return e.sentinel }

// wrap joins a sentinel to the underlying error so both errors.Is(result,
// sentinel) and errors.As(result, &target) (e.g. *ExitError, preserving its
// exit code) keep working.
func wrap(sentinel, err error) error {
	return errors.Join(sentinel, err)
}

// IsNotFoundErr reports whether an Incus error means the instance is not there.
// It is the errors.Is form of the ErrContainerNotFound classification, kept as
// a named predicate for the several call sites that read more clearly with it.
//
// For anything whose goal is "this container should be gone", not-found is
// success, not failure. Deletion races are routine: stopping a container ends
// the session that owns it, and that session then deletes its own ephemeral
// container — so a concurrent `coi kill` can find the instance already removed
// between checking that it exists and deleting it. Treating that as an error
// made `coi kill` report "No containers were killed" and exit non-zero about a
// container that had, in fact, been killed.
func IsNotFoundErr(err error) bool {
	return errors.Is(ClassifyIncusErr(err, ""), ErrContainerNotFound)
}
