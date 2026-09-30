package cli

import (
	"errors"
	"fmt"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// Process exit codes. Codes 1 and 2 predate this list; the named codes let the
// CLI map typed errors to a deliberate, documented status instead of collapsing
// every failure to 1.
const (
	ExitGeneric           = 1 // unclassified failure
	ExitUsage             = 2 // bad flags/arguments/format
	ExitIncusUnavailable  = 3 // incus not installed or daemon unreachable
	ExitContainerNotFound = 4 // targeted container does not exist
	ExitConfig            = 5 // configuration could not be loaded/parsed/validated
)

// ExitCodeError is returned by commands that need to exit with a specific
// non-zero code (e.g., health checks, container exec, coi run). Returning
// this through cobra instead of calling os.Exit() directly ensures that
// deferred cleanup (container deletion, firewall teardown) runs before the
// process exits.
type ExitCodeError struct {
	Code    int
	Message string
}

func (e *ExitCodeError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

// ExitCodeFor maps an error to a process exit code. An explicit ExitCodeError
// wins; otherwise typed/sentinel errors map to their dedicated code; anything
// else is ExitGeneric.
func ExitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	var ece *ExitCodeError
	if errors.As(err, &ece) {
		return ece.Code
	}
	var cfgErr *config.ConfigError
	switch {
	case errors.As(err, &cfgErr):
		return ExitConfig
	case errors.Is(err, container.ErrIncusUnavailable):
		return ExitIncusUnavailable
	case errors.Is(err, container.ErrContainerNotFound):
		return ExitContainerNotFound
	}
	return ExitGeneric
}
