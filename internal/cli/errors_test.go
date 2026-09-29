package cli

import (
	"errors"
	"fmt"
	"testing"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/container"
)

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"generic", errors.New("boom"), ExitGeneric},
		{"explicit ExitCodeError wins", &ExitCodeError{Code: 2, Message: "bad flag"}, 2},
		{"explicit ExitCodeError wrapped", fmt.Errorf("ctx: %w", &ExitCodeError{Code: 7}), 7},
		{"incus unavailable", fmt.Errorf("ctx: %w", container.ErrIncusUnavailable), ExitIncusUnavailable},
		{"container not found", fmt.Errorf("ctx: %w", container.ErrContainerNotFound), ExitContainerNotFound},
		{"config error", &config.ConfigError{Err: errors.New("bad toml")}, ExitConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCodeFor(tc.err); got != tc.want {
				t.Errorf("ExitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// An explicit ExitCodeError must take precedence even when a sentinel is also
// present in the chain, so a command's deliberate code is never overridden.
func TestExitCodeFor_ExitCodeErrorBeatsSentinel(t *testing.T) {
	err := fmt.Errorf("%w: %w", &ExitCodeError{Code: 9}, container.ErrContainerNotFound)
	if got := ExitCodeFor(err); got != 9 {
		t.Errorf("explicit ExitCodeError must win: got %d, want 9", got)
	}
}
