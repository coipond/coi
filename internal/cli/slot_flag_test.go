package cli

import (
	"errors"
	"testing"
)

func TestValidateSlotFlag(t *testing.T) {
	for _, slot := range []int{0, 1, 10, 11} {
		if err := validateSlotFlag(slot); err != nil {
			t.Errorf("validateSlotFlag(%d) = %v, want nil", slot, err)
		}
	}

	err := validateSlotFlag(-1)
	var ece *ExitCodeError
	if !errors.As(err, &ece) || ece.Code != ExitUsage {
		t.Fatalf("validateSlotFlag(-1) = %v, want an ExitCodeError with code %d", err, ExitUsage)
	}
	if want := "invalid --slot -1: use a positive slot number, or 0 to auto-allocate"; ece.Message != want {
		t.Errorf("message = %q, want %q", ece.Message, want)
	}
}
