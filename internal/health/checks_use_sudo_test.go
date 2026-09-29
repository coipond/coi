package health

import (
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// With use_sudo=false, CheckNft must not hard-fail: open mode is OK, and a mode
// that needs nft (restricted/allowlist) is a warning pointing at open mode —
// never StatusFailed, because the user deliberately opted out of sudo.
func TestCheckNft_UseSudoFalse(t *testing.T) {
	t.Run("open mode is OK", func(t *testing.T) {
		r := CheckNft(config.NetworkConfig{Mode: config.NetworkModeOpen, UseSudo: boolPtr(false)})
		if r.Status != StatusOK {
			t.Errorf("open + use_sudo=false: status = %s, want OK (%s)", r.Status, r.Message)
		}
	})

	t.Run("restricted mode warns, not fails", func(t *testing.T) {
		r := CheckNft(config.NetworkConfig{Mode: config.NetworkModeRestricted, UseSudo: boolPtr(false)})
		if r.Status != StatusWarning {
			t.Errorf("restricted + use_sudo=false: status = %s, want Warning (%s)", r.Status, r.Message)
		}
		if !strings.Contains(r.Message, "open") {
			t.Errorf("message should point at open mode, got: %s", r.Message)
		}
		if r.Details["use_sudo"] != false {
			t.Errorf("details[use_sudo] = %v, want false", r.Details["use_sudo"])
		}
	})
}
