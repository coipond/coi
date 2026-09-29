package network

import (
	"strings"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/config"
)

// TestApplyAllowlist_RequiresGateway pins that allowlist mode treats a missing
// gateway as a hard error rather than silently omitting the DHCP renewal rule.
// Allowlist mode is default-reject, so without that rule the container's DHCP
// lease eventually lapses and it loses the IP every other rule is keyed on. The
// guard is the first statement in ApplyAllowlist, so this needs no nft or sudo.
func TestApplyAllowlist_RequiresGateway(t *testing.T) {
	f := NewNftManager("10.0.0.50", "") // no gateway
	err := f.ApplyAllowlist(&config.NetworkConfig{Mode: config.NetworkModeAllowlist}, nil)
	if err == nil {
		t.Fatal("ApplyAllowlist with no gateway must error, not silently skip the DHCP rule")
	}
	if !strings.Contains(err.Error(), "gateway") {
		t.Errorf("error should name the missing gateway, got: %v", err)
	}
}

// TestElementTimeout pins the invariant that a dynamic set element must outlive
// the refresh that renews it. If an element expired first it would drop out of
// the firewall while /etc/hosts still pointed at the address, so the container
// would resolve an allowlisted name and have the connection rejected — the exact
// "Unable to connect" failure allowlist mode exists to prevent. The old code
// sized elements at ttl+10min regardless of the refresh cadence, so a TTL-0
// domain (e.g. api.anthropic.com) with the default 30-min refresh expired 20
// minutes before it was renewed.
func TestElementTimeout(t *testing.T) {
	t.Run("refresh disabled installs a permanent element", func(t *testing.T) {
		for _, ttl := range []uint32{0, 60, 3600} {
			if got := elementTimeout(ttl, 0); got != 0 {
				t.Errorf("elementTimeout(%d, 0) = %v, want 0 (permanent) when refresh is disabled", ttl, got)
			}
			if got := elementTimeout(ttl, -time.Second); got != 0 {
				t.Errorf("elementTimeout(%d, <0) = %v, want 0 (permanent)", ttl, got)
			}
		}
	})

	t.Run("an enabled element always outlives its refresh interval", func(t *testing.T) {
		// Includes the previously-broken case: TTL 0 with the 30-min default cap.
		ttls := []uint32{0, 1, 60, 300, 3600, 86400}
		intervals := []time.Duration{time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 6 * time.Hour}
		for _, ttl := range ttls {
			for _, r := range intervals {
				got := elementTimeout(ttl, r)
				if got <= r {
					t.Errorf("elementTimeout(%d, %v) = %v, must be strictly greater than the refresh interval", ttl, r, got)
				}
				// The margin is at least a full grace period beyond the interval.
				if got < r+dnsElementGrace {
					t.Errorf("elementTimeout(%d, %v) = %v, want >= interval + grace (%v)", ttl, r, got, r+dnsElementGrace)
				}
			}
		}
	})

	t.Run("regression: TTL-0 at the default cap no longer expires before refresh", func(t *testing.T) {
		const defaultRefresh = 30 * time.Minute
		got := elementTimeout(0, defaultRefresh)
		if got != defaultRefresh+dnsElementGrace {
			t.Errorf("elementTimeout(0, 30m) = %v, want 40m (interval + grace)", got)
		}
		if got <= defaultRefresh {
			t.Fatalf("elementTimeout(0, 30m) = %v would expire before the 30m refresh — the original bug", got)
		}
	})

	t.Run("the cap never falls below one refresh-plus-grace", func(t *testing.T) {
		// A refresh interval larger than the 12h cap must still not size an element
		// shorter than the interval, or the expiry gap reappears.
		huge := dnsElementMaxTimeout + time.Hour
		got := elementTimeout(0, huge)
		if got <= huge {
			t.Errorf("elementTimeout(0, %v) = %v, must exceed the interval even past the default cap", huge, got)
		}
	})
}
