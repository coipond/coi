package network

import (
	"errors"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// stubNft records which nftRuler methods are called, in order.
// Set failOn to the method name to make that call return an error.
type stubNft struct {
	calls            []string
	failOn           string
	lastAllowedIPs   []string    // IPs passed to the most recent ReplaceAllowlist call
	dynamicIPs       []string    // IPs installed into the dynamic set, cumulative
	lastDynamicTTL   uint32      // TTL of the most recent AllowDynamicIPs call
	lastDynamicPorts []portRange // ports of the most recent AllowDynamicIPs call
}

func (s *stubNft) ApplyAllowlist(_ *config.NetworkConfig, allowedIPs []string) error {
	s.calls = append(s.calls, "ApplyAllowlist")
	s.lastAllowedIPs = allowedIPs
	if s.failOn == "ApplyAllowlist" {
		return errors.New("stub: ApplyAllowlist failed")
	}
	return nil
}

// AllowDynamicIPsPorts makes stubNft satisfy dynAllower, so Manager.nftSetAllower
// routes DNS-learned addresses here instead of to the real nft set.
func (s *stubNft) AllowDynamicIPsPorts(ips []string, ports []portRange, ttl uint32, _ time.Duration) error {
	s.calls = append(s.calls, "AllowDynamicIPs")
	s.dynamicIPs = append(s.dynamicIPs, ips...)
	s.lastDynamicPorts = ports
	s.lastDynamicTTL = ttl
	if s.failOn == "AllowDynamicIPs" {
		return errors.New("stub: AllowDynamicIPs failed")
	}
	return nil
}

func (s *stubNft) ApplyRestricted(_ *config.NetworkConfig) error {
	s.calls = append(s.calls, "ApplyRestricted")
	if s.failOn == "ApplyRestricted" {
		return errors.New("stub: ApplyRestricted failed")
	}
	return nil
}

func (s *stubNft) RemoveRules() error {
	s.calls = append(s.calls, "RemoveRules")
	if s.failOn == "RemoveRules" {
		return errors.New("stub: RemoveRules failed")
	}
	return nil
}

func (s *stubNft) ReplaceAllowlist(_ *config.NetworkConfig, allowedIPs []string) error {
	s.calls = append(s.calls, "ReplaceAllowlist")
	s.lastAllowedIPs = allowedIPs
	if s.failOn == "ReplaceAllowlist" {
		return errors.New("stub: ReplaceAllowlist failed")
	}
	return nil
}

func (s *stubNft) called(method string) bool {
	for _, c := range s.calls {
		if c == method {
			return true
		}
	}
	return false
}

// newManagerForRefreshTest builds a Manager wired for refreshAllowedIPs tests.
//
// Domains under the ".invalid" TLD are guaranteed by RFC 2606 never to resolve,
// so ResolveAll falls back to the seeded cache without depending on a live
// upstream answer. That keeps the refresher's behaviour under test rather than
// the network's.
func newManagerForRefreshTest(t *testing.T, stub *stubNft, cachedIPs map[string][]string, domains []string) *Manager {
	t.Helper()
	cache := &IPCache{
		Domains: cachedIPs,
		TTLs:    make(map[string]uint32),
	}
	policy, err := NewAllowPolicy(domains)
	if err != nil {
		t.Fatalf("NewAllowPolicy(%v): %v", domains, err)
	}
	return &Manager{
		config:       &config.NetworkConfig{AllowedDomains: domains},
		nft:          stub,
		policy:       policy,
		resolver:     NewResolver(cache),
		cacheManager: NewCacheManager(t.TempDir()),
		logger:       logger.NewDiscard(),
	}
}

// TestRefreshAllowedIPs_InstallsIntoDynamicSet verifies that the refresher feeds
// resolved addresses into the container's dynamic set.
func TestRefreshAllowedIPs_InstallsIntoDynamicSet(t *testing.T) {
	stub := &stubNft{}
	m := newManagerForRefreshTest(t, stub,
		map[string][]string{"stale.example.invalid": {"9.9.9.9"}},
		[]string{"stale.example.invalid"},
	)

	if _, err := m.refreshAllowedIPs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !stub.called("AllowDynamicIPs") {
		t.Errorf("AllowDynamicIPs was not called; calls: %v", stub.calls)
	}
	found := false
	for _, ip := range stub.dynamicIPs {
		if ip == "9.9.9.9" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected the resolved address in the dynamic set, got: %v", stub.dynamicIPs)
	}
}

// TestRefreshAllowedIPs_NeverRewritesRules is the regression guard for the bug
// this design replaced.
//
// The old refresher rebuilt the whole rule set on every change: it appended a
// fresh batch of accept rules *behind* the still-present default reject, then
// deleted the previous handles one exec at a time. For the length of that
// teardown, any address present only in the new batch was rejected — so the
// firewall was at its most closed exactly when an address had just rotated and
// the container most needed the new one.
//
// Rules now reference nft sets by name and never change. Refreshing must
// therefore touch elements only, never rules.
func TestRefreshAllowedIPs_NeverRewritesRules(t *testing.T) {
	stub := &stubNft{}
	m := newManagerForRefreshTest(t, stub,
		map[string][]string{"stale.example.invalid": {"9.9.9.9"}},
		[]string{"stale.example.invalid"},
	)

	if _, err := m.refreshAllowedIPs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, forbidden := range []string{"ReplaceAllowlist", "ApplyAllowlist", "RemoveRules"} {
		if stub.called(forbidden) {
			t.Errorf("refreshAllowedIPs must not call %s — rules are stable and only set elements change; calls: %v",
				forbidden, stub.calls)
		}
	}
}

// TestRefreshAllowedIPs_LiteralEntriesAreNotResolved verifies that raw IP and
// CIDR entries are treated as static set elements, installed once at setup, and
// are never handed to the resolver or re-installed by the refresher.
func TestRefreshAllowedIPs_LiteralEntriesAreNotResolved(t *testing.T) {
	stub := &stubNft{}
	m := newManagerForRefreshTest(t, stub, map[string][]string{}, []string{"8.8.8.8", "10.0.0.0/8"})

	if _, err := m.refreshAllowedIPs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stub.calls) != 0 {
		t.Errorf("an allowlist of only literal addresses gives the refresher nothing to do, got calls: %v", stub.calls)
	}
}

// TestRefreshAllowedIPs_NoPolicyIsNoOp guards the restricted/open-mode paths,
// where no allowlist policy is ever compiled.
func TestRefreshAllowedIPs_NoPolicyIsNoOp(t *testing.T) {
	stub := &stubNft{}
	m := newManagerForRefreshTest(t, stub, map[string][]string{}, []string{"example.invalid"})
	m.policy = nil

	if _, err := m.refreshAllowedIPs(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stub.calls) != 0 {
		t.Errorf("expected no nft calls without a policy, got: %v", stub.calls)
	}
}

// TestOtherContainersRunning covers the bridge-rule teardown decision logic.
// The fix ensures that on JSON parse failure the function returns true
// (conservative: keep rules) instead of the former false (remove rules).
func TestOtherContainersRunning(t *testing.T) {
	tests := []struct {
		name       string
		json       string
		exclude    string
		wantResult bool
	}{
		{
			name:       "invalid JSON returns true (conservative)",
			json:       "not json at all",
			exclude:    "coi-abc",
			wantResult: true,
		},
		{
			name:       "empty JSON array returns false",
			json:       `[]`,
			exclude:    "coi-abc",
			wantResult: false,
		},
		{
			name:       "only excluded container running returns false",
			json:       `[{"name":"coi-abc","state":{"status":"Running"}}]`,
			exclude:    "coi-abc",
			wantResult: false,
		},
		{
			name:       "another running container returns true",
			json:       `[{"name":"coi-abc","state":{"status":"Running"}},{"name":"coi-xyz","state":{"status":"Running"}}]`,
			exclude:    "coi-abc",
			wantResult: true,
		},
		{
			name:       "other container stopped returns false",
			json:       `[{"name":"coi-abc","state":{"status":"Running"}},{"name":"coi-xyz","state":{"status":"Stopped"}}]`,
			exclude:    "coi-abc",
			wantResult: false,
		},
		{
			name:       "truncated JSON returns true (conservative)",
			json:       `[{"name":"coi-xyz","state":`,
			exclude:    "coi-abc",
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := otherContainersRunning(tt.json, tt.exclude)
			if got != tt.wantResult {
				t.Errorf("otherContainersRunning(%q, %q) = %v, want %v",
					tt.json, tt.exclude, got, tt.wantResult)
			}
		})
	}
}
