package network

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// TestLogRestrictedPrivateAccess verifies the restricted session log matches the
// RFC1918 and metadata rules addRestrictedRules installs.
func TestLogRestrictedPrivateAccess(t *testing.T) {
	const (
		blockRFC1918  = "Blocking private networks (RFC1918, 100.64.0.0/10)"
		blockMetadata = "Blocking cloud metadata endpoints"
		allowRFC1918  = "Allowing private networks (RFC1918, 100.64.0.0/10"
	)
	on, off := true, false
	tests := []struct {
		name    string
		cfg     config.NetworkConfig
		want    []string
		notWant []string
	}{
		{
			name: "local access off",
			cfg: config.NetworkConfig{
				AllowLocalNetworkAccess: &off,
				BlockPrivateNetworks:    &on,
				BlockMetadataEndpoint:   &on,
			},
			want:    []string{blockRFC1918, blockMetadata},
			notWant: []string{allowRFC1918},
		},
		{
			name: "local access on",
			cfg: config.NetworkConfig{
				AllowLocalNetworkAccess: &on,
				BlockPrivateNetworks:    &on,
				BlockMetadataEndpoint:   &on,
			},
			want:    []string{allowRFC1918 + "; allow_local_network_access)", blockMetadata},
			notWant: []string{blockRFC1918, "on ports"},
		},
		{
			name: "local access on with allowed_ports",
			cfg: config.NetworkConfig{
				AllowLocalNetworkAccess: &on,
				BlockPrivateNetworks:    &on,
				AllowedPorts:            []int{443, 8080},
			},
			want:    []string{allowRFC1918 + ") on ports [443 8080] (allow_local_network_access)"},
			notWant: []string{blockRFC1918, blockMetadata},
		},
		{
			name: "nothing blocked",
			cfg: config.NetworkConfig{
				AllowLocalNetworkAccess: &off,
				BlockPrivateNetworks:    &off,
				BlockMetadataEndpoint:   &off,
			},
			notWant: []string{blockRFC1918, blockMetadata, allowRFC1918},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := logger.New("restricted-log", t.TempDir())
			m := &Manager{config: &tt.cfg, logger: sl}
			m.logRestrictedPrivateAccess()
			_ = sl.Close()

			out, err := os.ReadFile(sl.OutPath())
			if err != nil {
				t.Fatalf("read session log: %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("log missing %q; got: %q", w, out)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(string(out), nw) {
					t.Errorf("log has %q; got: %q", nw, out)
				}
			}
		})
	}
}

// TestLogAllowlistPrivateAccess verifies the allowlist session log matches the
// RFC1918 and metadata rules for allow_local_network_access.
func TestLogAllowlistPrivateAccess(t *testing.T) {
	const (
		blockRFC1918  = "Blocking all private networks (RFC1918, 100.64.0.0/10)"
		blockMetadata = "Blocking cloud metadata endpoints"
		allowRFC1918  = "Allowing private networks (RFC1918, 100.64.0.0/10"
	)
	on, off := true, false
	tests := []struct {
		name    string
		cfg     config.NetworkConfig
		want    []string
		notWant []string
	}{
		{
			name:    "local access off",
			cfg:     config.NetworkConfig{AllowLocalNetworkAccess: &off},
			want:    []string{blockRFC1918, blockMetadata},
			notWant: []string{allowRFC1918},
		},
		{
			name:    "local access on",
			cfg:     config.NetworkConfig{AllowLocalNetworkAccess: &on},
			want:    []string{allowRFC1918 + "; allow_local_network_access)"},
			notWant: []string{blockRFC1918, blockMetadata, "on ports"},
		},
		{
			name:    "local access on, metadata blocked",
			cfg:     config.NetworkConfig{AllowLocalNetworkAccess: &on, BlockMetadataEndpoint: &on},
			want:    []string{allowRFC1918 + "; allow_local_network_access)", blockMetadata},
			notWant: []string{blockRFC1918},
		},
		{
			name: "local access on with allowed_ports",
			cfg: config.NetworkConfig{
				AllowLocalNetworkAccess: &on,
				AllowedPorts:            []int{443, 8080},
			},
			want:    []string{allowRFC1918 + ") on ports [443 8080] (allow_local_network_access)"},
			notWant: []string{blockRFC1918, blockMetadata},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := logger.New("allowlist-log", t.TempDir())
			m := &Manager{config: &tt.cfg, logger: sl}
			m.logAllowlistPrivateAccess()
			_ = sl.Close()

			out, err := os.ReadFile(sl.OutPath())
			if err != nil {
				t.Fatalf("read session log: %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("log missing %q; got: %q", w, out)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(string(out), nw) {
					t.Errorf("log has %q; got: %q", nw, out)
				}
			}
		})
	}
}

// Open mode rejects metadataCIDR ahead of its accept under
// block_metadata_endpoint; a reused container with exactly those rules is
// left alone.
func TestApplyOpenRules_MetadataBlock(t *testing.T) {
	on, off := true, false
	const ip = "10.0.0.2"
	listing := func(texts []string) string {
		var b strings.Builder
		for i, text := range texts {
			fmt.Fprintf(&b, "\t\t%s # handle %d\n", text, 5+i)
		}
		return b.String()
	}
	for _, tc := range []struct {
		name    string
		block   *bool
		listing string
		want    []string // rules added, in order; nil: no nft script
	}{
		{"blocked", &on, "", []string{"ip daddr 169.254.0.0/16 meta l4proto tcp reject with tcp reset", "ip daddr 169.254.0.0/16 reject", "ip saddr 10.0.0.2 accept"}},
		{"not blocked", &off, "", []string{"ip saddr 10.0.0.2 accept"}},
		{"blocked, reused", &on, listing(openModeRuleTexts(ip, true)), nil},
		{"blocked, reused without the reject", &on, listing(openModeRuleTexts(ip, false)), []string{"handle 5", "169.254.0.0/16 meta l4proto tcp reject", "169.254.0.0/16 reject", "accept"}},
		{"not blocked, reused with the reject", &off, listing(openModeRuleTexts(ip, true)), []string{"handle 5", "handle 6", "handle 7", "ip saddr 10.0.0.2 accept"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := fakeNftSudo(t, "table ip coi {\n\tchain forward { # handle 1\n"+tc.listing+"\t}\n}\n", "")
			fakeIncus(t)
			m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen, BlockMetadataEndpoint: tc.block}, logger.NewDiscard())
			m.applyOpenRules(ip)
			calls := readCalls(t, logPath)
			script := calls[strings.Index(calls, "-f -\n")+1:]
			if tc.want == nil {
				if strings.Contains(calls, "-f -") {
					t.Fatalf("reuse must not touch the rules, got:\n%s", calls)
				}
				return
			}
			lines := strings.Split(strings.TrimSpace(script), "\n")
			var got []string
			for _, l := range lines {
				if strings.HasPrefix(l, "delete rule ip coi forward") || strings.HasPrefix(l, "add rule ip coi forward") {
					got = append(got, l)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("script rules = %q, want %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("rule %d = %q, want %q", i, got[i], w)
				}
			}
		})
	}
}

// Open mode's header says whether metadata is blocked; with no usable nft
// the block is not enforced, and the session log and MetadataUnenforced say so.
func TestSetupForContainer_OpenMetadataLog(t *testing.T) {
	on, off := true, false
	prev := SudoEnabled()
	SetSudoAllowed(false)
	t.Cleanup(func() { SetSudoAllowed(prev) })
	for _, tc := range []struct {
		name       string
		block      *bool
		header     string
		unenforced bool
	}{
		{"blocked", &on, "Network mode: open (only cloud metadata endpoints blocked)", true},
		{"not blocked", &off, "Network mode: open (no restrictions)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sl := logger.New("open-log", t.TempDir())
			m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen, BlockMetadataEndpoint: tc.block, UseSudo: &off}, sl)
			if err := m.SetupForContainer(t.Context(), "c1"); err != nil {
				t.Fatal(err)
			}
			_ = sl.Close()
			out, _ := os.ReadFile(sl.OutPath())
			errOut, _ := os.ReadFile(sl.ErrPath())
			if !strings.Contains(string(out), tc.header) {
				t.Errorf("log missing %q; got %q", tc.header, out)
			}
			warned := strings.Contains(string(errOut), "block_metadata_endpoint is not enforced in open mode")
			if warned != tc.unenforced || m.MetadataUnenforced() != tc.unenforced {
				t.Errorf("warned=%v MetadataUnenforced=%v, want %v; stderr log %q", warned, m.MetadataUnenforced(), tc.unenforced, errOut)
			}
		})
	}
}

// When the forward chain cannot be listed, open mode falls back to purge then
// add, and the fallback keeps the metadata reject ahead of the accept.
func TestApplyOpenRules_FallbackKeepsMetadataBlock(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := fmt.Sprintf(`#!/bin/sh
shift 2
echo "$*" >> %q
case "$*" in
"-f -") cat >> %q ;;
*"list chain ip coi forward"*) echo "Error: permission denied" >&2; exit 1 ;;
esac
exit 0
`, logPath, logPath)
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := SudoEnabled()
	SetSudoAllowed(true)
	t.Cleanup(func() { SetSudoAllowed(prev) })

	on := true
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen, BlockMetadataEndpoint: &on}, logger.NewDiscard())
	if !m.applyOpenRules("10.0.0.2") {
		t.Fatal("fallback reported failure")
	}
	calls := readCalls(t, logPath)
	reject := strings.Index(calls, "ip daddr 169.254.0.0/16 meta l4proto tcp reject")
	accept := strings.Index(calls, "ip saddr 10.0.0.2 accept")
	if reject < 0 || accept < reject {
		t.Errorf("fallback must add the metadata reject before the accept, got:\n%s", calls)
	}
}
