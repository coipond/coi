package monitor

import (
	"reflect"
	"testing"
)

// M1: the collector must prefer the live-allowlist provider when it yields
// entries, and fall back to the static snapshot when the provider is nil or
// returns nothing — so it is never worse than the pre-provider behavior.
func TestCollector_CurrentAllowedCIDRs(t *testing.T) {
	static := []string{"1.1.1.1/32"}

	// No provider → static snapshot.
	c := NewCollector("c", "", "/ws", static)
	if got := c.currentAllowedCIDRs(); !reflect.DeepEqual(got, static) {
		t.Errorf("no provider: got %v want %v", got, static)
	}

	// Provider yields entries → live wins.
	live := []string{"2.2.2.2/32", "3.3.3.3/32"}
	c.SetAllowedCIDRsProvider(func() []string { return live })
	if got := c.currentAllowedCIDRs(); !reflect.DeepEqual(got, live) {
		t.Errorf("live provider: got %v want %v", got, live)
	}

	// Provider returns nothing (read failed / empty) → fall back to static.
	c.SetAllowedCIDRsProvider(func() []string { return nil })
	if got := c.currentAllowedCIDRs(); !reflect.DeepEqual(got, static) {
		t.Errorf("empty provider fallback: got %v want %v", got, static)
	}
}

// A flow seen allowed stays unflagged after its address leaves the allowlist
// (the firewall keeps it open); a new flow to that address is still flagged.
func TestCollector_KeepPermittedFlows(t *testing.T) {
	held := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:40000", RemoteAddr: "2.2.2.2:443", State: "ESTABLISHED"}
	fresh := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:40001", RemoteAddr: "2.2.2.2:443", State: "ESTABLISHED"}
	poll := func(c *Collector, allowed []string, conns ...Connection) NetworkStats {
		stats := NetworkStats{Connections: conns}
		for i := range stats.Connections {
			if reason := checkSuspicious(stats.Connections[i], allowed, nil, nil); reason != "" {
				stats.Connections[i].Suspicious = true
				stats.Connections[i].SuspectReason = reason
				stats.SuspiciousCount++
			}
		}
		c.keepPermittedFlows(&stats)
		return stats
	}

	c := NewCollector("c", "", "/ws", nil)
	if got := poll(c, []string{"2.2.2.2/32"}, held); got.SuspiciousCount != 0 {
		t.Fatalf("allowlisted flow flagged: %+v", got.Connections)
	}

	expired := []string{"1.1.1.1/32"}
	got := poll(c, expired, held, fresh)
	if got.SuspiciousCount != 1 || got.Connections[0].Suspicious || !got.Connections[1].Suspicious {
		t.Fatalf("want only the new flow flagged, got %+v", got.Connections)
	}

	// Closing states keep the exemption: the flow is the same.
	held.State = "TIME_WAIT"
	if got := poll(c, expired, held); got.SuspiciousCount != 0 {
		t.Errorf("closing permitted flow flagged: %+v", got.Connections)
	}

	// A flagged flow never becomes permitted.
	if got := poll(c, expired, fresh); got.SuspiciousCount != 1 {
		t.Errorf("flagged flow must stay flagged: %+v", got.Connections)
	}

	// Only the allowlist check is waived: a C2 port is still flagged.
	c2 := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:40002", RemoteAddr: "2.2.2.2:4444", State: "ESTABLISHED"}
	poll(c, []string{"2.2.2.2/32"}, c2)
	if got := poll(c, expired, c2); got.SuspiciousCount != 1 {
		t.Errorf("C2 port flow must stay flagged: %+v", got.Connections)
	}

	// A flow gone for one poll loses its exemption.
	poll(c, []string{"2.2.2.2/32"}, held)
	poll(c, expired)
	if got := poll(c, expired, held); got.SuspiciousCount != 1 {
		t.Errorf("reused flow after a gap must be flagged: %+v", got.Connections)
	}
}
