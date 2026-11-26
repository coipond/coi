package monitor

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
)

// rejectNotListed is a firewall verdict for an allowlist of 140.82.112.3 only.
func rejectNotListed(_, ip string, _ int) bool { return ip == "140.82.112.3" }

// flagConn flags conn as CollectNetworkStats does in allowlist mode.
func flagConn(conn Connection, permitted PermittedDestinationFunc) Connection {
	conn.SuspectReason = checkSuspicious(conn, config.NetworkModeAllowlist, []string{"140.82.112.3/32"}, permitted, nil, nil)
	if conn.SuspectReason != "" {
		conn.Suspicious = true
		conn.FirewallRejected = firewallRejects(conn, permitted)
	}
	return conn
}

func analyzeConns(d *Detector, ts time.Time, conns ...Connection) []ThreatEvent {
	return d.Analyze(MonitorSnapshot{Timestamp: ts, Network: NetworkStats{Connections: conns}})
}

func synSent(remote string) Connection {
	return Connection{Protocol: "tcp", LocalAddr: "10.47.62.50:40000", RemoteAddr: remote, State: "SYN_SENT"}
}

// A single `curl --noproxy '*' https://<unlisted>` the firewall rejects is a
// WARNING: audited, and no pause even with auto_pause_on_high.
func TestRejectedConnection_SingleAttemptWarns(t *testing.T) {
	d := NewDetector(0, 0)
	threats := analyzeConns(d, time.Now(), flagConn(synSent("93.184.215.14:443"), rejectNotListed))
	if len(threats) != 1 || threats[0].Level != ThreatLevelWarning {
		t.Fatalf("want one WARNING, got %+v", threats)
	}
	if !strings.Contains(threats[0].Description, "rejected by the firewall") {
		t.Errorf("description should say the firewall rejected it: %q", threats[0].Description)
	}

	var action string
	r := NewResponder("test-container", true, true, nil, func(t ThreatEvent) { action = t.Action })
	if err := r.Handle(context.Background(), threats[0]); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if action != "alerted" || r.paused {
		t.Errorf("WARNING must be alerted without a pause, got action %q paused=%v", action, r.paused)
	}
}

// Rejected attempts to the threshold of distinct destinations within the
// window are HIGH; a repeat to the same destination does not count.
func TestRejectedConnection_BurstEscalates(t *testing.T) {
	d := NewDetector(0, 0).WithRejectedBurst(3, time.Minute)
	ts := time.Now()
	for i, remote := range []string{"93.184.215.14:443", "93.184.215.14:443", "93.184.215.15:443"} {
		threats := analyzeConns(d, ts.Add(time.Duration(i)*time.Second), flagConn(synSent(remote), rejectNotListed))
		if len(threats) != 1 || threats[0].Level != ThreatLevelWarning {
			t.Fatalf("attempt %d to %s: want WARNING, got %+v", i, remote, threats)
		}
	}
	threats := analyzeConns(d, ts.Add(3*time.Second), flagConn(synSent("93.184.215.16:80"), rejectNotListed))
	if len(threats) != 1 || threats[0].Level != ThreatLevelHigh {
		t.Fatalf("third distinct destination: want HIGH, got %+v", threats)
	}
	if !strings.Contains(threats[0].Description, "3 distinct rejected destinations") {
		t.Errorf("description should give the count: %q", threats[0].Description)
	}
}

// A connection the firewall lets through but the monitor does not expect stays
// HIGH: no verdict, an ESTABLISHED TCP connection, or a suspicious port on a
// destination the firewall permits.
func TestRejectedConnection_PermittedUnexpectedStaysHigh(t *testing.T) {
	established := synSent("93.184.215.14:443")
	established.State = "ESTABLISHED"
	for _, tc := range []struct {
		name      string
		conn      Connection
		permitted PermittedDestinationFunc
	}{
		{"no verdict", synSent("93.184.215.14:443"), nil},
		{"established", established, rejectNotListed},
		{"suspicious port", synSent("140.82.112.3:1234"), rejectNotListed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			threats := analyzeConns(NewDetector(0, 0), time.Now(), flagConn(tc.conn, tc.permitted))
			if len(threats) != 1 || threats[0].Level != ThreatLevelHigh {
				t.Fatalf("want one HIGH, got %+v", threats)
			}
		})
	}
}

// A rejected UDP socket is an attempt even when connected (ESTABLISHED), and a
// CRITICAL check is not lowered by the verdict.
func TestRejectedConnection_UDPAndCritical(t *testing.T) {
	udp := Connection{Protocol: "udp", LocalAddr: "10.47.62.50:40000", RemoteAddr: "10.0.0.1:80", State: "ESTABLISHED"}
	threats := analyzeConns(NewDetector(0, 0), time.Now(), flagConn(udp, rejectNotListed))
	if len(threats) != 1 || threats[0].Level != ThreatLevelWarning {
		t.Fatalf("connected UDP to a rejected LAN host: want WARNING, got %+v", threats)
	}
	threats = analyzeConns(NewDetector(0, 0), time.Now(), flagConn(synSent("93.184.215.14:4444"), rejectNotListed))
	if len(threats) != 1 || threats[0].Level != ThreatLevelCritical {
		t.Fatalf("C2 port 4444: want CRITICAL, got %+v", threats)
	}
}

func TestRejectedBurst_Window(t *testing.T) {
	b := NewRejectedBurst(2, 10*time.Second)
	ts := time.Now()
	if level, _ := b.Rate("1.1.1.1:443", ts); level != ThreatLevelWarning {
		t.Fatalf("first: want WARNING, got %s", level)
	}
	if level, _ := b.Rate("1.1.1.2:443", ts.Add(11*time.Second)); level != ThreatLevelWarning {
		t.Fatalf("second, after the first left the window: want WARNING, got %s", level)
	}
	if level, _ := b.Rate("1.1.1.3:443", ts.Add(12*time.Second)); level != ThreatLevelHigh {
		t.Fatalf("two within the window: want HIGH, got %s", level)
	}
}

func TestNewRejectedBurst_Defaults(t *testing.T) {
	b := NewRejectedBurst(0, 0)
	if b.threshold != DefaultRejectedBurstDestinations || b.window != DefaultRejectedBurstWindowSec*time.Second {
		t.Errorf("defaults: got %d / %s", b.threshold, b.window)
	}
	ts := time.Now()
	for i := range DefaultRejectedBurstDestinations - 1 {
		if level, _ := b.Rate(fmt.Sprintf("1.1.1.%d:443", i), ts); level != ThreatLevelWarning {
			t.Fatalf("destination %d: want WARNING, got %s", i+1, level)
		}
	}
	if level, _ := b.Rate("1.1.2.1:443", ts); level != ThreatLevelHigh {
		t.Fatalf("destination %d: want HIGH, got %s", DefaultRejectedBurstDestinations, level)
	}
}
