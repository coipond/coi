package monitor

import (
	"context"
	"fmt"
	"strconv"
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
// HIGH: no verdict, a TCP socket past SYN_SENT (its handshake got through), or
// a suspicious port on a destination the firewall permits.
func TestRejectedConnection_PermittedUnexpectedStaysHigh(t *testing.T) {
	type testCase struct {
		name      string
		conn      Connection
		permitted PermittedDestinationFunc
	}
	cases := []testCase{
		{"no verdict", synSent("93.184.215.14:443"), nil},
		{"suspicious port", synSent("140.82.112.3:1234"), rejectNotListed},
	}
	for _, state := range []string{"ESTABLISHED", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK", "CLOSING"} {
		conn := synSent("93.184.215.14:443")
		conn.State = state
		cases = append(cases, testCase{state, conn, rejectNotListed})
	}
	for _, tc := range cases {
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

// A burst HIGH for a destination first seen as a WARNING within the
// responder's dedupe window still gets its response.
func TestRejectedConnection_BurstHighNotDeduplicated(t *testing.T) {
	d := NewDetector(0, 0).WithRejectedBurst(3, 10*time.Second)
	var alerted []ThreatLevel
	r := NewResponder("test-container", false, false, nil, func(t ThreatEvent) { alerted = append(alerted, t.Level) })
	ts := time.Now()
	for _, step := range []struct {
		remote string
		at     int
		want   ThreatLevel
	}{
		{"93.184.215.1:443", 0, ThreatLevelWarning},
		{"93.184.215.2:443", 11, ThreatLevelWarning},
		{"93.184.215.3:443", 12, ThreatLevelWarning},
		{"93.184.215.1:443", 13, ThreatLevelHigh},
	} {
		threats := analyzeConns(d, ts.Add(time.Duration(step.at)*time.Second), flagConn(synSent(step.remote), rejectNotListed))
		if len(threats) != 1 || threats[0].Level != step.want {
			t.Fatalf("%s at %ds: want %s, got %+v", step.remote, step.at, step.want, threats)
		}
		if err := r.Handle(context.Background(), threats[0]); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}
	if len(alerted) != 4 || alerted[3] != ThreatLevelHigh {
		t.Errorf("the HIGH must be alerted, not deduplicated; alerts: %v", alerted)
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

// A later attempt keeps its destination in the window after its first one
// expires, and the queue stays bounded by the attempts within the window.
func TestRejectedBurst_RepeatKeepsDestination(t *testing.T) {
	b := NewRejectedBurst(2, 10*time.Second)
	ts := time.Now()
	b.Rate("1.1.1.1:443", ts)
	b.Rate("1.1.1.1:443", ts.Add(8*time.Second))
	if level, _ := b.Rate("1.1.1.2:443", ts.Add(12*time.Second)); level != ThreatLevelHigh {
		t.Fatalf("1.1.1.1 retried within the window: want HIGH, got %s", level)
	}
	for i := range 1000 {
		b.Rate(fmt.Sprintf("2.2.%d.%d:443", i/256, i%256), ts.Add(time.Duration(100+i)*time.Second))
	}
	if len(b.queue) > 11 || len(b.seen) > 11 {
		t.Errorf("one attempt per second, 10 s window: queue %d, seen %d", len(b.queue), len(b.seen))
	}
}

func BenchmarkRejectedBurst_Scan(b *testing.B) {
	rb := NewRejectedBurst(0, 0)
	ts := time.Now()
	for i := 0; b.Loop(); i++ {
		rb.Rate(strconv.Itoa(i), ts.Add(time.Duration(i)*10*time.Millisecond))
	}
}

func TestNewRejectedBurst_Defaults(t *testing.T) {
	b := NewRejectedBurst(0, 0)
	if b.threshold != DefaultRejectedBurstThreshold || b.window != DefaultRejectedBurstWindowSec*time.Second {
		t.Errorf("defaults: got %d / %s", b.threshold, b.window)
	}
	ts := time.Now()
	for i := range DefaultRejectedBurstThreshold - 1 {
		if level, _ := b.Rate(fmt.Sprintf("1.1.1.%d:443", i), ts); level != ThreatLevelWarning {
			t.Fatalf("destination %d: want WARNING, got %s", i+1, level)
		}
	}
	if level, _ := b.Rate("1.1.2.1:443", ts); level != ThreatLevelHigh {
		t.Fatalf("destination %d: want HIGH, got %s", DefaultRejectedBurstThreshold, level)
	}
}
