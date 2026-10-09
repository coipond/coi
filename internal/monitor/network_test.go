package monitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// fakeIncusInfo simulates the output of `incus info <container>` for PID parsing tests.
const fakeIncusInfoOutput = `Name: coi-test-1
Status: Running
Type: container
Architecture: x86_64
PID: 12345
Created: 2024/01/01 00:00 UTC`

const fakeIncusInfoOutputLowercase = `Name: coi-test-2
Status: Running
Pid: 99
Created: 2024/01/01 00:00 UTC`

const fakeIncusInfoNoPID = `Name: coi-test-3
Status: Stopped
Created: 2024/01/01 00:00 UTC`

func TestParseContainerInitPID_FromIncusInfoOutput(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantPID int
		wantErr bool
	}{
		{"uppercase PID key", fakeIncusInfoOutput, 12345, false},
		{"lowercase Pid key", fakeIncusInfoOutputLowercase, 99, false},
		{"no PID in output", fakeIncusInfoNoPID, 0, true},
		{"empty output", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid, err := parseInitPIDFromIncusInfo(tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("wantErr=%v got err=%v", tt.wantErr, err)
			}
			if pid != tt.wantPID {
				t.Errorf("want PID %d got %d", tt.wantPID, pid)
			}
		})
	}
}

func TestParseContainerInitPID_StrictPrefix(t *testing.T) {
	// A line containing "PID:" somewhere in the middle must NOT match.
	tricky := "  Description: has a PID: 0 in the middle\nPID: 777\n"
	pid, err := parseInitPIDFromIncusInfo(tricky)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 777 {
		t.Errorf("want 777 got %d", pid)
	}
}

func TestParseConnections_FallbackEmptyContainerIP(t *testing.T) {
	// When PID resolution fails and containerIP is empty the fallback must
	// return nil rather than all host connections.
	ctx := context.Background()
	// Use a syntactically invalid container name so Incus always errors out,
	// guaranteeing the fallback path is exercised regardless of the environment.
	conns, err := parseConnections(ctx, "INVALID/CONTAINER/NAME", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("expected empty result when containerIP is empty, got %d connections", len(conns))
	}
}

func TestParseHexIP_LittleEndian(t *testing.T) {
	// Linux /proc/net/tcp stores IPs in little-endian byte order.
	// 10.0.0.2 is encoded as 0200000A (bytes reversed).
	ip, err := parseHexIP("0200000A")
	if err != nil {
		t.Fatalf("parseHexIP error: %v", err)
	}
	if ip != "10.0.0.2" {
		t.Errorf("want 10.0.0.2 got %s", ip)
	}
}

// procNetTCPHeader is the standard header line found in /proc/net/tcp and /proc/net/udp.
const procNetTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

// procNetTCPEstabLine: 10.0.0.2:51820 -> 8.8.8.8:4444 ESTABLISHED (state 01)
// 10.0.0.2  = 0200000A (little-endian), port 51820 = CA6C
// 8.8.8.8   = 08080808 (little-endian), port 4444  = 115C
const procNetTCPEstabLine = "   0: 0200000A:CA6C 08080808:115C 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0"

func TestParseProcNetTCP_ESTAB(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "tcp")
	content := procNetTCPHeader + "\n" + procNetTCPEstabLine + "\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	conns, err := parseProcNetTCP(f, "tcp")
	if err != nil {
		t.Fatalf("parseProcNetTCP error: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("want 1 connection, got %d", len(conns))
	}
	c := conns[0]
	if c.Protocol != "tcp" {
		t.Errorf("protocol: want tcp got %s", c.Protocol)
	}
	if c.LocalAddr != "10.0.0.2:51820" {
		t.Errorf("local addr: want 10.0.0.2:51820 got %s", c.LocalAddr)
	}
	if c.RemoteAddr != "8.8.8.8:4444" {
		t.Errorf("remote addr: want 8.8.8.8:4444 got %s", c.RemoteAddr)
	}
	if c.State != "ESTABLISHED" {
		t.Errorf("state: want ESTABLISHED got %s", c.State)
	}
}

func TestParseProcNetTCP_UDP(t *testing.T) {
	// /proc/net/udp uses the same format as /proc/net/tcp.
	tmp := t.TempDir()
	f := filepath.Join(tmp, "udp")
	content := procNetTCPHeader + "\n" + procNetTCPEstabLine + "\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	conns, err := parseProcNetTCP(f, "udp")
	if err != nil {
		t.Fatalf("parseProcNetTCP error: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("want 1 connection, got %d", len(conns))
	}
	if conns[0].Protocol != "udp" {
		t.Errorf("protocol: want udp got %s", conns[0].Protocol)
	}
}

func TestCheckSuspicious_SuspiciousPort(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:51820",
		RemoteAddr: "8.8.8.8:4444",
		State:      "ESTABLISHED",
	}
	reason := checkSuspicious(conn, nil)
	if reason == "" {
		t.Error("expected port 4444 to be flagged as suspicious, got empty reason")
	}
}

func TestCheckSuspicious_MetadataEndpoint(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:54321",
		RemoteAddr: "169.254.169.254:80",
		State:      "ESTABLISHED",
	}
	reason := checkSuspicious(conn, nil)
	if reason != "Cloud metadata endpoint access" {
		t.Errorf("want 'Cloud metadata endpoint access' got %q", reason)
	}
}

func TestCheckSuspicious_LISTEN_NotFlagged(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "0.0.0.0:4444",
		RemoteAddr: "0.0.0.0:0",
		State:      "LISTEN",
	}
	reason := checkSuspicious(conn, nil)
	if reason != "" {
		t.Errorf("LISTEN state should not be flagged, got %q", reason)
	}
}

func TestCheckSuspicious_RFC1918_RestrictedMode(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:51820",
		RemoteAddr: "192.168.1.1:80",
		State:      "ESTABLISHED",
	}
	// With allowedCIDRs set (restricted mode), RFC1918 should be flagged.
	reason := checkSuspicious(conn, []string{"8.8.8.8/32"})
	if reason == "" {
		t.Error("RFC1918 address should be flagged in restricted mode")
	}
}

// A private [[network.hosts]] entry in allowlist mode is on the allowlist the
// firewall permits, so connecting to it is not a threat; any other private
// address still is.
func TestCheckSuspicious_RFC1918_AllowlistedHostEntry(t *testing.T) {
	allowed := []string{"140.82.112.3/32", "10.50.0.100/32"}
	conn := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:51820", RemoteAddr: "10.50.0.100:443", State: "ESTABLISHED"}
	if reason := checkSuspicious(conn, allowed); reason != "" {
		t.Errorf("allowlisted private host should not be flagged, got %q", reason)
	}
	conn.RemoteAddr = "10.50.0.101:443"
	if reason := checkSuspicious(conn, allowed); reason == "" {
		t.Error("a private address not on the allowlist must still be flagged")
	}
}

func TestCheckSuspicious_RFC1918_OpenMode(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:51820",
		RemoteAddr: "192.168.1.1:80",
		State:      "ESTABLISHED",
	}
	// With no allowedCIDRs (open mode), RFC1918 should NOT be flagged.
	reason := checkSuspicious(conn, nil)
	if reason != "" {
		t.Errorf("RFC1918 should not be flagged in open mode, got %q", reason)
	}
}
