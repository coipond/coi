package monitor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
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
	conns, _, err := parseConnections(ctx, "INVALID/CONTAINER/NAME", "")
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
	reason := checkSuspicious(conn, config.NetworkModeOpen, nil, nil, nil, nil)
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
	reason := checkSuspicious(conn, config.NetworkModeOpen, nil, nil, nil, nil)
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
	reason := checkSuspicious(conn, config.NetworkModeOpen, nil, nil, nil, nil)
	if reason != "" {
		t.Errorf("LISTEN state should not be flagged, got %q", reason)
	}
}

// An unconnected UDP6 socket reads as :::0.
func TestCheckSuspicious_Loopback_NotFlagged(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:8080", "127.0.0.53:53", "::1:53", "0.0.0.0:80", ":::0", "::ffff:127.0.0.1:53", "127.0.0.2:8080", "127.0.1.1:5432"} {
		conn := Connection{Protocol: "udp", LocalAddr: "127.0.0.1:39386", RemoteAddr: remote, State: "ESTABLISHED"}
		if reason := checkSuspicious(conn, config.NetworkModeAllowlist, []string{"1.1.1.1/32"}, nil, nil, nil); reason != "" {
			t.Errorf("%s should not be flagged, got %q", remote, reason)
		}
	}
}

func TestCheckSuspicious_RFC1918_RestrictedMode(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:51820",
		RemoteAddr: "192.168.1.1:80",
		State:      "ESTABLISHED",
	}
	// Restricted mode has no allowlist.
	reason := checkSuspicious(conn, config.NetworkModeRestricted, nil, nil, nil, nil)
	if !strings.Contains(reason, "Private address") {
		t.Errorf("RFC1918 address should be flagged in restricted mode, got %q", reason)
	}

	conn.RemoteAddr = "100.101.1.2:22" // RFC 6598 shared address space (Tailscale)
	if reason := checkSuspicious(conn, config.NetworkModeRestricted, nil, nil, nil, nil); !strings.Contains(reason, "Private address") {
		t.Errorf("100.64.0.0/10 address should be flagged in restricted mode, got %q", reason)
	}
	conn.RemoteAddr = "100.128.0.1:22"
	if reason := checkSuspicious(conn, config.NetworkModeRestricted, nil, nil, nil, nil); strings.Contains(reason, "Private address") {
		t.Errorf("100.128.0.1 is public, got %q", reason)
	}
}

func TestCheckSuspicious_RFC1918_ByMode(t *testing.T) {
	conn := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:51820", RemoteAddr: "192.168.1.1:80", State: "ESTABLISHED"}
	permitted := func(_, ip string, port int) bool { return ip == "192.168.1.1" && port == 80 }
	for _, tc := range []struct {
		mode      config.NetworkMode
		allowed   []string
		permitted PermittedDestinationFunc
		flagged   bool
	}{
		{config.NetworkModeRestricted, nil, nil, true},
		{config.NetworkModeRestricted, nil, permitted, false},
		{config.NetworkModeAllowlist, []string{"140.82.112.3/32"}, nil, true},
		{config.NetworkModeAllowlist, []string{"140.82.112.3/32"}, permitted, false},
		{config.NetworkModeOpen, nil, nil, false},
	} {
		reason := checkSuspicious(conn, tc.mode, tc.allowed, tc.permitted, nil, nil)
		if flagged := strings.Contains(reason, "Private address"); flagged != tc.flagged {
			t.Errorf("mode %q permitted=%t: got %q, want flagged=%t", tc.mode, tc.permitted != nil, reason, tc.flagged)
		}
	}
}

// A destination the firewall permits (a [[network.hosts]] LAN service on its
// port) is neither a private-network nor an allowlist violation. The exemption is
// port-aware: another port on that host, or another private host, is still
// flagged, and the other checks (C2 ports) still apply to the permitted host.
func TestCheckSuspicious_FirewallPermittedDestination(t *testing.T) {
	allowed := []string{"140.82.112.3/32"}
	permitted := func(_, ip string, port int) bool { return ip == "10.50.0.100" && (port == 443 || port == 4444) }
	check := func(remote string) string {
		return checkSuspicious(Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:51820", RemoteAddr: remote, State: "ESTABLISHED"}, config.NetworkModeAllowlist, allowed, permitted, nil, nil)
	}
	if reason := check("10.50.0.100:443"); reason != "" {
		t.Errorf("permitted LAN service should not be flagged, got %q", reason)
	}
	if reason := check("10.50.0.100:22"); !strings.Contains(reason, "Private address") {
		t.Errorf("another port on the permitted host must still be flagged as RFC1918, got %q", reason)
	}
	if reason := check("10.50.0.101:443"); !strings.Contains(reason, "Private address") {
		t.Errorf("another private host must still be flagged, got %q", reason)
	}
	if reason := check("10.50.0.100:4444"); !strings.Contains(reason, "Suspicious port") {
		t.Errorf("a C2 port must still be flagged on a permitted host, got %q", reason)
	}
}

// An explicit permit for host:port skips the suspicious-port check for that
// exact host:port only, in every mode.
func TestCheckSuspicious_ExplicitPortPermit(t *testing.T) {
	portPermitted := func(_, ip string, port int) bool {
		return (ip == "203.0.113.10" || ip == "192.168.1.50") && port == 8080
	}
	firewall := func(_, ip string, _ int) bool { return ip == "192.168.1.50" || ip == "192.168.1.60" }
	for _, tc := range []struct {
		mode    config.NetworkMode
		remote  string
		flagged bool
	}{
		{config.NetworkModeRestricted, "203.0.113.10:8080", false},
		{config.NetworkModeOpen, "203.0.113.10:8080", false},
		{config.NetworkModeRestricted, "192.168.1.50:8080", false},
		{config.NetworkModeRestricted, "203.0.113.10:4444", true},
		{config.NetworkModeRestricted, "203.0.113.11:8080", true},
		{config.NetworkModeOpen, "203.0.113.11:8080", true},
		// The firewall permits it, but not on an explicit port.
		{config.NetworkModeRestricted, "192.168.1.60:8080", true},
		{config.NetworkModeAllowlist, "192.168.1.60:8080", true},
	} {
		conn := Connection{Protocol: "tcp", LocalAddr: "10.0.0.2:51820", RemoteAddr: tc.remote, State: "ESTABLISHED"}
		reason := checkSuspicious(conn, tc.mode, nil, firewall, portPermitted, nil)
		if tc.flagged != strings.Contains(reason, "Suspicious port") || (!tc.flagged && reason != "") {
			t.Errorf("mode %q %s: got %q, want flagged=%t", tc.mode, tc.remote, reason, tc.flagged)
		}
	}
}

func TestCheckSuspicious_RFC1918_OpenMode(t *testing.T) {
	conn := Connection{
		Protocol:   "tcp",
		LocalAddr:  "10.0.0.2:51820",
		RemoteAddr: "192.168.1.1:80",
		State:      "ESTABLISHED",
	}
	reason := checkSuspicious(conn, config.NetworkModeOpen, nil, nil, nil, nil)
	if reason != "" {
		t.Errorf("RFC1918 should not be flagged in open mode, got %q", reason)
	}
}

// Bound, unconnected UDP sockets are local; a connected one to a private host
// is not.
func TestCheckSuspicious_UnconnectedUDP(t *testing.T) {
	allowed := []string{"140.82.112.3/32"}
	for _, conn := range []Connection{
		{Protocol: "udp6", LocalAddr: ":::5353", RemoteAddr: ":::0", State: "CLOSE"},
		{Protocol: "udp", LocalAddr: "10.0.0.2:68", RemoteAddr: "0.0.0.0:0", State: "CLOSE"},
	} {
		if reason := checkSuspicious(conn, config.NetworkModeAllowlist, allowed, nil, nil, nil); reason != "" {
			t.Errorf("%s %s should not be flagged, got %q", conn.Protocol, conn.RemoteAddr, reason)
		}
	}
	conn := Connection{Protocol: "udp", LocalAddr: "10.0.0.2:41000", RemoteAddr: "10.0.0.5:53", State: "ESTABLISHED"}
	if reason := checkSuspicious(conn, config.NetworkModeAllowlist, allowed, nil, nil, nil); !strings.Contains(reason, "Private address") {
		t.Errorf("a connected UDP socket to a private host must still be flagged, got %q", reason)
	}
}

// The bridge gateway's DNS and DHCP ports are exempt; another port on the
// gateway, and any other private host, are still flagged.
func TestCheckSuspicious_GatewayDNSAndDHCP(t *testing.T) {
	allowed := []string{"140.82.112.3/32"}
	asked := 0
	gateway := func() string { asked++; return "10.250.0.1" }
	check := func(proto, remote string) string {
		return checkSuspicious(Connection{Protocol: proto, LocalAddr: "10.250.0.5:41000", RemoteAddr: remote, State: "ESTABLISHED"}, config.NetworkModeAllowlist, allowed, nil, nil, gateway)
	}
	for _, tc := range []struct{ proto, remote string }{
		{"udp", "10.250.0.1:53"},
		{"tcp", "10.250.0.1:53"},
		{"udp", "10.250.0.1:67"},
	} {
		if reason := check(tc.proto, tc.remote); reason != "" {
			t.Errorf("%s %s should not be flagged, got %q", tc.proto, tc.remote, reason)
		}
	}
	asked = 0
	for _, tc := range []struct{ proto, remote string }{
		{"tcp", "10.250.0.1:22"},
		{"tcp", "10.250.0.1:67"},
		{"udp", "10.250.0.9:53"},
		{"tcp", "192.168.1.1:53"},
	} {
		if reason := check(tc.proto, tc.remote); !strings.Contains(reason, "Private address") {
			t.Errorf("%s %s must still be flagged, got %q", tc.proto, tc.remote, reason)
		}
	}
	if asked != 2 {
		t.Errorf("gateway asked %d times, want 2 (port 53 only)", asked)
	}
	if reason := checkSuspicious(Connection{Protocol: "udp", LocalAddr: "10.250.0.5:41000", RemoteAddr: "10.250.0.1:53", State: "ESTABLISHED"}, config.NetworkModeAllowlist, allowed, nil, nil, nil); !strings.Contains(reason, "Private address") {
		t.Errorf("without a known gateway, gateway:53 must still be flagged, got %q", reason)
	}
	asked = 0
	if reason := checkSuspicious(Connection{Protocol: "udp", LocalAddr: "10.250.0.5:41000", RemoteAddr: "10.250.0.1:53", State: "ESTABLISHED"}, config.NetworkModeRestricted, nil, nil, nil, gateway); reason != "" || asked != 1 {
		t.Errorf("in restricted mode, gateway:53 got %q and asked the gateway %d times, want none and 1", reason, asked)
	}
	asked = 0
	if reason := checkSuspicious(Connection{Protocol: "udp", LocalAddr: "10.250.0.5:41000", RemoteAddr: "10.250.0.1:53", State: "ESTABLISHED"}, config.NetworkModeOpen, nil, nil, nil, gateway); reason != "" || asked != 0 {
		t.Errorf("in open mode, gateway:53 got %q and asked the gateway %d times, want neither", reason, asked)
	}
}

// routeTable is a container's /proc/net/route with a nested Docker bridge
// (docker0, 172.17.0.0/16) and a route through a host on it.
const routeTable = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	01003C0A	0003	0	0	1024	00000000	0	0	0
eth0	00003C0A	00000000	0001	0	0	1024	00FFFFFF	0	0	0
eth0	01003C0A	00000000	0005	0	0	1024	FFFFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
docker0	0001A8C0	020011AC	0003	0	0	0	00FFFFFF	0	0	0
br-down	000012AC	00000000	0000	0	0	0	0000FFFF	0	0	0
`

func TestContainerLocalNets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(routeTable), 0o644); err != nil {
		t.Fatal(err)
	}
	local := containerLocalNets(path)

	for ip, want := range map[string]bool{
		"172.17.0.2":   true,  // nested Docker container
		"172.17.0.1":   true,  // docker0 itself (docker-proxy source)
		"10.60.0.1":    false, // the bridge gateway, on the uplink
		"10.60.0.7":    false, // another host on the uplink subnet
		"192.168.1.10": false, // routed through a host, leaves docker0
		"172.18.0.2":   false, // route on an interface that is down
		"8.8.8.8":      false,
	} {
		if got := inNets(ip, local); got != want {
			t.Errorf("inNets(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestContainerLocalNets_NoDefaultRouteKeepsIncusNIC(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00003C0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	if local := containerLocalNets(path); inNets("10.60.0.7", local) {
		t.Errorf("the Incus NIC's subnet must not be local: %v", local)
	}
}

func TestContainerLocalNets_DefaultRouteInterfaceIsUplink(t *testing.T) {
	// eth0 enslaved to a bridge in the container: the uplink is br0.
	table := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"br0\t00000000\t01003C0A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"br0\t00003C0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	local := containerLocalNets(path)
	if inNets("10.60.0.7", local) {
		t.Errorf("the default route's interface subnet must not be local: %v", local)
	}
	if !inNets("172.17.0.2", local) {
		t.Errorf("docker0 must be local: %v", local)
	}
}

func TestContainerLocalNets_MissingFile(t *testing.T) {
	if local := containerLocalNets(filepath.Join(t.TempDir(), "none")); local != nil {
		t.Errorf("want no networks, got %v", local)
	}
}

// fakeNetTables gives host pid's network namespace the given lines in its tcp,
// tcp6, udp and udp6 tables (empty tables when lines is nil).
func fakeNetTables(t *testing.T, root string, pid int, tcpLines ...string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid), "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		table := tcpTableHeader
		if name == "tcp" {
			table += strings.Join(tcpLines, "")
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// shareNetns makes host pid share the network namespace of other.
func shareNetns(t *testing.T, root string, pid, other int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(pid)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, strconv.Itoa(other), "net"), filepath.Join(root, strconv.Itoa(pid), "net")); err != nil {
		t.Fatal(err)
	}
}

func TestNestedNetnsConnectionsReadsEachOtherNetnsOnce(t *testing.T) {
	root := fakeSocketProc(t)
	// 10.0.0.5:40000 -> 1.2.3.4:4444 ESTABLISHED
	nested := "   0: 0500000A:9C40 04030201:115C 01 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 20 4 30 10 -1\n"
	main := "   0: 0500000A:9C41 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 555 1 0000000000000000 20 4 30 10 -1\n"
	fakeNetTables(t, root, 40, main)
	shareNetns(t, root, 41, 40)
	fakeNetTables(t, root, 42, nested) // e.g. a Docker container
	shareNetns(t, root, 43, 42)
	// 44 exited: no /proc entry.

	conns := nestedNetnsConnections(40, []int{40, 41, 42, 43, 44})

	if len(conns) != 1 {
		t.Fatalf("got %d connections, want only the nested one once: %+v", len(conns), conns)
	}
	if conns[0].RemoteAddr != "1.2.3.4:4444" || conns[0].Inode != 777 {
		t.Errorf("got %+v, want the nested connection to 1.2.3.4:4444", conns[0])
	}
	if reason := checkSuspicious(conns[0], config.NetworkModeOpen, nil, nil, nil, nil); reason == "" {
		t.Error("nested C2-port connection not flagged")
	}
}

func TestNestedNetnsConnectionsWithoutInitNetns(t *testing.T) {
	root := fakeSocketProc(t)
	fakeNetTables(t, root, 42)
	if conns := nestedNetnsConnections(40, []int{42}); conns != nil {
		t.Errorf("got %+v, want nil when the init netns is unknown", conns)
	}
}

func TestNetnsConnectionsReadsAllTables(t *testing.T) {
	root := fakeSocketProc(t)
	if _, ok := netnsConnections(50); ok {
		t.Error("ok for a pid without tables")
	}
	line := "   0: 0500000A:9C40 04030201:115C 01 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 20 4 30 10 -1\n"
	dir := filepath.Join(root, "50", "net")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(tcpTableHeader+line), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	conns, ok := netnsConnections(50)
	if !ok || len(conns) != 4 {
		t.Fatalf("got %d connections (ok=%v), want one per table", len(conns), ok)
	}
	for i, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if conns[i].Protocol != proto {
			t.Errorf("connection %d protocol %q, want %q", i, conns[i].Protocol, proto)
		}
	}
}
