package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// The --fix / --dry-run command line must be copy-pasteable: a remediation can
// carry a multi-line `sh -c` script and a rule with spaces and '#'.
func TestShellQuoteArgs(t *testing.T) {
	argv := []string{"sudo", "sh", "-c", "tmp=\"$(mktemp)\"\nprintf '%s\\n' \"$1\" > \"$tmp\"", "sh", "#1000 ALL=(ALL) NOPASSWD: /usr/sbin/nft", "/etc/sudoers.d/coi-nft"}
	got := shellQuoteArgs(argv)
	if !strings.HasPrefix(got, "sudo sh -c '") || !strings.HasSuffix(got, " /etc/sudoers.d/coi-nft") {
		t.Errorf("unexpected rendering: %s", got)
	}
	// Round-trip: a shell must parse it back into exactly the original argv.
	parsed, err := exec.Command("sh", "-c", "set -- "+got+`; for a in "$@"; do printf '%s\0' "$a"; done`).Output()
	if err != nil {
		t.Fatalf("shell could not parse %q: %v", got, err)
	}
	back := strings.Split(strings.TrimSuffix(string(parsed), "\x00"), "\x00")
	if strings.Join(back, "\x01") != strings.Join(argv, "\x01") {
		t.Errorf("round-trip mismatch:\n got  %q\n want %q", back, argv)
	}
	if shellQuoteArgs([]string{"sysctl", "-w", "net.ipv4.ip_forward=1"}) != "sysctl -w net.ipv4.ip_forward=1" {
		t.Error("safe arguments should stay unquoted")
	}
	if shellQuoteArgs([]string{"echo", "=ls"}) != "echo '=ls'" {
		t.Error("a leading '=' must be quoted (zsh =cmd expansion)")
	}
	if shellQuoteArgs([]string{"echo", ""}) != "echo ''" {
		t.Error("an empty argument must be quoted")
	}
}
