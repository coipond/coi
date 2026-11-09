package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both DNS blocks answer TCP with a reset ahead of the reject, so blocked TCP
// does not use up the container's ICMP rate-limit budget.
func TestBlockDNSAddsTCPResetBeforeEachReject(t *testing.T) {
	logPath := fakeNftSudo(t, "")
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	if err := f.blockDNS(); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	for _, chain := range []string{"forward", "input"} {
		prefix := "add rule ip coi " + chain + " ip saddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 "
		reset := strings.Index(calls, prefix+"meta l4proto tcp reject with tcp reset")
		reject := strings.Index(calls, prefix+"reject comment")
		if reset < 0 || reject < 0 || reset > reject {
			t.Errorf("%s: want the TCP reset rule before the reject, calls:\n%s", chain, calls)
		}
	}
}

// Allowlist setup stops the container's resolver in the same exec as the IPv6
// sysctl, so no blocked upstream query costs an ICMP error.
func TestDisableIPv6AndResolverForContainer(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incus.log")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := DisableIPv6AndResolverForContainer("c1"); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	if n := strings.Count(calls, "exec"); n != 1 {
		t.Errorf("want one incus exec, got %d:\n%s", n, calls)
	}
	for _, want := range []string{"disable_ipv6=1", "systemctl mask --runtime systemd-resolved.service", "systemctl stop systemd-resolved.service"} {
		if !strings.Contains(calls, want) {
			t.Errorf("exec must contain %q, got:\n%s", want, calls)
		}
	}
}
