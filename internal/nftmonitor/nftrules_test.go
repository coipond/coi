package nftmonitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The suspicious-traffic LOG rule covers every private range the firewall
// blocks, including the RFC 6598 shared address space (Tailscale peers).
func TestAddSuspiciousTrafficRule_PrivateRanges(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\nshift 2\necho \"$*\" >> " + logPath + "\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := NewRuleManager(&Config{ContainerIP: "10.0.0.5"}).addSuspiciousTrafficRule(); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "ip daddr { 169.254.169.254 , 10.0.0.0/8 , 172.16.0.0/12 , 192.168.0.0/16 , 100.64.0.0/10 } log"
	if !strings.Contains(string(calls), want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}
