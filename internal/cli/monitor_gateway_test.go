package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// A failed gateway lookup is not kept: the monitor asks again at the next
// socket to a DNS or DHCP port and gets the gateway once Incus answers.
func TestMonitorGateway_RetriesAfterFailure(t *testing.T) {
	dir := t.TempDir()
	failFlag := filepath.Join(dir, "fail")
	if err := os.WriteFile(failFlag, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
[ -e ` + failFlag + ` ] && exit 1
case "$*" in
  *"/1.0/instances/c1?"*) printf '{"name":"c1","expanded_devices":{"eth0":{"type":"nic","network":"coitestbr0"}},"state":{"network":{}}}' ;;
  *"network show coitestbr0"*) printf 'config:\n  ipv4.address: 10.250.0.1/24\n' ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	gateway := monitorGateway("c1")
	if gw := gateway(); gw != "" {
		t.Fatalf("lookup with a failing incus returned %q", gw)
	}
	if err := os.Remove(failFlag); err != nil {
		t.Fatal(err)
	}
	if gw := gateway(); gw != "10.250.0.1" {
		t.Errorf("after a failure the lookup must be retried, got %q", gw)
	}
}
