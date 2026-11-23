package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// fakeConfigIncus puts an incus on PATH that keeps runtimeHostPortsKey in a
// file (config get/set/unset), logs every call and answers the rest with
// nothing. It returns the key file and the log.
func fakeConfigIncus(t *testing.T) (keyPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath, logPath = filepath.Join(dir, "key"), filepath.Join(dir, "incus.log")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
*"config get "*` + runtimeHostPortsKey + `*) cat ` + keyPath + ` 2>/dev/null ;;
*"config set "*) for a in "$@"; do case "$a" in ` + runtimeHostPortsKey + `=*) printf '%s' "${a#*=}" > ` + keyPath + ` ;; esac; done ;;
*"config unset "*) rm -f ` + keyPath + ` ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return keyPath, logPath
}

func readKey(t *testing.T, keyPath string) string {
	t.Helper()
	b, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A second `coi hosts add --ports` keeps the first entry's ports.
func TestRecordRuntimeHostPorts_Merges(t *testing.T) {
	keyPath, _ := fakeConfigIncus(t)
	c := "coi-rhp-merge"
	if err := recordRuntimeHostPorts(c, config.HostEntry{IP: "192.168.1.50", Ports: []int{8080}}); err != nil {
		t.Fatal(err)
	}
	if err := recordRuntimeHostPorts(c, config.HostEntry{IP: "192.168.1.60", Ports: []int{1234, 443}}); err != nil {
		t.Fatal(err)
	}
	if got, want := readKey(t, keyPath), "192.168.1.50=8080 192.168.1.60=1234,443"; got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

func TestClearRuntimeHostPorts(t *testing.T) {
	keyPath, _ := fakeConfigIncus(t)
	if err := os.WriteFile(keyPath, []byte("203.0.113.10=8080"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ClearRuntimeHostPorts("coi-rhp-clear"); err != nil {
		t.Fatal(err)
	}
	if got := readKey(t, keyPath); got != "" {
		t.Errorf("key after clear = %q, want none", got)
	}
}

// Session setup drops a record left by an earlier session, also when the
// config has no [[network.hosts]] (the firewall it described is gone).
func TestSetupForContainer_ClearsRuntimeHostPorts(t *testing.T) {
	keyPath, _ := fakeConfigIncus(t)
	if err := os.WriteFile(keyPath, []byte("203.0.113.10=8080"), 0o600); err != nil {
		t.Fatal(err)
	}
	useSudo := false
	cfg := &config.NetworkConfig{Mode: config.NetworkModeOpen, UseSudo: &useSudo}
	_ = NewManager(cfg, logger.NewDiscard()).SetupForContainer(context.Background(), "coi-rhp-setup")
	if got := readKey(t, keyPath); got != "" {
		t.Errorf("key after setup = %q, want none", got)
	}
}

// `coi hosts add --ports` records its ports for the monitors.
func TestAddUserHost_RecordsPorts(t *testing.T) {
	if !hostInterfaceExists("lo") {
		t.Skip("no /sys/class/net/lo")
	}
	keyPath, logPath := fakeConfigIncus(t)
	sudoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sudoDir, "sudo"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", sudoDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := "coi-rhp-add"
	instanceNetCache.Store(c, instanceNet{ip: "10.47.0.5", veth: "lo", at: time.Now()})
	t.Cleanup(func() { instanceNetCache.Delete(c) })

	entry := config.HostEntry{IP: "192.168.1.50", Hostnames: []string{"svc.lan"}, Ports: []int{8080}}
	if err := AddUserHost(c, config.NetworkModeRestricted, false, entry, nil); err != nil {
		log, _ := os.ReadFile(logPath)
		t.Fatalf("AddUserHost: %v\nincus calls:\n%s", err, log)
	}
	if got := readKey(t, keyPath); got != "192.168.1.50=8080" {
		t.Errorf("key = %q, want 192.168.1.50=8080", got)
	}

	// Without ports there is nothing to record.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	entry = config.HostEntry{IP: "192.168.1.60", Hostnames: []string{"other.lan"}}
	if err := AddUserHost(c, config.NetworkModeRestricted, false, entry, []int{443}); err != nil {
		t.Fatal(err)
	}
	if got := readKey(t, keyPath); got != "" {
		t.Errorf("key = %q, want none", got)
	}
}
