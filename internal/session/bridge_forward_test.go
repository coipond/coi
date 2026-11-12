package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
	"github.com/coipond/coi/internal/network"
)

// fakeBridgeHost puts fake `incus`, `sudo` and `iptables` on PATH: container
// c has an IPv4 address on network, the default profile is on incusbr0, the
// FORWARD policy is DROP and coi's rules are missing. Returns the sudo log.
func fakeBridgeHost(t *testing.T, c, net string) string {
	t.Helper()
	dir := t.TempDir()
	sudoLog := filepath.Join(dir, "sudo.log")
	scripts := map[string]string{
		"incus": fmt.Sprintf(`#!/bin/sh
case "$*" in
  *"query /1.0/instances/%[1]s?"*) echo '{"name":"%[1]s","expanded_devices":{"eth0":{"type":"nic","network":"%[2]s"}},"state":{"network":{"eth0":{"host_name":"veth%[1]s","addresses":[{"family":"inet","address":"10.99.0.5"}]}}}}' ;;
  *"profile device show default"*) printf 'eth0:\n  network: incusbr0\n' ;;
  *"--columns=ns"*) echo '%[1]s,RUNNING' ;;
esac
exit 0
`, c, net),
		"sudo": fmt.Sprintf(`#!/bin/sh
shift
echo "$*" >> %q
case "$*" in
  "iptables -S FORWARD") echo "-P FORWARD DROP" ;;
  "iptables -C"*) exit 1 ;;
esac
exit 0
`, sudoLog),
		"iptables": "#!/bin/sh\necho 'iptables v1.8.10 (nf_tables)'\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	prev := network.SudoEnabled()
	network.SetSudoAllowed(true)
	t.Cleanup(func() { network.SetSudoAllowed(prev) })
	return sudoLog
}

// assertBridgeRules fails unless both coi FORWARD rules went on bridge.
func assertBridgeRules(t *testing.T, sudoLog, bridge string) {
	t.Helper()
	data, _ := os.ReadFile(sudoLog)
	for _, dir := range []string{"-i", "-o"} {
		if !strings.Contains(string(data), "iptables -I FORWARD "+dir+" "+bridge+" ") {
			t.Errorf("no %s %s rule; sudo calls:\n%s", dir, bridge, data)
		}
	}
}

// coi shell adds the FORWARD rules for the network a reused container is on.
func TestPhaseSetupNetwork_ContainerBridge(t *testing.T) {
	sudoLog := fakeBridgeHost(t, "coi-br-1", "coinetshell")
	st := &setupState{
		opts: SetupOptions{
			Logger:  func(string) {},
			Network: NetworkOptions{Config: &config.NetworkConfig{Mode: config.NetworkModeRestricted}},
		},
		result: &SetupResult{ContainerName: "coi-br-1", Logger: logger.NewDiscard()},
	}
	_, _ = st.phaseSetupNetwork(context.Background())
	assertBridgeRules(t, sudoLog, "coinetshell")
}

func TestConfigureContainer_ContainerBridge(t *testing.T) {
	sudoLog := fakeBridgeHost(t, "coi-br-2", "coinetconfigure")
	_, _ = ConfigureContainer(context.Background(), ConfigureOptions{
		ContainerName: "coi-br-2",
		NetworkConfig: &config.NetworkConfig{Mode: config.NetworkModeRestricted},
		Logger:        func(string) {},
	})
	assertBridgeRules(t, sudoLog, "coinetconfigure")
}
