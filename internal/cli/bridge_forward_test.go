package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/network"
)

// fakeBridgeHost puts fake `incus`, `sudo` and `iptables` on PATH: running
// container c has an IPv4 address on network, the default profile is on
// incusbr0, the FORWARD policy is DROP and coi's rules are missing. Returns the
// sudo log.
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
	network.ResetBridgeForwardMemo()
	t.Cleanup(func() {
		network.SetSudoAllowed(prev)
		network.ResetBridgeForwardMemo()
	})
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

func restrictedApp() *App {
	cfg := config.GetDefaultConfig()
	cfg.Network.Mode = config.NetworkModeRestricted
	return &App{cfg: cfg}
}

// coi run adds the FORWARD rules for the network the container is on.
func TestApplyNetworkIsolation_ContainerBridge(t *testing.T) {
	sudoLog := fakeBridgeHost(t, "coi-br-3", "coinetrun")
	_, _ = restrictedApp().applyNetworkIsolation(t.Context(), "coi-br-3")
	assertBridgeRules(t, sudoLog, "coinetrun")
}

// coi container start/launch add them too.
func TestIsolateStartedContainer_ContainerBridge(t *testing.T) {
	sudoLog := fakeBridgeHost(t, "coi-br-4", "coinetstart")
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	_ = restrictedApp().isolateStartedContainer(cmd, "coi-br-4")
	assertBridgeRules(t, sudoLog, "coinetstart")
}

// coi run in open mode installs the metadata reject under
// block_metadata_endpoint and returns the manager for teardown; without it
// nothing is installed.
func TestApplyNetworkIsolation_OpenMetadataBlock(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("block=%v", block), func(t *testing.T) {
			dir := t.TempDir()
			sudoLog := filepath.Join(dir, "sudo.log")
			scripts := map[string]string{
				"incus": `#!/bin/sh
case "$*" in
  *"query /1.0/instances/coi-open-run?"*) echo '{"name":"coi-open-run","state":{"network":{"eth0":{"host_name":"vethx","addresses":[{"family":"inet","address":"10.99.0.7"}]}}}}' ;;
esac
exit 0
`,
				"sudo": fmt.Sprintf(`#!/bin/sh
shift
echo "$*" >> %[1]q
case "$*" in
  "nft -f -") cat >> %[1]q ;;
esac
exit 0
`, sudoLog),
			}
			for name, script := range scripts {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("HOME", t.TempDir())
			prev := network.SudoEnabled()
			network.SetSudoAllowed(true)
			t.Cleanup(func() { network.SetSudoAllowed(prev) })

			cfg := config.GetDefaultConfig()
			cfg.Network.Mode = config.NetworkModeOpen
			cfg.Network.BlockMetadataEndpoint = &block
			nm, err := (&App{cfg: cfg}).applyNetworkIsolation(t.Context(), "coi-open-run")
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(sudoLog)
			reject := strings.Contains(string(data), "ip saddr 10.99.0.7 ip daddr 169.254.0.0/16")
			if reject != block || (nm != nil) != block {
				t.Errorf("metadata reject = %v, manager = %v, want %v; sudo calls:\n%s", reject, nm != nil, block, data)
			}
		})
	}
}
