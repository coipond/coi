package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runConfigureBoot runs the REAL configure_boot from build.sh with /etc
// redirected into a temp root, optionally with COI_CLOUD_INIT=1.
func runConfigureBoot(t *testing.T, root string, cloudInit bool) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	driver := `set -euo pipefail
log() { echo "LOG: $*"; }
source <(sed -n "/^configure_boot()/,/^}/p" "$1" | sed "s#/etc/#$ROOT/etc/#g")
configure_boot
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(), "ROOT="+root)
	if cloudInit {
		cmd.Env = append(cmd.Env, "COI_CLOUD_INIT=1")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("configure_boot failed: %v\n%s", err, out)
	}
	return string(out)
}

// By default the image gets coi's own eth0 DHCP config and cloud-init is
// disabled (it otherwise runs ahead of the network on every boot).
func TestConfigureBoot_DisablesCloudInitByDefault(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "cloud"), 0o755); err != nil {
		t.Fatal(err)
	}
	runConfigureBoot(t, root, false)

	netplan := filepath.Join(root, "etc", "netplan", "01-coi-dhcp.yaml")
	b, err := os.ReadFile(netplan)
	if err != nil || !strings.Contains(string(b), "eth0:") || !strings.Contains(string(b), "dhcp4: true") {
		t.Fatalf("netplan DHCP config missing or wrong: %q %v", b, err)
	}
	if fi, _ := os.Stat(netplan); fi.Mode().Perm() != 0o600 {
		t.Errorf("netplan config mode = %v, want 0600 (netplan warns on wider modes)", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "cloud", "cloud-init.disabled")); err != nil {
		t.Error("cloud-init must be disabled by default")
	}
}

// [container.build] cloud_init = true (COI_CLOUD_INIT=1) keeps cloud-init on,
// and also clears a disable marker from a previous build of the base.
func TestConfigureBoot_KeepsCloudInitWhenRequested(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "etc", "cloud", "cloud-init.disabled")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out := runConfigureBoot(t, root, true)
	if _, err := os.Stat(marker); err == nil {
		t.Error("cloud_init = true must leave cloud-init enabled")
	}
	if !strings.Contains(out, "Keeping cloud-init enabled") {
		t.Errorf("want a log line saying cloud-init is kept, got %q", out)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "netplan", "01-coi-dhcp.yaml")); err != nil {
		t.Error("the DHCP config is written either way")
	}
}

// An existing (build-time injected) DHCP config is kept as is.
func TestConfigureBoot_KeepsExistingNetplan(t *testing.T) {
	root := t.TempDir()
	netplan := filepath.Join(root, "etc", "netplan", "01-coi-dhcp.yaml")
	if err := os.MkdirAll(filepath.Dir(netplan), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netplan, []byte("custom\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runConfigureBoot(t, root, false)
	if b, _ := os.ReadFile(netplan); string(b) != "custom\n" {
		t.Errorf("existing netplan config was overwritten: %q", b)
	}
}
