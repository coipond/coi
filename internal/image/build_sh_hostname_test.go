package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// coi runs its first command once sysinit.target is active (readyProbeScript
// in internal/session/setup.go), so the hostname unit must finish before it.
// With default dependencies it ran after basic.target and that command could
// miss the name in /etc/hosts.
func TestConfigureHostnameFix_RunsBeforeSysinit(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root := t.TempDir()
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	driver := `set -euo pipefail
log() { :; }
systemctl() { echo "systemctl $*" >> "$ROOT/calls"; }
source <(sed -n "/^configure_hostname_fix()/,/^}/p" "$1" | sed "s#/etc/systemd/#$ROOT/etc/systemd/#g")
configure_hostname_fix
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(), "ROOT="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure_hostname_fix failed: %v\n%s", err, out)
	}

	b, err := os.ReadFile(filepath.Join(unitDir, "coi-fix-hostname.service"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for _, want := range []string{"DefaultDependencies=no", "Before=sysinit.target", "WantedBy=sysinit.target"} {
		if !slices.Contains(lines, want) {
			t.Errorf("unit lacks %q:\n%s", want, b)
		}
	}
	if calls, _ := os.ReadFile(filepath.Join(root, "calls")); !strings.Contains(string(calls), "systemctl enable coi-fix-hostname.service") {
		t.Errorf("unit not enabled, calls: %q", calls)
	}
}
