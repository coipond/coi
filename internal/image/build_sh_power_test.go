package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writePowerWrappers runs the REAL configure_power_wrappers from build.sh
// with /usr/local redirected into root and returns the bin dir.
func writePowerWrappers(t *testing.T, root string) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	driver := `set -euo pipefail
log() { :; }
source <(sed -n "/^configure_power_wrappers()/,/^}/p" "$1" | sed "s#/usr/local/#$ROOT/usr/local/#g")
mkdir -p "$ROOT/usr/local/bin"
configure_power_wrappers
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(), "ROOT="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("configure_power_wrappers failed: %v\n%s", err, out)
	}
	return filepath.Join(root, "usr", "local", "bin")
}

// runWrapper runs one wrapper with a fake sudo on PATH: sudoOK decides
// whether `sudo -n true` passes; the fake logs every call it gets.
func runWrapper(t *testing.T, bin, name string, sudoOK bool) (string, string, error) {
	t.Helper()
	fake := t.TempDir()
	log := filepath.Join(fake, "sudo.log")
	rc := "1"
	if sudoOK {
		rc = "0"
	}
	script := "#!/bin/bash\necho \"$*\" >> " + log + "\n[ \"$*\" = \"-n true\" ] && exit " + rc + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(fake, "sudo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(bin, name))
	cmd.Env = append(os.Environ(), "PATH="+fake+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(log)
	return string(out), string(calls), err
}

// With sudo every wrapper hands over to coi-power; reboot reboots, the rest
// power off.
func TestPowerWrappers_WithSudo(t *testing.T) {
	bin := writePowerWrappers(t, t.TempDir())
	for _, name := range []string{"poweroff", "halt", "shutdown", "close", "stop", "reboot"} {
		want := "/libexec/coi-power poweroff"
		if name == "reboot" {
			want = "/libexec/coi-power reboot"
		}
		out, calls, err := runWrapper(t, bin, name, true)
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
		if !strings.Contains(calls, want) {
			t.Errorf("%s: sudo calls %q, want one ending in %q", name, calls, want)
		}
	}
}

// Without sudo a wrapper says how to stop the session and never calls
// coi-power.
func TestPowerWrappers_WithoutSudo(t *testing.T) {
	bin := writePowerWrappers(t, t.TempDir())
	for _, name := range []string{"poweroff", "close", "reboot"} {
		out, calls, err := runWrapper(t, bin, name, false)
		if err == nil {
			t.Errorf("%s: want a non-zero exit without sudo", name)
		}
		if !strings.Contains(out, name+": no sudo in this session") || !strings.Contains(out, "coi shutdown") {
			t.Errorf("%s: output %q must explain how to stop the session", name, out)
		}
		if strings.Contains(calls, "coi-power") {
			t.Errorf("%s: coi-power must not run without sudo, sudo calls %q", name, calls)
		}
	}
}
