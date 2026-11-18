package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runRemoveSnapd runs the REAL remove_snapd from build.sh with its paths
// redirected into root and stub systemctl, dpkg and apt-get on PATH. The dpkg
// stub reports snapd installed while root/installed exists; the apt-get stub
// removes that file unless purgeKeeps is set.
func runRemoveSnapd(t *testing.T, root string, purgeKeeps bool) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	purge := `rm -f "$ROOT/installed"`
	if purgeKeeps {
		purge = "true"
	}
	stubs := map[string]string{
		"systemctl": "exit 0",
		"dpkg":      `[ -e "$ROOT/installed" ]`,
		"apt-get":   `echo "apt-get $*" >> "$ROOT/calls"; ` + purge,
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	driver := `set -euo pipefail
log() { echo "LOG: $*"; }
source <(sed -n "/^remove_snapd()/,/^}/p" "$1" | sed "s# /snap# $ROOT/snap#g; s# /var/# $ROOT/var/#g; s#/etc/#$ROOT/etc/#g")
remove_snapd
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(), "ROOT="+root, "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestRemoveSnapd_PurgesAndPins(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"snap/core/1", "var/lib/snapd/seed", "etc/apt/preferences.d"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "installed"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if out, err := runRemoveSnapd(t, root, false); err != nil {
		t.Fatalf("remove_snapd failed: %v\n%s", err, out)
	}
	if calls, _ := os.ReadFile(filepath.Join(root, "calls")); !strings.Contains(string(calls), "purge -y -qq snapd") {
		t.Errorf("snapd should be purged, apt-get calls: %q", calls)
	}
	for _, p := range []string{"snap", "var/lib/snapd"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s should be removed", p)
		}
	}
	pin, err := os.ReadFile(filepath.Join(root, "etc/apt/preferences.d/no-snapd"))
	if err != nil || !strings.Contains(string(pin), "Package: snapd") || !strings.Contains(string(pin), "Pin-Priority: -10") {
		t.Errorf("snapd should be pinned at -10: %q %v", pin, err)
	}
}

// Without snapd (a base image that does not ship it) there is nothing to
// purge, and the pin is still written.
func TestRemoveSnapd_NotInstalled(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/apt/preferences.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runRemoveSnapd(t, root, false); err != nil {
		t.Fatalf("remove_snapd failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "calls")); err == nil {
		t.Error("apt-get should not run when snapd is not installed")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/apt/preferences.d/no-snapd")); err != nil {
		t.Errorf("the pin should be written: %v", err)
	}
}

// The build fails when snapd is still installed after the purge.
func TestRemoveSnapd_FailsWhenStillInstalled(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/apt/preferences.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "installed"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runRemoveSnapd(t, root, true)
	if err == nil || !strings.Contains(out, "snapd is still installed") {
		t.Errorf("remove_snapd should fail when snapd stays installed, got %v:\n%s", err, out)
	}
}
