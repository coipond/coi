package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runMirrorFallback sources the REAL configure_apt_mirror /
// restore_default_apt_sources / apt_get from build.sh and runs `script` in bash
// with a temp ubuntu.sources and a fake apt-get on PATH. The fake apt-get logs
// each call and fails while the sources point at the mirror unless okOnMirror.
func runMirrorFallback(t *testing.T, mirror string, okOnMirror, okOnDefault bool, script string) (out, sources string, err error) {
	t.Helper()
	if _, lookErr := exec.LookPath("bash"); lookErr != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "ubuntu.sources")
	if err := os.WriteFile(src, []byte("URIs: http://archive.ubuntu.com/ubuntu\nURIs: http://security.ubuntu.com/ubuntu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	boolStr := map[bool]string{true: "0", false: "1"}
	fake := `#!/bin/sh
echo "apt-get $*" >> "` + filepath.Join(dir, "calls.log") + `"
if grep -q "` + "azure" + `" "` + src + `"; then exit ` + boolStr[okOnMirror] + `; fi
exit ` + boolStr[okOnDefault] + `
`
	if err := os.WriteFile(filepath.Join(bin, "apt-get"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	driver := `set -euo pipefail
log() { echo "LOG: $*"; }
for fn in configure_apt_mirror restore_default_apt_sources apt_get; do
  source <(sed -n "/^${fn}()/,/^}/p" "$1") || { echo "SOURCE_FAILED $fn"; exit 3; }
done
` + script
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"COI_APT_MIRROR="+mirror,
		"COI_APT_SOURCE_FILES="+src,
		"COI_APT_BACKUP_DIR="+filepath.Join(dir, "backup"),
	)
	b, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
	srcNow, _ := os.ReadFile(src)
	return string(b) + string(calls), string(srcNow), err
}

// A failing mirror falls back to the stock archive: sources restored, index
// refreshed, the install retried — and the build continues.
func TestAptGet_FallsBackFromFailingMirror(t *testing.T) {
	out, sources, err := runMirrorFallback(t, "http://azure.archive.ubuntu.com/ubuntu", false, true,
		`configure_apt_mirror; apt_get install -y -qq git && echo INSTALL_OK`)
	if err != nil || !strings.Contains(out, "INSTALL_OK") {
		t.Fatalf("install should succeed via the fallback (err=%v):\n%s", err, out)
	}
	if !strings.Contains(out, "falling back to the default Ubuntu archive") {
		t.Errorf("fallback should be logged:\n%s", out)
	}
	if strings.Contains(sources, "azure") || !strings.Contains(sources, "http://archive.ubuntu.com/ubuntu") {
		t.Errorf("stock sources should be restored, got:\n%s", sources)
	}
	if strings.Count(out, "apt-get install -y -qq git") != 2 || !strings.Contains(out, "apt-get update -qq") {
		t.Errorf("want install, update, install again; calls:\n%s", out)
	}
}

// A working mirror is used as-is: no fallback, sources stay rewritten.
func TestAptGet_UsesWorkingMirror(t *testing.T) {
	out, sources, err := runMirrorFallback(t, "http://azure.archive.ubuntu.com/ubuntu", true, true,
		`configure_apt_mirror; apt_get install -y -qq git && echo INSTALL_OK`)
	if err != nil || !strings.Contains(out, "INSTALL_OK") || strings.Contains(out, "falling back") {
		t.Fatalf("a working mirror should not fall back (err=%v):\n%s", err, out)
	}
	if !strings.Contains(sources, "azure.archive.ubuntu.com") {
		t.Errorf("sources should point at the mirror, got:\n%s", sources)
	}
}

// Without a mirror, a failing apt-get fails the step (no retry loop).
func TestAptGet_NoMirrorFailsNormally(t *testing.T) {
	out, _, _ := runMirrorFallback(t, "", false, false,
		`configure_apt_mirror; if apt_get install -y -qq git; then echo UNEXPECTED_OK; else echo FAILED_AS_EXPECTED; fi`)
	if !strings.Contains(out, "FAILED_AS_EXPECTED") || strings.Contains(out, "falling back") {
		t.Errorf("without a mirror apt_get should just fail:\n%s", out)
	}
	if strings.Count(out, "apt-get install") != 1 {
		t.Errorf("no retry expected without a mirror:\n%s", out)
	}
}

// If the stock archive fails too, the failure propagates.
func TestAptGet_FallbackFailurePropagates(t *testing.T) {
	out, _, _ := runMirrorFallback(t, "http://azure.archive.ubuntu.com/ubuntu", false, false,
		`configure_apt_mirror; if apt_get install -y -qq git; then echo UNEXPECTED_OK; else echo FAILED_AS_EXPECTED; fi`)
	if !strings.Contains(out, "FAILED_AS_EXPECTED") {
		t.Errorf("a failing fallback must still fail the step:\n%s", out)
	}
}
