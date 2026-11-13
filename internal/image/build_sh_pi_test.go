package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakePiInstaller mimics https://pi.dev/install.sh run without a TTY (as in
// the image build): it installs into ~/.pi/agent/bin and links itself into
// ~/.local/bin only when that directory is already on PATH. It never writes a
// PATH line to the shell profile; that needs a TTY prompt.
const fakePiInstaller = `set -e
mkdir -p "$HOME/.pi/agent/bin"
printf '#!/bin/sh\necho "pi 1.5.2"\n' > "$HOME/.pi/agent/bin/pi"
chmod +x "$HOME/.pi/agent/bin/pi"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ln -sf ../../.pi/agent/bin/pi "$HOME/.local/bin/pi" ;;
esac
`

// fakeLegacyPiInstaller mimics PI_LEGACY_INSTALL=1: an npm install straight
// into ~/.local/bin, with no ~/.pi/agent/bin launcher.
const fakeLegacyPiInstaller = `set -e
printf '#!/bin/sh\necho "pi 1.5.2"\n' > "$HOME/.local/bin/pi"
chmod +x "$HOME/.local/bin/pi"
`

// runInstallPi runs the REAL install_pi from build.sh with /home and
// /usr/local/bin redirected into a temp root. su is faked as a login shell for
// the code user whose PATH has ~/.local/bin only if it exists, like Ubuntu's
// ~/.profile; curl serves the given installer script.
func runInstallPi(t *testing.T, script string, localBin bool) (root, out string, err error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	root = t.TempDir()
	home := filepath.Join(root, "home", "code")
	for _, dir := range []string{home, filepath.Join(root, "usr", "local", "bin")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if localBin {
		if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fakeBin := t.TempDir()
	installer := filepath.Join(fakeBin, "install.sh")
	if err := os.WriteFile(installer, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "curl"),
		[]byte("#!/bin/sh\ncat \""+installer+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	driver := `set -euo pipefail
CODE_USER=code
log() { echo "LOG: $*"; }
su() {
    local home="$ROOT/home/code" path="$FAKE_BIN:/usr/bin:/bin"
    [ -d "$home/.local/bin" ] && path="$home/.local/bin:$path"
    env -i HOME="$home" PATH="$path" bash -c "${@: -1}"
}
source <(sed -n "/^install_pi()/,/^}/p" "$1" | sed "s#/home/#$ROOT/home/#g; s#/usr/local/bin#$ROOT/usr/local/bin#g")
install_pi
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(), "ROOT="+root, "FAKE_BIN="+fakeBin)
	b, err := cmd.CombinedOutput()
	return root, string(b), err
}

// install_pi links pi system-wide wherever the installer put it: off the code
// user's PATH when nothing created ~/.local/bin first, e.g. agents = ["pi"]
// without claude (#1035), and outside ~/.pi/agent/bin in the legacy layout.
func TestInstallPi_LinksBinary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		script   string
		localBin bool
	}{
		{"pi alone, no ~/.local/bin", fakePiInstaller, false},
		{"~/.local/bin on PATH", fakePiInstaller, true},
		{"legacy npm install into ~/.local/bin", fakeLegacyPiInstaller, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, out, err := runInstallPi(t, tc.script, tc.localBin)
			if err != nil {
				t.Fatalf("install_pi failed: %v\n%s", err, out)
			}
			link := filepath.Join(root, "usr", "local", "bin", "pi")
			got, err := exec.Command(link).Output()
			if err != nil {
				t.Fatalf("/usr/local/bin/pi not runnable: %v\n%s", err, out)
			}
			if strings.TrimSpace(string(got)) != "pi 1.5.2" {
				t.Errorf("/usr/local/bin/pi printed %q", got)
			}
		})
	}
}
