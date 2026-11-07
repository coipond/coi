package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const zeroSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

// gooseTarball writes a release-shaped tarball (one ./goose member) and
// returns its path and sha256.
func gooseTarball(t *testing.T) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho 'goose 1.57.0'\n")
	if err := tw.WriteHeader(&tar.Header{Name: "./goose", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "goose.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return path, hex.EncodeToString(sum[:])
}

type gooseInstall struct {
	root    string // holds usr/local/bin and etc/goose
	curlLog string // one URL per download
	out     string
	err     error
}

// runInstallGoose runs the REAL install_goose from build.sh with
// /usr/local/bin and /etc/goose redirected into a temp root, and fake curl
// (serves tarball) and uname (prints arch) on PATH. The version comes from
// build.sh; the sha256 values are replaced with x86 and arm.
func runInstallGoose(t *testing.T, arch, tarball, x86, arm string) gooseInstall {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("sha256sum not available")
	}
	res := gooseInstall{root: t.TempDir()}
	fakeBin := t.TempDir()
	res.curlLog = filepath.Join(fakeBin, "curl.log")
	fakes := map[string]string{
		"curl": `#!/bin/bash
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        -*) ;;
        *) url="$1" ;;
    esac
    shift
done
echo "$url" >> "$CURL_LOG"
cp "$FAKE_TARBALL" "$out"
`,
		"uname": "#!/bin/sh\necho \"$FAKE_ARCH\"\n",
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(res.root, "usr", "local", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	driver := `set -euo pipefail
log() { echo "LOG: $*"; }
eval "$(grep -E '^GOOSE_(VERSION|SHA256_[A-Z0-9_]+)=' "$1")"
GOOSE_SHA256_X86_64="$X86"
GOOSE_SHA256_AARCH64="$ARM"
source <(sed -n "/^install_goose()/,/^}/p" "$1" | sed "s#/usr/local/bin#$ROOT/usr/local/bin#g; s#/etc/goose#$ROOT/etc/goose#g")
install_goose
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t))
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
		"ROOT="+res.root, "CURL_LOG="+res.curlLog, "FAKE_TARBALL="+tarball,
		"FAKE_ARCH="+arch, "X86="+x86, "ARM="+arm)
	out, err := cmd.CombinedOutput()
	res.out, res.err = string(out), err
	return res
}

func (g gooseInstall) downloads(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(g.curlLog)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

func (g gooseInstall) binary() string {
	return filepath.Join(g.root, "usr", "local", "bin", "goose")
}

// A tarball with the expected hash installs goose 0755 and the image config
// that turns telemetry off and keeps secrets out of the keyring.
func TestInstallGoose_InstallsVerifiedTarball(t *testing.T) {
	tarball, sum := gooseTarball(t)
	res := runInstallGoose(t, "x86_64", tarball, sum, zeroSHA256)
	if res.err != nil {
		t.Fatalf("install_goose failed: %v\n%s", res.err, res.out)
	}
	want := "https://github.com/aaif-goose/goose/releases/download/v1.57.0/goose-x86_64-unknown-linux-gnu.tar.gz"
	if got := res.downloads(t); len(got) != 1 || got[0] != want {
		t.Errorf("downloads = %v, want [%s]", got, want)
	}
	fi, err := os.Stat(res.binary())
	if err != nil {
		t.Fatalf("goose not installed: %v\n%s", err, res.out)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("goose mode = %v, want 0755", fi.Mode().Perm())
	}
	cfg, err := os.ReadFile(filepath.Join(res.root, "etc", "goose", "config.yaml"))
	if err != nil {
		t.Fatalf("/etc/goose/config.yaml not written: %v", err)
	}
	if string(cfg) != "GOOSE_TELEMETRY_ENABLED: false\nGOOSE_DISABLE_KEYRING: true\n" {
		t.Errorf("/etc/goose/config.yaml = %q", cfg)
	}
}

// A hash mismatch fails the build before anything is unpacked or installed.
func TestInstallGoose_RejectsWrongSHA256(t *testing.T) {
	tarball, _ := gooseTarball(t)
	res := runInstallGoose(t, "x86_64", tarball, zeroSHA256, zeroSHA256)
	if res.err == nil {
		t.Fatalf("install_goose succeeded with a wrong sha256:\n%s", res.out)
	}
	if _, err := os.Stat(res.binary()); err == nil {
		t.Error("goose was installed despite the sha256 mismatch")
	}
	if _, err := os.Stat(filepath.Join(res.root, "etc", "goose")); err == nil {
		t.Error("/etc/goose was written despite the sha256 mismatch")
	}
}

// aarch64 downloads the aarch64 asset and checks it against the aarch64 hash.
func TestInstallGoose_Aarch64UsesItsOwnAssetAndHash(t *testing.T) {
	tarball, sum := gooseTarball(t)
	res := runInstallGoose(t, "aarch64", tarball, zeroSHA256, sum)
	if res.err != nil {
		t.Fatalf("install_goose failed: %v\n%s", res.err, res.out)
	}
	want := "https://github.com/aaif-goose/goose/releases/download/v1.57.0/goose-aarch64-unknown-linux-gnu.tar.gz"
	if got := res.downloads(t); len(got) != 1 || got[0] != want {
		t.Errorf("downloads = %v, want [%s]", got, want)
	}
	if _, err := os.Stat(res.binary()); err != nil {
		t.Errorf("goose not installed: %v", err)
	}
}

// Any other architecture fails without downloading.
func TestInstallGoose_RejectsUnsupportedArch(t *testing.T) {
	tarball, sum := gooseTarball(t)
	res := runInstallGoose(t, "riscv64", tarball, sum, sum)
	if res.err == nil {
		t.Fatalf("install_goose succeeded on riscv64:\n%s", res.out)
	}
	if got := res.downloads(t); len(got) != 0 {
		t.Errorf("downloads = %v, want none", got)
	}
	if _, err := os.Stat(res.binary()); err == nil {
		t.Error("goose was installed on an unsupported arch")
	}
}

// The pinned hashes are the v1.57.0 release asset digests.
func TestInstallGoose_PinnedRelease(t *testing.T) {
	script := string(embeddedCoiBuildScript)
	for _, line := range []string{
		`GOOSE_VERSION="v1.57.0"`,
		`GOOSE_SHA256_X86_64="10eb96cb6a159b6e1d38eeedbef6ab64cd28168aad91948f1fa5c34eefdf98e3"`,
		`GOOSE_SHA256_AARCH64="c32605acfd560aeb2adbf17ec359cc0217e28022a7e647b35a6af5dcfca91749"`,
	} {
		if !strings.Contains(script, "\n"+line+"\n") {
			t.Errorf("build.sh is missing %s", line)
		}
	}
}
