package image

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type knownHostsRun struct {
	file    string // the written known_hosts
	curlLog string // one URL per fetch
	sshLog  string // any ssh-keyscan, ssh or nc call
	out     string
	err     error
}

// runPopulateKnownHosts runs the REAL populate_known_hosts from build.sh with
// a fake curl that serves ghMeta for api.github.com and bbSSH for
// bitbucket.org, or fails (exit 7, like a refused connection) when the body
// is empty. Fake ssh-keyscan, ssh and nc log any call.
func runPopulateKnownHosts(t *testing.T, ghMeta, bbSSH string) knownHostsRun {
	t.Helper()
	for _, bin := range []string{"bash", "jq", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	fakeBin := t.TempDir()
	res := knownHostsRun{
		file:    filepath.Join(t.TempDir(), "known_hosts"),
		curlLog: filepath.Join(fakeBin, "curl.log"),
		sshLog:  filepath.Join(fakeBin, "ssh.log"),
	}
	bodies := map[string]string{"meta": ghMeta, "bitbucket": bbSSH}
	for name, body := range bodies {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fakes := map[string]string{
		"curl": `#!/bin/bash
url="${*: -1}"
echo "$url" >> "$CURL_LOG"
case "$url" in
    https://api.github.com/meta) body="$FAKE_DIR/meta" ;;
    https://bitbucket.org/site/ssh) body="$FAKE_DIR/bitbucket" ;;
    *) exit 6 ;;
esac
[ -s "$body" ] || exit 7
cat "$body"
`,
		"ssh-keyscan": "#!/bin/sh\necho \"ssh-keyscan $*\" >> \"$SSH_LOG\"\n",
		"ssh":         "#!/bin/sh\necho \"ssh $*\" >> \"$SSH_LOG\"\n",
		"nc":          "#!/bin/sh\necho \"nc $*\" >> \"$SSH_LOG\"\n",
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	driver := `set -euo pipefail
log() { echo "LOG: $*"; }
source <(sed -n '/^known_hosts_embedded()/,/^}/p;/^known_hosts_valid()/,/^}/p;/^populate_known_hosts()/,/^}/p' "$1")
populate_known_hosts "$2"
`
	cmd := exec.Command("bash", "-c", driver, "bash", writeBuildScript(t), res.file)
	cmd.Env = append(os.Environ(),
		"PATH="+fakeBin+":"+os.Getenv("PATH"),
		"FAKE_DIR="+fakeBin, "CURL_LOG="+res.curlLog, "SSH_LOG="+res.sshLog)
	out, err := cmd.CombinedOutput()
	res.out, res.err = string(out), err
	return res
}

func (r knownHostsRun) lines(t *testing.T, host string) []string {
	t.Helper()
	b, err := os.ReadFile(r.file)
	if err != nil {
		t.Fatalf("known_hosts not written: %v\n%s", err, r.out)
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.HasPrefix(l, host+" ") {
			got = append(got, l)
		}
	}
	return got
}

// assertNoPort22 fails when the run called a port-22 tool.
func (r knownHostsRun) assertNoPort22(t *testing.T) {
	t.Helper()
	if b, err := os.ReadFile(r.sshLog); err == nil {
		t.Errorf("build made SSH connections:\n%s", b)
	}
}

// embeddedKnownHosts returns the embedded known_hosts lines of host.
func embeddedKnownHosts(t *testing.T, host string) []string {
	t.Helper()
	body := extractShellFunc(t, string(embeddedCoiBuildScript), "known_hosts_embedded")
	var got []string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, host+" ") {
			got = append(got, l)
		}
	}
	return got
}

// testHostKeys generates an ed25519, an ecdsa and an rsa public key.
func testHostKeys(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir := t.TempDir()
	var keys []string
	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		path := filepath.Join(dir, typ)
		args := []string{"-q", "-t", typ, "-N", "", "-C", "", "-f", path}
		if typ == "rsa" {
			args = append(args, "-b", "2048")
		}
		if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen -t %s: %v\n%s", typ, err, out)
		}
		pub, err := os.ReadFile(path + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, strings.TrimSpace(string(pub)))
	}
	return keys
}

func ghMetaJSON(keys []string) string {
	return `{"verifiable_password_authentication": false, "ssh_keys": ["` +
		strings.Join(keys, `", "`) + `"]}`
}

func prefixed(host string, keys []string) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = host + " " + k
	}
	return out
}

func assertLines(t *testing.T, host string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s lines =\n%s\nwant\n%s", host, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// build.sh never runs ssh-keyscan: the known_hosts step makes no port-22
// connection.
func TestBuildScript_NoSSHKeyscan(t *testing.T) {
	if strings.Contains(string(embeddedCoiBuildScript), "ssh-keyscan") {
		t.Fatal("build.sh runs ssh-keyscan; known_hosts must come over HTTPS or from the embedded keys")
	}
}

// The embedded keys parse and hold ed25519, ecdsa and rsa keys per host.
func TestKnownHostsEmbedded_ValidPerHost(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	for _, host := range []string{"github.com", "gitlab.com", "bitbucket.org"} {
		lines := embeddedKnownHosts(t, host)
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("ssh-keygen", "-l", "-f", path).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen -l on embedded %s keys: %v\n%s", host, err, out)
		}
		for _, typ := range []string{"(ED25519)", "(ECDSA)", "(RSA)"} {
			if !strings.Contains(string(out), host+" "+typ) {
				t.Errorf("embedded %s keys have no %s key:\n%s", host, typ, out)
			}
		}
		if n := strings.Count(strings.TrimSpace(string(out)), "\n") + 1; n != len(lines) {
			t.Errorf("ssh-keygen read %d of %d embedded %s lines", n, len(lines), host)
		}
	}
}

// Valid keys from GitHub /meta and Bitbucket's /site/ssh are written; gitlab.com
// comes from the embedded keys.
func TestPopulateKnownHosts_FetchesOverHTTPS(t *testing.T) {
	gh, bb := testHostKeys(t), testHostKeys(t)
	bbBody := strings.Join(prefixed("bitbucket.org", bb), "\n") + "\n" +
		strings.Join(prefixed("ssh.bitbucket.org", bb), "\n") + "\n"
	res := runPopulateKnownHosts(t, ghMetaJSON(gh), bbBody)
	if res.err != nil {
		t.Fatalf("populate_known_hosts failed: %v\n%s", res.err, res.out)
	}
	assertLines(t, "github.com", res.lines(t, "github.com"), prefixed("github.com", gh))
	assertLines(t, "gitlab.com", res.lines(t, "gitlab.com"), embeddedKnownHosts(t, "gitlab.com"))
	assertLines(t, "bitbucket.org", res.lines(t, "bitbucket.org"), prefixed("bitbucket.org", bb))
	if got := res.lines(t, "ssh.bitbucket.org"); len(got) != 0 {
		t.Errorf("unexpected ssh.bitbucket.org lines: %v", got)
	}
	if strings.Contains(res.out, "WARNING") {
		t.Errorf("unexpected warning:\n%s", res.out)
	}
	res.assertNoPort22(t)
}

// With both fetches failing, every host gets its embedded keys, the run
// succeeds and no port-22 tool runs.
func TestPopulateKnownHosts_FetchFailsUsesEmbedded(t *testing.T) {
	res := runPopulateKnownHosts(t, "", "")
	if res.err != nil {
		t.Fatalf("populate_known_hosts failed: %v\n%s", res.err, res.out)
	}
	for _, host := range []string{"github.com", "gitlab.com", "bitbucket.org"} {
		assertLines(t, host, res.lines(t, host), embeddedKnownHosts(t, host))
	}
	b, err := os.ReadFile(res.curlLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "https://api.github.com/meta") ||
		!strings.Contains(string(b), "https://bitbucket.org/site/ssh") {
		t.Errorf("fetched URLs = %q", b)
	}
	for _, host := range []string{"github.com", "bitbucket.org"} {
		if !strings.Contains(res.out, "WARNING: no valid SSH host keys for "+host) {
			t.Errorf("no fallback warning for %s:\n%s", host, res.out)
		}
	}
	res.assertNoPort22(t)
}

// A malformed or incomplete fetch is replaced as a whole by the embedded
// keys, never written in part.
func TestPopulateKnownHosts_MalformedFetchUsesEmbedded(t *testing.T) {
	keys := testHostKeys(t)
	cases := map[string]struct{ meta, bb string }{
		"not json":       {meta: "<html>rate limited</html>", bb: "<html>maintenance</html>"},
		"bad key":        {meta: ghMetaJSON(append(keys[:3:3], "ssh-rsa AAAAnotbase64")), bb: strings.Join(prefixed("bitbucket.org", append(keys[:3:3], "ssh-rsa AAAAnotbase64")), "\n") + "\n"},
		"no rsa key":     {meta: ghMetaJSON(keys[:2]), bb: strings.Join(prefixed("bitbucket.org", keys[:2]), "\n") + "\n"},
		"empty key list": {meta: `{"ssh_keys": []}`, bb: "ssh.bitbucket.org " + keys[0] + "\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := runPopulateKnownHosts(t, tc.meta, tc.bb)
			if res.err != nil {
				t.Fatalf("populate_known_hosts failed: %v\n%s", res.err, res.out)
			}
			for _, host := range []string{"github.com", "bitbucket.org"} {
				assertLines(t, host, res.lines(t, host), embeddedKnownHosts(t, host))
			}
			res.assertNoPort22(t)
		})
	}
}
