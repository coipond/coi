package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// Both DNS blocks answer TCP with a reset ahead of the reject, so blocked TCP
// does not use up the container's ICMP rate-limit budget.
func TestBlockDNSAddsTCPResetBeforeEachReject(t *testing.T) {
	logPath := fakeNftSudo(t, "", "")
	f := NewNftManager("10.0.0.2", "10.0.0.1")
	if err := f.blockDNS(); err != nil {
		t.Fatal(err)
	}
	calls := readCalls(t, logPath)
	for _, chain := range []string{"forward", "input"} {
		prefix := "add rule ip coi " + chain + " ip saddr 10.0.0.2 meta l4proto { tcp, udp } th dport 53 "
		reset := strings.Index(calls, prefix+"meta l4proto tcp reject with tcp reset")
		reject := strings.Index(calls, prefix+"reject comment")
		if reset < 0 || reject < 0 || reset > reject {
			t.Errorf("%s: want the TCP reset rule before the reject, calls:\n%s", chain, calls)
		}
	}
}

// fakeIncus puts an incus on PATH that logs its arguments.
func fakeIncus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incus.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o700); err != nil { //nolint:gosec // test fake must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// Allowlist mode stops the resolver and limits name lookups to /etc/hosts;
// restricted and open modes give both back. Only the IPv4-only modes disable
// IPv6.
func TestContainerNetCmd(t *testing.T) {
	for _, tc := range []struct {
		mode      config.NetworkMode
		want, not []string
	}{
		{config.NetworkModeAllowlist, []string{disableIPv6Cmd, stopResolverCmd, filesOnlyHostsCmd}, []string{restoreResolverCmd}},
		{config.NetworkModeRestricted, []string{disableIPv6Cmd, restoreResolverCmd, restoreHostsCmd}, []string{stopResolverCmd, filesOnlyHostsCmd}},
		{config.NetworkModeOpen, []string{restoreResolverCmd, restoreHostsCmd}, []string{disableIPv6Cmd, stopResolverCmd, filesOnlyHostsCmd}},
	} {
		got := containerNetCmd(tc.mode)
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in %q", tc.mode, w, got)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(got, n) {
				t.Errorf("%s: must not contain %q", tc.mode, n)
			}
		}
	}
}

// The mode's in-container step is one exec.
func TestPrepareContainer(t *testing.T) {
	logPath := fakeIncus(t)
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeAllowlist}, logger.NewDiscard())
	m.prepareContainer("c1")
	calls := readCalls(t, logPath)
	if n := strings.Count(calls, "exec"); n != 1 {
		t.Errorf("want one incus exec, got %d:\n%s", n, calls)
	}
	for _, want := range []string{"c1", "disable_ipv6=1", "systemctl mask --runtime systemd-resolved.service"} {
		if !strings.Contains(calls, want) {
			t.Errorf("exec must contain %q, got:\n%s", want, calls)
		}
	}
}

// Open mode gives the resolver back only to a container that still carries
// another mode's rules (reused from an earlier session); a new container, or
// one already in open mode, pays no exec.
func TestApplyOpenRules_RestoresResolverOnReuse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listing string
		exec    bool
	}{
		{"new container", "", false},
		{"already open", "\t\tip saddr 10.0.0.2 accept comment \"coi-10.0.0.2\" # handle 5\n", false},
		{"reused from allowlist", "\t\tip saddr 10.0.0.2 ip daddr @coi_s_10_0_0_2 accept comment \"coi-10.0.0.2\" # handle 5\n" +
			"\t\tip saddr 10.0.0.2 reject comment \"coi-10.0.0.2\" # handle 6\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeNftSudo(t, "table ip coi {\n\tchain forward { # handle 1\n"+tc.listing+"\t}\n}\n", "")
			logPath := fakeIncus(t)
			m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen}, logger.NewDiscard())
			m.containerName = "c1"
			m.applyOpenRules("10.0.0.2")
			calls := readCalls(t, logPath)
			if got := strings.Contains(calls, "unmask --runtime systemd-resolved.service"); got != tc.exec {
				t.Errorf("resolver restore = %v, want %v; incus calls:\n%s", got, tc.exec, calls)
			}
		})
	}
}

func TestAllSteps(t *testing.T) {
	for _, tc := range []struct {
		steps []string
		ok    bool
	}{
		{[]string{"true", "true"}, true},
		{[]string{"false", "true"}, false},
		{[]string{"true", "if false; then :; fi"}, true},
		{[]string{"true", "if true; then false; fi"}, false},
	} {
		err := exec.Command("sh", "-c", allSteps(tc.steps...)).Run()
		if (err == nil) != tc.ok {
			t.Errorf("%v: err = %v, want ok=%v", tc.steps, err, tc.ok)
		}
	}
}

// runInRoot runs an in-container script with /etc/ moved under root.
func runInRoot(t *testing.T, root, script string) {
	t.Helper()
	out, err := exec.Command("bash", "-c", strings.ReplaceAll(script, "/etc/", root+"/etc/")).CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
}

// Allowlist mode puts filesOnlyPrefix in front of the "hosts:" modules in
// nsswitch.conf itself (a package script can still replace the file) and
// installs a boot unit that undoes it. A package edits the line as usual; the
// restore removes only the prefix, so the package's change stays, and the next
// allowlist setup applies again.
func TestFilesOnlyHosts(t *testing.T) {
	const orig = "passwd:         files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\nnetworks:       files\n"
	const plain = "hosts:          files dns\n"
	for _, tc := range []struct {
		name    string
		systemd bool
		conf    string
		edit    string // what a package does while allowlist mode is on
		want    string // after the restore
	}{
		{
			"systemd", true, orig,
			"sed -i 's/^passwd:.*/passwd: files/' /etc/nsswitch.conf",
			strings.Replace(orig, "passwd:         files systemd", "passwd: files", 1),
		},
		{"no systemd", false, orig, "", orig},
		{"no hosts line", true, "passwd: files\n", "", "passwd: files\nhosts: dns [!UNAVAIL=return] files\n"},
		{
			"package inserts a module before dns", true, plain,
			"sed -i 's/ dns$/ mdns4_minimal [NOTFOUND=return] dns/' /etc/nsswitch.conf",
			"hosts:          files mdns4_minimal [NOTFOUND=return] dns\n",
		},
		{
			"package appends a module", true, plain,
			"sed -i '/^hosts:/s/$/ myhostname/' /etc/nsswitch.conf",
			"hosts:          files dns myhostname\n",
		},
		{
			"package removes a module", true, orig,
			"sed -i 's/mdns4_minimal \\[NOTFOUND=return\\] //' /etc/nsswitch.conf",
			strings.Replace(orig, "mdns4_minimal [NOTFOUND=return] ", "", 1),
		},
		{
			"package removes the line", true, orig,
			"sed -i '/^hosts:/d' /etc/nsswitch.conf",
			strings.Replace(orig, "hosts:          files mdns4_minimal [NOTFOUND=return] dns\n", "", 1),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			conf := filepath.Join(root, "etc", "nsswitch.conf")
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.systemd {
				if err := os.MkdirAll(filepath.Join(root, "etc", "systemd", "system"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(conf, []byte(tc.conf), 0o644); err != nil {
				t.Fatal(err)
			}
			read := func() string {
				b, err := os.ReadFile(conf)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			assertFilesOnly := func(when string) {
				t.Helper()
				var hosts []string
				for _, line := range strings.Split(read(), "\n") {
					if strings.HasPrefix(line, "hosts:") {
						hosts = append(hosts, line)
					}
				}
				if len(hosts) != 1 || !strings.HasPrefix(strings.TrimLeft(strings.TrimPrefix(hosts[0], "hosts:"), " \t"), filesOnlyPrefix) {
					t.Fatalf("%s: want one 'hosts:' line starting with %q, got:\n%s", when, filesOnlyPrefix, read())
				}
			}

			runInRoot(t, root, filesOnlyHostsCmd)
			runInRoot(t, root, filesOnlyHostsCmd)
			assertFilesOnly("apply")
			if want := strings.Replace(tc.conf, "hosts:          files", "hosts:          "+filesOnlyPrefix+"files", 1); strings.Contains(tc.conf, "hosts:") && read() != want {
				t.Errorf("apply must only add the prefix:\ngot  %q\nwant %q", read(), want)
			}

			unit := filepath.Join(root, "etc", "systemd", "system", "coi-nss-restore.service")
			wants := filepath.Join(root, "etc", "systemd", "system", "sysinit.target.wants", "coi-nss-restore.service")
			if tc.systemd {
				if b, err := os.ReadFile(unit); err != nil || string(b) != strings.ReplaceAll(nssRestoreUnit, "/etc/", root+"/etc/") {
					t.Errorf("boot unit: %v\n%s", err, b)
				}
				if _, err := os.Stat(wants); err != nil {
					t.Errorf("boot unit not enabled: %v", err)
				}
			} else if _, err := os.Stat(unit); !os.IsNotExist(err) {
				t.Errorf("no unit without systemd, stat: %v", err)
			}

			if tc.edit != "" {
				runInRoot(t, root, tc.edit)
			}
			if tc.systemd {
				// What the boot unit runs; its paths are already under root.
				if out, err := exec.Command("sh", filepath.Join(root, "etc", "coi", "nss-restore.sh")).CombinedOutput(); err != nil {
					t.Fatalf("restore script: %v\n%s", err, out)
				}
			} else {
				runInRoot(t, root, restoreHostsCmd)
			}
			if got := read(); got != tc.want {
				t.Errorf("restore:\ngot  %q\nwant %q", got, tc.want)
			}
			runInRoot(t, root, restoreHostsCmd)
			if got := read(); got != tc.want {
				t.Errorf("repeated restore changed the file: %q", got)
			}

			// The same running container set up in allowlist mode again.
			runInRoot(t, root, filesOnlyHostsCmd)
			assertFilesOnly("second apply")
		})
	}
}
