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

// Allowlist mode stops the resolver; restricted and open modes give it back.
// Only the IPv4-only modes disable IPv6.
func TestContainerNetCmd(t *testing.T) {
	for _, tc := range []struct {
		mode      config.NetworkMode
		want, not []string
	}{
		{config.NetworkModeAllowlist, []string{disableIPv6Cmd, stopResolverCmd}, []string{restoreResolverCmd}},
		{config.NetworkModeRestricted, []string{disableIPv6Cmd, restoreResolverCmd}, []string{stopResolverCmd}},
		{config.NetworkModeOpen, []string{restoreResolverCmd}, []string{disableIPv6Cmd, stopResolverCmd}},
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
