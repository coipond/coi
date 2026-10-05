package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDomainsToHostCIDRs_EmptyInput(t *testing.T) {
	if got := resolveDomainsToHostCIDRs(nil); got != nil {
		t.Errorf("expected nil for nil input, got %v", got)
	}
	if got := resolveDomainsToHostCIDRs([]string{}); got != nil {
		t.Errorf("expected nil for empty slice, got %v", got)
	}
}

func TestResolveDomainsToHostCIDRs_IPv4Input(t *testing.T) {
	// Raw IPv4 addresses resolve immediately without DNS and return /32 CIDRs.
	got := resolveDomainsToHostCIDRs([]string{"1.2.3.4", "5.6.7.8"})
	if len(got) == 0 {
		t.Fatal("expected non-empty CIDRs for IPv4 inputs")
	}
	for _, cidr := range got {
		if !strings.HasSuffix(cidr, "/32") {
			t.Errorf("expected /32 CIDR, got %q", cidr)
		}
	}
}

func TestResolveDomainsToHostCIDRs_CIDRPassthrough(t *testing.T) {
	// CIDRs must come back unchanged — no /32 appended.
	got := resolveDomainsToHostCIDRs([]string{"54.231.0.0/17", "10.0.0.0/8"})
	if len(got) == 0 {
		t.Fatal("expected non-empty result for CIDR inputs")
	}
	want := map[string]bool{
		"54.231.0.0/17": false,
		"10.0.0.0/8":    false,
	}
	for _, cidr := range got {
		if _, ok := want[cidr]; ok {
			want[cidr] = true
		}
	}
	for cidr, found := range want {
		if !found {
			t.Errorf("expected %q in output, got %v", cidr, got)
		}
	}
	// Guard against the regression: appending /32 to a CIDR produces "54.231.0.0/17/32"
	for _, cidr := range got {
		if strings.Count(cidr, "/") > 1 {
			t.Errorf("malformed CIDR with double slash: %q", cidr)
		}
	}
}

func TestResolveDomainsToHostCIDRs_MixedInputs(t *testing.T) {
	// Raw IPs get /32; CIDRs stay as-is.
	got := resolveDomainsToHostCIDRs([]string{"1.2.3.4", "10.0.0.0/8"})
	if len(got) == 0 {
		t.Fatal("expected non-empty result")
	}
	hasRaw := false
	hasCIDR := false
	for _, cidr := range got {
		if strings.Count(cidr, "/") > 1 {
			t.Errorf("malformed CIDR with double slash: %q", cidr)
		}
		if cidr == "1.2.3.4/32" {
			hasRaw = true
		}
		if cidr == "10.0.0.0/8" {
			hasCIDR = true
		}
	}
	if !hasRaw {
		t.Errorf("expected 1.2.3.4/32 in output, got %v", got)
	}
	if !hasCIDR {
		t.Errorf("expected 10.0.0.0/8 in output, got %v", got)
	}
}

func TestBuildTmuxNewSessionCmd_PassesEnvViaDashE(t *testing.T) {
	env := map[string]string{
		"GITHUB_TOKEN": "ghp_secret",
		"JIRA_USER":    "alice",
	}
	got := buildTmuxNewSessionCmd("coi-x", "/workspace", "claude --verbose", env)

	for _, want := range []string{
		"-e 'GITHUB_TOKEN=ghp_secret'",
		"-e 'JIRA_USER=alice'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in command, got: %s", want, got)
		}
	}
	if strings.Contains(got, "export GITHUB_TOKEN") || strings.Contains(got, "export JIRA_USER") {
		t.Errorf("env must not be inlined as `export` statements (would leak to ps and not propagate to new windows): %s", got)
	}
	if !strings.Contains(got, "tmux new-session -d -s 'coi-x'") {
		t.Errorf("expected detached new-session for coi-x, got: %s", got)
	}
	if !strings.Contains(got, "-c '/workspace'") {
		t.Errorf("expected workspace path -c flag, got: %s", got)
	}
	if !strings.Contains(got, "claude --verbose") {
		t.Errorf("expected cliCmd in payload, got: %s", got)
	}
	if !strings.Contains(got, "trap : INT;") {
		t.Errorf("expected SIGINT trap to be preserved, got: %s", got)
	}
	if !strings.Contains(got, "exec bash") {
		t.Errorf("expected exec bash fallback to be preserved, got: %s", got)
	}
}

func TestBuildTmuxNewSessionCmd_DeterministicOrder(t *testing.T) {
	env := map[string]string{"BBB": "2", "AAA": "1", "CCC": "3"}
	got := buildTmuxNewSessionCmd("s", "/w", "cmd", env)
	a := strings.Index(got, "AAA=")
	b := strings.Index(got, "BBB=")
	c := strings.Index(got, "CCC=")
	if a < 0 || b < 0 || c < 0 || a >= b || b >= c {
		t.Errorf("expected env flags in lexicographic order, got: %s", got)
	}
}

func TestBuildTmuxNewSessionCmd_QuotesAwkwardValues(t *testing.T) {
	env := map[string]string{
		"WITH_SPACE":  "hello world",
		"WITH_QUOTE":  "it's risky",
		"WITH_DOLLAR": "$HOME",
	}
	got := buildTmuxNewSessionCmd("s", "/w", "cmd", env)

	// Spaces stay inside the quoted token.
	if !strings.Contains(got, "-e 'WITH_SPACE=hello world'") {
		t.Errorf("space value not single-quoted as one token, got: %s", got)
	}
	// Embedded single quote is escaped via the standard '"'"' trick.
	if !strings.Contains(got, `-e 'WITH_QUOTE=it'"'"'s risky'`) {
		t.Errorf("embedded single quote not escaped, got: %s", got)
	}
	// $HOME must not be exposed to shell expansion -- it must stay inside single quotes.
	if !strings.Contains(got, "-e 'WITH_DOLLAR=$HOME'") {
		t.Errorf("dollar sign not protected by single quotes, got: %s", got)
	}
}

func TestBuildTmuxNewSessionCmd_EmptyEnv(t *testing.T) {
	got := buildTmuxNewSessionCmd("s", "/w", "cmd", nil)
	if strings.Contains(got, " -e ") {
		t.Errorf("expected no -e flags for nil env, got: %s", got)
	}
	if !strings.Contains(got, "tmux new-session -d -s 's'") {
		t.Errorf("expected new-session header, got: %s", got)
	}
}

func TestBuildTmuxSetEnvironmentCmds_OnePerVar(t *testing.T) {
	env := map[string]string{"FOO": "1", "BAR": "two words"}
	got := buildTmuxSetEnvironmentCmds("coi-x", env)

	if len(got) != 2 {
		t.Fatalf("expected 2 commands, got %d: %v", len(got), got)
	}
	// Sorted: BAR before FOO. Session-scoped (no -g) so values don't leak
	// to other tmux sessions sharing the server.
	if got[0] != "tmux set-environment -t 'coi-x' 'BAR' 'two words'" {
		t.Errorf("unexpected first command: %q", got[0])
	}
	if got[1] != "tmux set-environment -t 'coi-x' 'FOO' '1'" {
		t.Errorf("unexpected second command: %q", got[1])
	}
}

func TestBuildTmuxSetEnvironmentCmds_EmptyEnv(t *testing.T) {
	if got := buildTmuxSetEnvironmentCmds("s", nil); len(got) != 0 {
		t.Errorf("expected no commands for nil env, got: %v", got)
	}
}

// The tmux prep script must create a missing session, reuse an existing one,
// apply env either way, and report each outcome — checked against a fake tmux.
func TestBuildTmuxPrepScript_Exec(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := "#!/bin/sh\necho \"$*\" >> " + log + "\n" +
		"case \"$1\" in has-session) [ -n \"$FAKE_EXISTS\" ] ;; new-session) [ -z \"$FAKE_CREATE_FAILS\" ] ;; set-environment) [ -z \"$FAKE_ENV_FAILS\" ] ;; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"A": "1"}
	script := buildTmuxPrepScript("coi-x", buildTmuxNewSessionCmd("coi-x", "/w", "claude", env), buildTmuxSetEnvironmentCmds("coi-x", env))

	run := func(extra ...string) (string, string, error) {
		_ = os.Remove(log)
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append([]string{"PATH=" + dir + ":" + os.Getenv("PATH")}, extra...)
		out, err := cmd.Output()
		calls, _ := os.ReadFile(log)
		return string(out), string(calls), err
	}

	out, calls, err := run()
	if err != nil || !strings.Contains(out, tmuxPrepCreated) || !strings.Contains(calls, "new-session") || !strings.Contains(calls, "set-environment") {
		t.Errorf("missing session: want create + env; out=%q err=%v calls=%q", out, err, calls)
	}
	out, calls, err = run("FAKE_EXISTS=1")
	if err != nil || !strings.Contains(out, tmuxPrepExisting) || strings.Contains(calls, "new-session") || !strings.Contains(calls, "set-environment") {
		t.Errorf("existing session: want reuse + env, no create; out=%q err=%v calls=%q", out, err, calls)
	}
	out, _, err = run("FAKE_CREATE_FAILS=1")
	if err == nil || strings.Contains(out, tmuxPrepCreated) {
		t.Errorf("failed create must exit non-zero without the created marker; out=%q err=%v", out, err)
	}
	out, _, err = run("FAKE_ENV_FAILS=1")
	if err != nil || !strings.Contains(out, tmuxPrepEnvFailed) || !strings.Contains(out, tmuxPrepCreated) {
		t.Errorf("env failure is a warning, not fatal; out=%q err=%v", out, err)
	}
}
