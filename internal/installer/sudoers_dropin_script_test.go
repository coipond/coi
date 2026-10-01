package installer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sudoersDropinScriptPath returns scripts/install-sudoers-dropin.sh at the repo root.
func sudoersDropinScriptPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(installShPath(t)), "scripts", "install-sudoers-dropin.sh")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("install-sudoers-dropin.sh not found: %v", err)
	}
	return path
}

// runSudoersDropin runs the helper against a temp sudoers.d holding a
// pre-existing "previous" drop-in, with sudo stubbed to run unprivileged and
// visudo stubbed to exit visudoExit. It returns the combined output, the exit
// code, the target's content and mode, and the directory's file count.
func runSudoersDropin(t *testing.T, visudoExit string, args ...string) (out string, code int, content, mode string, files int) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	sudoersD := filepath.Join(dir, "sudoers.d")
	for _, d := range []string{bin, sudoersD} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stubs := map[string]string{
		"sudo":   "#!/bin/bash\nexec \"$@\"\n",
		"visudo": "#!/bin/sh\nexit " + visudoExit + "\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(sudoersD, "coi-nft")
	if err := os.WriteFile(target, []byte("previous\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	argv := append([]string{sudoersDropinScriptPath(t)}, args...)
	if len(args) == 1 {
		argv = append(argv, target) // rule only → install to the temp target
	}
	cmd := exec.Command("bash", argv...)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	b, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	c, _ := os.ReadFile(target)
	fi, _ := os.Stat(target)
	entries, _ := os.ReadDir(sudoersD)
	return string(b), code, string(c), fi.Mode().Perm().String(), len(entries)
}

// A rule visudo accepts replaces the target with mode 0440 and no temp file.
func TestSudoersDropinScript_InstallsValidatedRule(t *testing.T) {
	rule := "%incus-admin ALL=(ALL) NOPASSWD: /usr/sbin/nft"
	out, code, content, mode, files := runSudoersDropin(t, "0", rule)
	if code != 0 {
		t.Fatalf("exit %d; out:\n%s", code, out)
	}
	if content != rule+"\n" {
		t.Errorf("content = %q", content)
	}
	if mode != "-r--r-----" {
		t.Errorf("mode = %s, want 0440", mode)
	}
	if files != 1 {
		t.Errorf("temp file left behind (%d files)", files)
	}
}

// A rule visudo rejects never reaches the target: the existing drop-in
// survives, no temp file remains, and the script fails loudly.
func TestSudoersDropinScript_RejectedRuleLeavesTargetUntouched(t *testing.T) {
	out, code, content, _, files := runSudoersDropin(t, "1", "John Doe ALL=(ALL) NOPASSWD: /usr/sbin/nft")
	if code == 0 {
		t.Fatalf("expected failure; out:\n%s", out)
	}
	if !strings.Contains(out, "refusing to install an invalid sudoers rule") {
		t.Errorf("missing refusal message; out:\n%s", out)
	}
	if content != "previous\n" {
		t.Errorf("target modified: %q", content)
	}
	if files != 1 {
		t.Errorf("temp file left behind (%d files)", files)
	}
}

func TestSudoersDropinScript_Usage(t *testing.T) {
	out, code, _, _, _ := runSudoersDropin(t, "0")
	if code != 2 || !strings.Contains(out, "usage:") {
		t.Errorf("no args should print usage and exit 2, got %d; out:\n%s", code, out)
	}
}

// The exact rules the helper's callers install must pass the real visudo.
func TestSudoersDropinScript_CallerRulesParse(t *testing.T) {
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		if _, statErr := os.Stat("/usr/sbin/visudo"); statErr != nil {
			t.Skip("visudo not installed")
		}
		visudo = "/usr/sbin/visudo"
	}
	for _, rule := range []string{
		"%incus-admin ALL=(ALL) NOPASSWD: /usr/sbin/nft", // scripts/install-nft-deps.sh
		"#1001 ALL=(ALL) NOPASSWD: /usr/sbin/nft *",      // lima-guest-setup.sh, ci.yml
	} {
		f := filepath.Join(t.TempDir(), "rule")
		if err := os.WriteFile(f, []byte(rule+"\n"), 0o440); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(visudo, "-cf", f).CombinedOutput(); err != nil {
			t.Errorf("visudo rejected %q: %v\n%s", rule, err, out)
		}
	}
}
