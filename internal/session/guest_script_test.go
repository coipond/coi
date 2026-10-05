package session

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// The rendered script must really work in bash: write exact bytes (quotes,
// newlines, shell metacharacters), apply the mode, replace a symlink at the
// target instead of writing through it, and run plain commands in order.
func TestRenderGuestScript_RunsInBash(t *testing.T) {
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("base64 not available")
	}
	dir := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sub", "linked")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	tricky := "a'b\"c $(touch " + filepath.Join(dir, "pwned") + ") `x`\n\\n end\n"
	script := renderGuestScript([]guestOp{
		guestCmd("mkdir -p " + shellEscape(filepath.Join(dir, "new"))),
		guestFile(filepath.Join(dir, "new", "f"), tricky, uid, gid, "0751"),
		guestFile(link, "replaced", uid, gid, "0644"),
		guestCmd("ln -sf f " + shellEscape(filepath.Join(dir, "new", "g"))),
	})
	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s\n--- script ---\n%s", err, out, script)
	}

	got, err := os.ReadFile(filepath.Join(dir, "new", "f"))
	if err != nil || string(got) != tricky {
		t.Fatalf("content mismatch: %q, %v", got, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "new", "f")); fi.Mode().Perm() != 0o751 {
		t.Errorf("mode = %v, want 0751", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Error("file content was executed by the shell")
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Error("write followed the symlink at the target")
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("symlink at the target was not replaced by a regular file")
	}
	if target, err := os.Readlink(filepath.Join(dir, "new", "g")); err != nil || target != "f" {
		t.Errorf("command op not run: %q, %v", target, err)
	}
}

// set -e: a failing step stops the script, so later steps don't run.
func TestRenderGuestScript_StopsOnError(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "after")
	script := renderGuestScript([]guestOp{guestCmd("false"), guestCmd("touch " + shellEscape(marker))})
	if err := exec.Command("bash", "-c", script).Run(); err == nil {
		t.Fatal("script should fail")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("steps after a failure must not run")
	}
}

type guestOpsRecorder struct {
	container.ContainerManager
	execs   []string
	creates []string
	execErr error
}

func (r *guestOpsRecorder) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	r.execs = append(r.execs, cmd)
	return "", r.execErr
}

func (r *guestOpsRecorder) CreateFileWithOwner(path, _ string, _, _ int, _ string) error {
	r.creates = append(r.creates, path)
	return nil
}

func TestRunGuestOps_OneExec(t *testing.T) {
	r := &guestOpsRecorder{}
	err := runGuestOps(r, []guestOp{guestCmd("true"), guestFile("/x", "y", 0, 0, "0644")}, container.ExecCommandOptions{})
	if err != nil || len(r.execs) != 1 || len(r.creates) != 0 {
		t.Fatalf("want one exec, got err=%v execs=%d creates=%d", err, len(r.execs), len(r.creates))
	}
	r.execErr = errors.New("boom")
	if err := runGuestOps(r, []guestOp{guestCmd("true")}, container.ExecCommandOptions{}); err == nil {
		t.Error("exec failure must be returned")
	}
}

// A batch too big for one argv element falls back to one call per op.
func TestRunGuestOps_LargeBatchFallsBack(t *testing.T) {
	r := &guestOpsRecorder{}
	big := strings.Repeat("x", maxGuestScriptBytes)
	ops := []guestOp{guestCmd("mkdir -p /d"), guestFile("/d/big", big, 1000, 1000, "0644"), guestCmd("true")}
	if err := runGuestOps(r, ops, container.ExecCommandOptions{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.execs) != "[mkdir -p /d true]" || fmt.Sprint(r.creates) != "[/d/big]" {
		t.Errorf("fallback order wrong: execs=%v creates=%v", r.execs, r.creates)
	}
}
