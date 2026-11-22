package session

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeChownOnPath puts a `chown` on PATH that logs its arguments instead of
// changing owners, and returns the log path.
func fakeChownOnPath(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(bin, "chown.log")
	script := "#!/bin/sh\necho \"$*\" >> " + shellEscape(logPath) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "chown"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// assertChownCalls checks that the logging chown handed exactly dirs, in
// order, to the code user.
func assertChownCalls(t *testing.T, logPath string, dirs ...string) {
	t.Helper()
	assertChownCallsTo(t, logPath, container.CodeUID, dirs...)
}

// assertChownCallsTo checks that the logging chown handed exactly dirs, in
// order, to owner.
func assertChownCallsTo(t *testing.T, logPath string, owner int, dirs ...string) {
	t.Helper()
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("chown never ran: %v", err)
	}
	var want strings.Builder
	for _, d := range dirs {
		fmt.Fprintf(&want, "%d:%d %s\n", owner, owner, d)
	}
	if string(log) != want.String() {
		t.Errorf("chown calls = %q, want %q", log, want.String())
	}
}

// fakeShellManager runs container execs in a local bash, so commands act on a
// temp dir standing in for the container home. File writes land there too;
// Chown (incus-side) is a no-op, so only the exec's own chown calls are seen.
type fakeShellManager struct {
	container.ContainerManager
}

func (fakeShellManager) ExecCommand(cmd string, _ container.ExecCommandOptions) (string, error) {
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	return string(out), err
}

func (fakeShellManager) ExecArgs(args []string, _ container.ExecCommandOptions) error {
	return exec.Command(args[0], args[1:]...).Run()
}

func (fakeShellManager) PushFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o600)
}

func (fakeShellManager) CreateFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func (fakeShellManager) Chown(string, int, int) error { return nil }

// TestSeedHostFile_ChownsCreatedDirs: a [[credentials]] entry such as
// .codex/auth.json in a container whose image has no ~/.codex must not leave
// a root-owned ~/.codex. The existing home keeps its owner.
func TestSeedHostFile_ChownsCreatedDirs(t *testing.T) {
	home := t.TempDir()
	host := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(host, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := fakeChownOnPath(t)

	entries := []CredentialEntry{{HostPath: host, ContainerPath: ".codex/auth.json"}}
	copied, err := setupCredentials(fakeShellManager{}, home, entries, func(string) {})
	if err != nil || len(copied) != 1 {
		t.Fatalf("setupCredentials: copied = %+v, err = %v", copied, err)
	}
	assertChownCalls(t, logPath, filepath.Join(home, ".codex"))
}

// TestSetupCLIConfig_ChownsCreatedConfigDir: claude seeded from a host
// ~/.claude without ~/.claude.json, into an image without ~/.claude, must not
// leave a root-owned ~/.claude (that branch has no recursive chown).
func TestSetupCLIConfig_ChownsCreatedConfigDir(t *testing.T) {
	home := t.TempDir()
	hostDir := filepath.Join(t.TempDir(), ".claude")
	if err := os.Mkdir(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := fakeChownOnPath(t)

	if _, err := setupCLIConfig(fakeShellManager{}, hostDir, home, toolWithConfigDirFiles(t, "claude"), func(string) {}); err != nil {
		t.Fatalf("setupCLIConfig: %v", err)
	}
	assertChownCalls(t, logPath, filepath.Join(home, ".claude"))
}

// TestHomeMkdirCmd_ExplicitOwner: each dir HomeMkdirCmd creates goes to the
// given owner; an existing parent keeps its owner.
func TestHomeMkdirCmd_ExplicitOwner(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".coi"), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := fakeChownOnPath(t)

	dir := filepath.Join(home, ".coi", "runs", "x")
	if out, err := (fakeShellManager{}).ExecCommand(HomeMkdirCmd(dir, home, 1234), container.ExecCommandOptions{}); err != nil {
		t.Fatalf("HomeMkdirCmd: %v: %s", err, out)
	}
	assertChownCallsTo(t, logPath, 1234, filepath.Dir(dir), dir)
}

// TestHomeMkdirCmd_ConcurrentCreate: parallel execs creating the same missing
// dirs must all succeed, though only one of them creates each dir.
func TestHomeMkdirCmd_ConcurrentCreate(t *testing.T) {
	fakeChownOnPath(t)
	for round := 0; round < 50; round++ {
		home := t.TempDir()
		cmd := HomeMkdirCmd(filepath.Join(home, ".coi", "runs"), home, 1234)
		var wg sync.WaitGroup
		errs := make(chan error, 4)
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if out, err := (fakeShellManager{}).ExecCommand(cmd, container.ExecCommandOptions{}); err != nil {
					errs <- fmt.Errorf("%w: %s", err, out)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("round %d: HomeMkdirCmd: %v", round, err)
		}
	}
}
