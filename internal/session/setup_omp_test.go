package session

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeOpsManager is a fakeDirsManager that records execs and pushes in the
// order they ran.
type fakeOpsManager struct {
	*fakeDirsManager
	ops []string
}

func (f *fakeOpsManager) ExecArgs(args []string, opts container.ExecCommandOptions) error {
	f.ops = append(f.ops, "exec "+strings.Join(args, " "))
	return f.fakeDirsManager.ExecArgs(args, opts)
}

func (f *fakeOpsManager) PushFile(src, dest string) error {
	f.ops = append(f.ops, "push "+dest)
	return f.fakeDirsManager.PushFile(src, dest)
}

// writeOmpHostFiles writes the named files into <hostDir>/agent, each holding
// its own name.
func writeOmpHostFiles(t *testing.T, hostDir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(hostDir, "agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(hostDir, "agent", name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestInjectCredentials_Omp_OneMkdirPerDir verifies that on resume the omp
// files, which all sit in ~/.omp/agent, make that dir with one exec, not one
// per file.
func TestInjectCredentials_Omp_OneMkdirPerDir(t *testing.T) {
	hostDir := t.TempDir()
	files := []string{"config.yml", "models.yml", "agent.db", "AGENTS.md"}
	writeOmpHostFiles(t, hostDir, files...)

	mgr := newFakeDirsManager("/home/code/.omp")
	copied, err := injectCredentials(mgr, hostDir, "/home/code", toolWithConfigDirFiles(t, "omp"), func(string) {})
	if err != nil {
		t.Fatalf("injectCredentials failed: %v", err)
	}

	if len(copied) != len(files) {
		t.Errorf("copied = %+v, want %v", copied, files)
	}
	var mkdirs int
	for _, args := range mgr.execArgs {
		if args[0] == "mkdir" {
			mkdirs++
		}
	}
	if mkdirs != 1 {
		t.Errorf("execs = %v, want one mkdir -p /home/code/.omp/agent", mgr.execArgs)
	}
}

// TestInjectCredentials_Omp_ReplacesSavedWAL verifies that on resume the saved
// session's agent.db-wal and -shm are removed before the host agent.db is
// pushed, so SQLite does not replay the old WAL over the fresh DB, and that the
// host WAL (the latest committed logins) is pushed after the DB.
func TestInjectCredentials_Omp_ReplacesSavedWAL(t *testing.T) {
	hostDir := t.TempDir()
	writeOmpHostFiles(t, hostDir, "agent.db", "agent.db-wal")

	mgr := &fakeOpsManager{fakeDirsManager: newFakeDirsManager("/home/code/.omp", "/home/code/.omp/agent")}
	if _, err := injectCredentials(mgr, hostDir, "/home/code", toolWithConfigDirFiles(t, "omp"), func(string) {}); err != nil {
		t.Fatalf("injectCredentials failed: %v", err)
	}

	want := []string{
		"exec mkdir -p /home/code/.omp/agent",
		"exec rm -f /home/code/.omp/agent/agent.db-wal /home/code/.omp/agent/agent.db-shm",
		"push /home/code/.omp/agent/agent.db",
		"push /home/code/.omp/agent/agent.db-wal",
	}
	if !reflect.DeepEqual(mgr.ops, want) {
		t.Errorf("ops = %v, want %v", mgr.ops, want)
	}
}

// TestSetupCLIConfig_Omp_CopiesHostWAL verifies that a fresh session gets the
// host agent.db-wal next to agent.db: while a host omp has agent.db open, its
// committed logins may be only in the WAL.
func TestSetupCLIConfig_Omp_CopiesHostWAL(t *testing.T) {
	hostDir := t.TempDir()
	writeOmpHostFiles(t, hostDir, "agent.db", "agent.db-wal")

	mgr := newFakeCodexSetupManager()
	if _, err := setupCLIConfig(mgr, hostDir, "/home/code", toolWithConfigDirFiles(t, "omp"), func(string) {}); err != nil {
		t.Fatalf("setupCLIConfig failed: %v", err)
	}

	for _, name := range []string{"agent.db", "agent.db-wal"} {
		if got := mgr.files["/home/code/.omp/agent/"+name]; got != name {
			t.Errorf("%s in container = %q, want the host copy", name, got)
		}
	}
}
