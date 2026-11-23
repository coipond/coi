package session

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestInjectCredentials_Omp_OneMkdirPerDir verifies that on resume the omp
// files, which all sit in ~/.omp/agent, make that dir with one exec, not one
// per file.
func TestInjectCredentials_Omp_OneMkdirPerDir(t *testing.T) {
	hostDir := t.TempDir()
	files := []string{"config.yml", "models.yml", "agent.db", "AGENTS.md"}
	if err := os.MkdirAll(filepath.Join(hostDir, "agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(hostDir, "agent", name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	mgr := newFakeDirsManager("/home/code/.omp")
	copied, err := injectCredentials(mgr, hostDir, "/home/code", toolWithConfigDirFiles(t, "omp"), func(string) {})
	if err != nil {
		t.Fatalf("injectCredentials failed: %v", err)
	}

	if len(copied) != len(files) {
		t.Errorf("copied = %+v, want %v", copied, files)
	}
	want := [][]string{{"mkdir", "-p", "/home/code/.omp/agent"}}
	if !reflect.DeepEqual(mgr.execArgs, want) {
		t.Errorf("execs = %v, want %v", mgr.execArgs, want)
	}
}
