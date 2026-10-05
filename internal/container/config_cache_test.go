package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIncus puts an `incus` script on PATH that logs each argv line to a file
// and answers `config show` with a fixed YAML.
func fakeIncus(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"config show --expanded c1"*) printf 'config:\n  security.nesting: "true"\n  raw.idmap: both 1000 1000\ndevices: {}\n' ;;
  *"config show c1"*) printf 'config:\n  raw.idmap: both 1000 1000\n  user.marker: "x"\ndevices:\n  workspace:\n    path: /workspace\n    source: /home/u/p\n    type: disk\n  protect-a:\n    path: /workspace/.a\n    readonly: "true"\n    source: /home/u/p/.a\n    type: disk\n' ;;
  *"config device get c1 missing path"*) echo "Error: Device doesn't exist" >&2; exit 1 ;;
  *"config show"*) echo "Error: Instance not found" >&2; exit 1 ;;
  *"config get"*) echo FROM-REAL-GET ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	invalidateConfigCache()
	t.Cleanup(invalidateConfigCache)
	return logPath
}

func calls(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Repeated config reads of one container cost ONE `incus config show`.
func TestConfigCache_DedupesReads(t *testing.T) {
	logPath := fakeIncus(t)

	if v, err := IncusOutput("config", "get", "c1", "raw.idmap"); err != nil || v != "both 1000 1000" {
		t.Fatalf("config get = %q, %v", v, err)
	}
	if v, _ := IncusOutput("config", "get", "c1", "unset.key"); v != "" {
		t.Errorf("unset key = %q, want empty (like incus)", v)
	}
	if v, _ := IncusOutput("config", "device", "get", "c1", "workspace", "source"); v != "/home/u/p" {
		t.Errorf("device get = %q", v)
	}
	if v, _ := IncusOutput("config", "device", "list", "c1"); v != "protect-a\nworkspace" {
		t.Errorf("device list = %q", v)
	}
	if got := calls(t, logPath); len(got) != 1 || !strings.Contains(got[0], "config show c1") {
		t.Fatalf("want one config show, got %v", got)
	}

	// Expanded reads use their own (single) snapshot.
	if v, _ := IncusOutput("config", "get", "--expanded", "c1", "security.nesting"); v != "true" {
		t.Errorf("expanded get = %q", v)
	}
	if v, _ := IncusOutput("config", "get", "--expanded", "c1", "raw.idmap"); v != "both 1000 1000" {
		t.Errorf("expanded get = %q", v)
	}
	if got := calls(t, logPath); len(got) != 2 {
		t.Errorf("want 2 calls after expanded reads, got %v", got)
	}
}

// Any write drops the cache, so the next read goes back to Incus.
func TestConfigCache_InvalidatedByWrites(t *testing.T) {
	logPath := fakeIncus(t)
	_, _ = IncusOutput("config", "get", "c1", "raw.idmap")
	if err := IncusExecQuiet("config", "set", "c1", "raw.idmap=both 1 1"); err != nil {
		t.Fatal(err)
	}
	_, _ = IncusOutput("config", "get", "c1", "raw.idmap")
	got := calls(t, logPath)
	if len(got) != 3 || !strings.Contains(got[2], "config show c1") {
		t.Errorf("read after write must refetch, calls=%v", got)
	}

	// Read-only commands (exec, list) keep it.
	_, _ = IncusOutput("list", "^c1$", "--format=csv")
	_, _ = IncusOutput("exec", "c1", "--", "true")
	_, _ = IncusOutput("config", "get", "c1", "user.marker")
	if got := calls(t, logPath); len(got) != 5 {
		t.Errorf("read-only commands must not invalidate, calls=%v", got)
	}
}

// A device the snapshot doesn't have goes to Incus for its real error.
func TestConfigCache_MissingDeviceFallsThrough(t *testing.T) {
	logPath := fakeIncus(t)
	if _, err := IncusOutput("config", "device", "get", "c1", "missing", "path"); err == nil {
		t.Error("missing device must surface Incus's error")
	}
	got := calls(t, logPath)
	if len(got) != 2 || !strings.Contains(got[1], "config device get c1 missing path") {
		t.Errorf("want snapshot + real call, got %v", got)
	}
}

// When the snapshot can't be loaded, reads behave exactly as before.
func TestConfigCache_LoadFailureFallsBack(t *testing.T) {
	logPath := fakeIncus(t)
	if v, _ := IncusOutput("config", "get", "other", "k"); v != "FROM-REAL-GET" {
		t.Errorf("fallback read = %q", v)
	}
	if got := calls(t, logPath); len(got) != 2 {
		t.Errorf("want failed show + real get, got %v", got)
	}
}

func TestIncusArgsAreReadOnly(t *testing.T) {
	for args, want := range map[string]bool{
		"list":                        true,
		"exec c1 -- true":             true,
		"file push a c1/b":            true,
		"config get c1 k":             true,
		"config device list c1":       true,
		"config set c1 k=v":           false,
		"config device add c1 d disk": false,
		"config device remove c1 d":   false,
		"start c1":                    false,
		"stop c1":                     false,
		"delete c1":                   false,
		"image list":                  true,
		"profile device add p d x":    false,
	} {
		if got := incusArgsAreReadOnly(strings.Fields(args)); got != want {
			t.Errorf("%q: got %v want %v", args, got, want)
		}
	}
}

func TestRunningFromCSV(t *testing.T) {
	if !runningFromCSV("c1,RUNNING\n", "c1") {
		t.Error("running")
	}
	if runningFromCSV("c1,STOPPED\n", "c1") || runningFromCSV("c10,RUNNING\n", "c1") || runningFromCSV("", "c1") {
		t.Error("not running")
	}
}
