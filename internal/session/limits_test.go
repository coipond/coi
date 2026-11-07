package session

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// fakeLimitsIncus puts an `incus` on PATH that logs each argv line and
// answers `config show <name>` with configYAML. Each test uses its own
// container name, so the package's config cache never serves another test.
func fakeLimitsIncus(t *testing.T, name, configYAML string) (logPath string) {
	t.Helper()
	return fakeLimitsIncusStatus(t, name, configYAML, "")
}

// fakeLimitsIncusStatus is fakeLimitsIncus whose `incus list` also reports
// the container as existing with status (STOPPED, RUNNING) when set.
func fakeLimitsIncusStatus(t *testing.T, name, configYAML, status string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"config show "*` + name + `) cat ` + filepath.Join(dir, "config.yaml") + ` ;;
  *"list "*"--columns=ns"*) [ -n "` + status + `" ] && echo "` + name + `,` + status + `" ;;
  *"list "*"--columns=n"*) [ -n "` + status + `" ] && echo "` + name + `" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// limitWrites returns the logged incus calls that change a limit.
func limitWrites(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		line = strings.TrimPrefix(line, "--project default ")
		if strings.HasPrefix(line, "config set ") || strings.HasPrefix(line, "config unset ") ||
			strings.HasPrefix(line, "config device set ") || strings.HasPrefix(line, "config device unset ") {
			out = append(out, line)
		}
	}
	return out
}

func intPtr(n int) *int { return &n }

func TestReconcileLimits_LoweredToZeroUnsetsProcesses(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-zero", "config:\n  limits.processes: \"500\"\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.Runtime.MaxProcesses = intPtr(0)

	if err := ReconcileLimits("rl-zero", "default", cfg, func(string) {}); err != nil {
		t.Fatal(err)
	}
	want := []string{"config unset rl-zero limits.processes"}
	if got := limitWrites(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("writes = %q, want %q", got, want)
	}
}

func TestReconcileLimits_RemovedSectionUnsetsKeys(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-removed", `config:
  limits.cpu: "2"
  limits.memory: 2GiB
  limits.processes: "500"
  user.other: keep
devices:
  root:
    limits.read: 100MB
    path: /
    pool: default
    type: disk
`)
	var logged []string
	if err := ReconcileLimits("rl-removed", "default", &config.LimitsConfig{}, func(s string) { logged = append(logged, s) }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"config unset rl-removed limits.cpu",
		"config unset rl-removed limits.memory",
		"config unset rl-removed limits.processes",
		"config device unset rl-removed root limits.read",
	}
	if got := limitWrites(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("writes = %q, want %q", got, want)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "limits.processes") {
		t.Errorf("log = %q, want one line naming the changed keys", logged)
	}
}

func TestReconcileLimits_RaisedSetsOnlyChangedKeys(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-raised", "config:\n  limits.cpu: \"2\"\n  limits.memory: 2GiB\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.CPU.Count = "4"
	cfg.Memory.Limit = "2GiB"

	if err := ReconcileLimits("rl-raised", "default", cfg, func(string) {}); err != nil {
		t.Fatal(err)
	}
	want := []string{"config set rl-raised limits.cpu=4"}
	if got := limitWrites(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("writes = %q, want %q", got, want)
	}
}

func TestReconcileLimits_DiskLimitAddsInstanceRootDevice(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-disk", "config: {}\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.Disk.Read = "50MB"

	if err := ReconcileLimits("rl-disk", "default", cfg, func(string) {}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "config device add rl-disk root disk path=/ pool=default") {
		t.Errorf("root device not made instance-level before the set; calls:\n%s", b)
	}
	want := []string{"config device set rl-disk root limits.read=50MB"}
	if got := limitWrites(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("writes = %q, want %q", got, want)
	}
}

func TestReconcileLimits_MatchingConfigWritesNothing(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-same", "config:\n  limits.processes: \"500\"\n  limits.memory.swap: \"true\"\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.Runtime.MaxProcesses = intPtr(500)
	cfg.Memory.Swap = "true"

	var logged []string
	if err := ReconcileLimits("rl-same", "default", cfg, func(s string) { logged = append(logged, s) }); err != nil {
		t.Fatal(err)
	}
	if got := limitWrites(t, logPath); len(got) != 0 {
		t.Errorf("writes = %q, want none", got)
	}
	if len(logged) != 0 {
		t.Errorf("log = %q, want none", logged)
	}
}

func TestWarnLimitsDrift_RunningContainerWarnsAndDoesNotSet(t *testing.T) {
	logPath := fakeLimitsIncus(t, "rl-running", "config:\n  limits.cpu: \"2\"\n  limits.processes: \"500\"\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.CPU.Count = "2"

	var logged []string
	warnLimitsDrift("rl-running", "default", cfg, func(s string) { logged = append(logged, s) })
	if len(logged) != 1 || !strings.Contains(logged[0], "(limits.processes)") || !strings.Contains(logged[0], "restart it") {
		t.Errorf("log = %q, want one warning naming limits.processes", logged)
	}
	if got := limitWrites(t, logPath); len(got) != 0 {
		t.Errorf("writes = %q, want none on a running container", got)
	}
}

func TestWarnLimitsDrift_NoDriftIsSilent(t *testing.T) {
	fakeLimitsIncus(t, "rl-nodrift", "config:\n  limits.cpu: \"2\"\ndevices: {}\n")
	cfg := &config.LimitsConfig{}
	cfg.CPU.Count = "2"

	var logged []string
	warnLimitsDrift("rl-nodrift", "default", cfg, func(s string) { logged = append(logged, s) })
	if len(logged) != 0 {
		t.Errorf("log = %q, want none", logged)
	}
}

// tmpfsRecorder is a container that records SetTmpfsSize and
// RemoveTmpfsSize.
type tmpfsRecorder struct {
	container.ContainerManager
	size    string
	removed bool
}

func (r *tmpfsRecorder) SetTmpfsSize(size string) error {
	r.size = size
	return nil
}

func (r *tmpfsRecorder) RemoveTmpfsSize() (bool, error) {
	r.removed = true
	return true, nil
}

func TestPhaseSizeTmpfs(t *testing.T) {
	sized := &config.LimitsConfig{}
	sized.Disk.TmpfsSize = "1GiB"
	for _, tc := range []struct {
		name                  string
		cfg                   *config.LimitsConfig
		skipLaunch, restarted bool
		wantSize              string
		wantRemoved           bool
	}{
		{"fresh launch", sized, false, false, "1GiB", false},
		{"fresh launch without tmpfs_size", &config.LimitsConfig{}, false, false, "", false},
		{"restarted persistent container", sized, true, true, "1GiB", false},
		{"restarted after tmpfs_size was removed", &config.LimitsConfig{}, true, true, "", true},
		{"running reuse or --container attach", sized, true, false, "", false},
		{"running reuse without tmpfs_size", &config.LimitsConfig{}, true, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &tmpfsRecorder{}
			st := &setupState{
				opts:       SetupOptions{LimitsConfig: tc.cfg, Logger: func(string) {}},
				result:     &SetupResult{Manager: mgr},
				skipLaunch: tc.skipLaunch,
				restarted:  tc.restarted,
			}
			if _, err := st.phaseSizeTmpfs(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mgr.size != tc.wantSize || mgr.removed != tc.wantRemoved {
				t.Errorf("SetTmpfsSize(%q) removed=%v, want %q removed=%v", mgr.size, mgr.removed, tc.wantSize, tc.wantRemoved)
			}
		})
	}
}

// limitsWorkspaceYAML is a container config with the workspace mounted from
// workspace and the given limits.* lines.
func limitsWorkspaceYAML(workspace, limitLines string) string {
	return "config:\n" + limitLines + "devices:\n  workspace:\n    path: /workspace\n    source: " + workspace + "\n    type: disk\n"
}

func TestPhaseReconcileExisting_RestartAppliesLimitsBeforeStart(t *testing.T) {
	ws := t.TempDir()
	logPath := fakeLimitsIncusStatus(t, "rl-restart", limitsWorkspaceYAML(ws, "  limits.cpu: \"2\"\n  limits.processes: \"500\"\n"), "STOPPED")
	cfg := &config.LimitsConfig{}
	cfg.CPU.Count = "4"
	cfg.Runtime.MaxProcesses = intPtr(0)
	st := &setupState{
		opts:   SetupOptions{Persistent: true, WorkspacePath: ws, LimitsConfig: cfg, Logger: func(string) {}},
		result: &SetupResult{Manager: container.NewManager("rl-restart"), ContainerName: "rl-restart"},
	}
	if _, err := st.phaseReconcileExisting(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !st.restarted {
		t.Error("restarted not set for a restarted persistent container")
	}
	b, _ := os.ReadFile(logPath)
	log := string(b)
	set := strings.Index(log, "config set rl-restart limits.cpu=4")
	unset := strings.Index(log, "config unset rl-restart limits.processes")
	start := strings.Index(log, "start rl-restart")
	if set < 0 || unset < 0 || start < 0 || set > start || unset > start {
		t.Errorf("want limits.cpu set and limits.processes unset before the start; calls:\n%s", log)
	}
}

func TestPhaseReconcileExisting_RunningReuseWarnsOnLimitDrift(t *testing.T) {
	ws := t.TempDir()
	logPath := fakeLimitsIncusStatus(t, "rl-reuse", limitsWorkspaceYAML(ws, "  limits.processes: \"500\"\n"), "RUNNING")
	cfg := &config.LimitsConfig{}
	cfg.Runtime.MaxProcesses = intPtr(0)
	var logged []string
	st := &setupState{
		opts:   SetupOptions{Persistent: true, WorkspacePath: ws, LimitsConfig: cfg, Logger: func(s string) { logged = append(logged, s) }},
		result: &SetupResult{Manager: container.NewManager("rl-reuse"), ContainerName: "rl-reuse"},
	}
	if _, err := st.phaseReconcileExisting(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.restarted {
		t.Error("restarted set for a running reuse")
	}
	if !strings.Contains(strings.Join(logged, "\n"), "different resource limits than the current config (limits.processes)") {
		t.Errorf("no drift warning; log:\n%s", strings.Join(logged, "\n"))
	}
	if got := limitWrites(t, logPath); len(got) != 0 {
		t.Errorf("writes = %q, want none on a running container", got)
	}
}
