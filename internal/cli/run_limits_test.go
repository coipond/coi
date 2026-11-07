package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// fakeStoppedIncus puts an `incus` on PATH that logs its calls and reports
// name as an existing, stopped container whose own config is configYAML.
func fakeStoppedIncus(t *testing.T, name, configYAML string) (logPath string) {
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
  *"list "*"--columns=ns"*) echo "` + name + `,STOPPED" ;;
  *"list "*"--columns=n"*) echo "` + name + `" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestLaunchContainerRunPhase_RestartAppliesLimitsBeforeStart(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	logPath := fakeStoppedIncus(t, "run-limits",
		"config:\n  limits.cpu: \"2\"\n  limits.processes: \"500\"\ndevices:\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n")
	cfg := config.GetDefaultConfig()
	cfg.Network.Mode = config.NetworkModeOpen
	cfg.Security.DisableProtection = true
	cfg.Limits = config.LimitsConfig{}
	cfg.Limits.CPU.Count = "4"
	a := &App{cfg: cfg, persistent: true}
	s := &runState{absWorkspace: ws, containerName: "run-limits", img: "coi-default", slot: 1}

	if _, err := a.launchContainerRunPhase(s).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.wasRestarted {
		t.Fatal("wasRestarted not set")
	}
	b, _ := os.ReadFile(logPath)
	log := string(b)
	set := strings.Index(log, "config set run-limits limits.cpu=4")
	unset := strings.Index(log, "config unset run-limits limits.processes")
	start := strings.Index(log, "start run-limits")
	if set < 0 || unset < 0 || start < 0 || set > start || unset > start {
		t.Errorf("want limits.cpu set and limits.processes unset before the start; calls:\n%s", log)
	}
}

// tmpfsManager is a container that records the /tmp sizing calls.
type tmpfsManager struct {
	container.ContainerManager
	size    string
	removed bool
}

func (m *tmpfsManager) SetTmpfsSize(size string) error {
	m.size = size
	return nil
}

func (m *tmpfsManager) RemoveTmpfsSize() (bool, error) {
	m.removed = true
	return true, nil
}

func TestSizeTmpfsAndRemapUser(t *testing.T) {
	sized := &config.LimitsConfig{}
	sized.Disk.TmpfsSize = "1GiB"
	for _, tc := range []struct {
		name         string
		cfg          *config.LimitsConfig
		wasRestarted bool
		wantSize     string
		wantRemoved  bool
	}{
		{"fresh launch", sized, false, "1GiB", false},
		{"restart re-sizes", sized, true, "1GiB", false},
		{"restart after tmpfs_size was removed", &config.LimitsConfig{}, true, "", true},
		{"fresh launch without tmpfs_size", &config.LimitsConfig{}, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &tmpfsManager{}
			if err := sizeTmpfsAndRemapUser(mgr, tc.cfg, tc.wasRestarted, func(string) {}); err != nil {
				t.Fatal(err)
			}
			if mgr.size != tc.wantSize || mgr.removed != tc.wantRemoved {
				t.Errorf("SetTmpfsSize(%q) removed=%v, want %q removed=%v", mgr.size, mgr.removed, tc.wantSize, tc.wantRemoved)
			}
		})
	}
}
