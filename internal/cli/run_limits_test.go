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

// A reused container whose eth0 anti-spoofing keys cannot be set does not
// start in restricted mode.
func TestLaunchContainerRunPhase_RestartNICSecurityFailsClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ws := t.TempDir()
	logPath := fakeStoppedIncus(t, "run-nic",
		"config: {}\ndevices:\n  eth0:\n    type: nic\n  workspace:\n    path: /workspace\n    source: "+ws+"\n    type: disk\n")
	script := filepath.Join(filepath.Dir(logPath), "incus")
	b, _ := os.ReadFile(script)
	refuse := strings.Replace(string(b), "case \"$*\" in\n", "case \"$*\" in\n  *\"eth0 security\"*) echo \"Error: refused\" >&2; exit 1 ;;\n", 1)
	if err := os.WriteFile(script, []byte(refuse), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.GetDefaultConfig()
	cfg.Network.Mode = config.NetworkModeRestricted
	cfg.Security.DisableProtection = true
	a := &App{cfg: cfg, persistent: true}
	s := &runState{absWorkspace: ws, containerName: "run-nic", img: "coi-default", slot: 1}

	_, err := a.launchContainerRunPhase(s).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "restricted mode") {
		t.Fatalf("want a fail-closed error, got %v", err)
	}
	if b, _ := os.ReadFile(logPath); strings.Contains(string(b), "start run-nic") {
		t.Errorf("want no start; calls:\n%s", b)
	}
}

// A fresh container whose eth0 anti-spoofing keys cannot be set does not
// start in restricted/allowlist mode; open mode warns and starts it.
func TestLaunchContainerRunPhase_CreateNICSecurity(t *testing.T) {
	for _, mode := range []config.NetworkMode{config.NetworkModeRestricted, config.NetworkModeAllowlist, config.NetworkModeOpen} {
		t.Run(string(mode), func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			dir := t.TempDir()
			logPath := filepath.Join(dir, "calls")
			script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n  *\"eth0 security\"*) echo \"Error: refused\" >&2; exit 1 ;;\nesac\nexit 0\n"
			if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			a := runWorkspaceKeyApp(false)
			a.cfg.Network.Mode = mode
			s := &runState{absWorkspace: t.TempDir(), containerName: "run-nic-create", img: "coi-default", slot: 1}

			var err error
			stderr := captureOutput(t, &os.Stderr, func() {
				_, err = a.launchContainerRunPhase(s).Run(context.Background())
			})
			b, _ := os.ReadFile(logPath)
			started := strings.Contains(string(b), "start run-nic-create")
			if mode == config.NetworkModeOpen {
				if err != nil || !started || !strings.Contains(stderr, "Warning: NIC security hardening not applied") {
					t.Errorf("want a warning and a start, got err %v, stderr %q, calls:\n%s", err, stderr, b)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), string(mode)+" mode") {
				t.Fatalf("want a fail-closed error, got %v", err)
			}
			if started {
				t.Errorf("want no start, calls:\n%s", b)
			}
		})
	}
}
