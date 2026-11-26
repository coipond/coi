package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

const nicMissingYAML = "config: {}\ndevices:\n  eth0:\n    type: nic\n"

const nicKeysYAML = "    security.ipv4_filtering: \"true\"\n    security.mac_filtering: \"true\"\n    security.port_isolation: \"true\"\n"

// fakeNICIncus answers `config show` with eth0 without the anti-spoofing keys
// until a `config device override` writes them.
func fakeNICIncus(t *testing.T, name string) (logPath string) {
	t.Helper()
	logPath = fakeLimitsIncus(t, name, nicMissingYAML)
	dir := filepath.Dir(logPath)
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"config device override "*) printf '` + strings.ReplaceAll(nicMissingYAML+nicKeysYAML, "\n", "\\n") + `' > ` + filepath.Join(dir, "config.yaml") + ` ;;
  *"config show "*` + name + `) cat ` + filepath.Join(dir, "config.yaml") + ` ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return logPath
}

// Restricted/allowlist reuse of a container without the keys sets them and
// says so.
func TestReconcileNICSecurity_SetsMissingKeys(t *testing.T) {
	for _, mode := range []config.NetworkMode{config.NetworkModeRestricted, config.NetworkModeAllowlist} {
		t.Run(string(mode), func(t *testing.T) {
			name := "nic-reuse-" + string(mode)
			logPath := fakeNICIncus(t, name)
			var logs []string
			if err := ReconcileNICSecurity(name, mode, func(s string) { logs = append(logs, s) }); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(logPath)
			if !strings.Contains(string(b), "config device override "+name+" eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true") {
				t.Fatalf("want the keys written, calls:\n%s", b)
			}
			if len(logs) != 1 || !strings.Contains(logs[0], "anti-spoofing") {
				t.Errorf("want one log line, got %q", logs)
			}
		})
	}
}

// Keys that cannot be set fail the restricted reuse.
func TestReconcileNICSecurity_FailsClosed(t *testing.T) {
	name := "nic-refused"
	logPath := fakeLimitsIncus(t, name, nicMissingYAML)
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"eth0 security"*) echo "Error: refused" >&2; exit 1 ;;
  *"config show "*` + name + `) cat ` + filepath.Join(filepath.Dir(logPath), "config.yaml") + ` ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(filepath.Dir(logPath), "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	err := ReconcileNICSecurity(name, config.NetworkModeRestricted, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "restricted mode") {
		t.Fatalf("want a fail-closed error naming the mode, got %v", err)
	}
}

func TestReconcileNICSecurity_AlreadyProtectedUntouched(t *testing.T) {
	name := "nic-protected"
	logPath := fakeLimitsIncus(t, name, nicMissingYAML+nicKeysYAML)
	var logs []string
	if err := ReconcileNICSecurity(name, config.NetworkModeRestricted, func(s string) { logs = append(logs, s) }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	if strings.Contains(string(b), "config device") {
		t.Errorf("want no device write, calls:\n%s", b)
	}
	if len(logs) != 0 {
		t.Errorf("want no log line, got %q", logs)
	}
}

func TestReconcileNICSecurity_OpenModeUnchanged(t *testing.T) {
	logPath := fakeLimitsIncus(t, "nic-open", nicMissingYAML)
	if err := ReconcileNICSecurity("nic-open", config.NetworkModeOpen, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(logPath); len(b) != 0 {
		t.Errorf("want no incus call in open mode, calls:\n%s", b)
	}
}

func TestNICSecurityError(t *testing.T) {
	cause := errors.New("refused")
	for _, mode := range []config.NetworkMode{config.NetworkModeRestricted, config.NetworkModeAllowlist} {
		if err := NICSecurityError(mode, cause); !errors.Is(err, cause) {
			t.Errorf("%s: got %v, want an error wrapping the cause", mode, err)
		}
	}
	for _, mode := range []config.NetworkMode{config.NetworkModeOpen, ""} {
		if err := NICSecurityError(mode, cause); err != nil {
			t.Errorf("%q: got %v, want nil (warn only)", mode, err)
		}
	}
}

// The shell reuse path runs the reconcile before the start and aborts on it.
func TestRestartStoppedContainer_NICSecurityFailsClosed(t *testing.T) {
	name := "nic-restart"
	logPath := fakeLimitsIncus(t, name, nicMissingYAML)
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"eth0 security"*) echo "Error: refused" >&2; exit 1 ;;
  *"config show "*` + name + `) cat ` + filepath.Join(filepath.Dir(logPath), "config.yaml") + ` ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(filepath.Dir(logPath), "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	result := &SetupResult{ContainerName: name, Manager: container.NewManager(name)}
	opts := &SetupOptions{Logger: func(string) {}}
	opts.Network.Config = &config.NetworkConfig{Mode: config.NetworkModeAllowlist}
	err := restartStoppedContainer(result, opts, name)
	if err == nil || !strings.Contains(err.Error(), "allowlist mode") {
		t.Fatalf("want a fail-closed error, got %v", err)
	}
	if b, _ := os.ReadFile(logPath); strings.Contains(string(b), " start ") {
		t.Errorf("want no start, calls:\n%s", b)
	}
}

// nicReuseYAML is a container config with eth0 (keys are its extra lines) and
// the workspace mounted from ws.
func nicReuseYAML(ws, keys string) string {
	return "config: {}\ndevices:\n  eth0:\n    type: nic\n" + keys +
		"  workspace:\n    path: /workspace\n    source: " + ws + "\n    type: disk\n"
}

// A container coi does not reconcile (running, or named with --container) is
// refused in restricted/allowlist mode while eth0 lacks the keys; with the keys,
// or in open mode, it is reused.
func TestPhaseReconcileExisting_NICSecurityRefusal(t *testing.T) {
	tests := []struct {
		name, status, explicit string
		mode                   config.NetworkMode
		keys                   string
		wantErr                string
	}{
		{"running persistent", "RUNNING", "", config.NetworkModeRestricted, "", "coi container stop"},
		{"running persistent allowlist", "RUNNING", "", config.NetworkModeAllowlist, "", "coi container stop"},
		{"running --container", "RUNNING", "x", config.NetworkModeRestricted, "", "without --container"},
		{"stopped --container", "STOPPED", "x", config.NetworkModeRestricted, "", "without --container"},
		{"running with keys", "RUNNING", "", config.NetworkModeRestricted, nicKeysYAML, ""},
		{"stopped --container with keys", "STOPPED", "x", config.NetworkModeAllowlist, nicKeysYAML, ""},
		{"running open mode", "RUNNING", "", config.NetworkModeOpen, "", ""},
		{"stopped --container open mode", "STOPPED", "x", config.NetworkModeOpen, "", ""},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ws := t.TempDir()
			name := fmt.Sprintf("nic-refuse-%d", i)
			logPath := fakeLimitsIncusStatus(t, name, nicReuseYAML(ws, tc.keys), tc.status)
			opts := SetupOptions{Persistent: true, WorkspacePath: ws, Logger: func(string) {}}
			if tc.explicit != "" {
				opts.ContainerName = name
			}
			opts.Network.Config = &config.NetworkConfig{Mode: tc.mode}
			st := &setupState{opts: opts, result: &SetupResult{Manager: container.NewManager(name), ContainerName: name}}
			_, err := st.phaseReconcileExisting(context.Background())
			b, _ := os.ReadFile(logPath)
			if tc.wantErr == "" {
				// A stopped container then fails later, at the fake's boot
				// network block; it got past the check if it was started.
				if err != nil && (tc.status == "RUNNING" || !strings.Contains(string(b), "start "+name)) {
					t.Fatalf("want reuse, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "security.ipv4_filtering") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want a refusal naming the keys and %q, got %v", tc.wantErr, err)
			}
			if strings.Contains(string(b), "start "+name) || strings.Contains(string(b), "config device") {
				t.Errorf("want no start and no device write, calls:\n%s", b)
			}
		})
	}
}

// failNICIncus is an incus that logs its calls and refuses the eth0 security
// keys; every other call succeeds.
func failNICIncus(t *testing.T) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + logPath + "\ncase \"$*\" in\n  *\"eth0 security\"*) echo \"Error: refused\" >&2; exit 1 ;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// A fresh container whose eth0 keys cannot be set is not started in
// restricted/allowlist mode; open mode warns and starts it.
func TestCreateAndStartContainer_NICSecurity(t *testing.T) {
	for _, mode := range []config.NetworkMode{config.NetworkModeRestricted, config.NetworkModeAllowlist, config.NetworkModeOpen} {
		t.Run(string(mode), func(t *testing.T) {
			logPath := failNICIncus(t)
			var logs []string
			result := &SetupResult{ContainerName: "nic-create", Manager: container.NewManager("nic-create")}
			opts := &SetupOptions{WorkspacePath: t.TempDir(), Logger: func(s string) { logs = append(logs, s) }}
			opts.Network.Config = &config.NetworkConfig{Mode: mode}
			err := createAndStartContainer(result, opts, "img", "nic-create")
			b, _ := os.ReadFile(logPath)
			started := strings.Contains(string(b), "start nic-create")
			if mode == config.NetworkModeOpen {
				if !started || !strings.Contains(strings.Join(logs, "\n"), "Warning: NIC security hardening not applied") {
					t.Errorf("want a warning and a start (err %v), logs %q, calls:\n%s", err, logs, b)
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
