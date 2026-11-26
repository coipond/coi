package session

import (
	"errors"
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
