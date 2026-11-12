package limits

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

func TestDesiredLimits_CoversEveryLimitKey(t *testing.T) {
	opts := ApplyOptions{
		CPU:     CPULimits{Count: "2", Allowance: "50%", Priority: 3},
		Memory:  MemoryLimits{Limit: "2GiB", Enforce: "hard", Swap: "false"},
		Disk:    DiskLimits{Read: "10MB", Write: "20MB", Max: "30MB", Priority: 4, Size: "8GiB"},
		Runtime: RuntimeLimits{MaxProcesses: 500},
	}
	want := map[string]string{
		"limits.cpu":                "2",
		"limits.cpu.allowance":      "50%",
		"limits.cpu.priority":       "3",
		"limits.memory":             "2GiB",
		"limits.memory.enforce":     "hard",
		"limits.memory.swap":        "false",
		"limits.processes":          "500",
		"root.limits.read":          "10MB",
		"root.limits.write":         "20MB",
		"root.limits.max":           "30MB",
		"root.limits.disk.priority": "4",
		"root.size":                 "8GiB",
	}
	got := DesiredLimits(opts)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredLimits = %v, want %v", got, want)
	}
	for _, k := range container.LimitKeys {
		if _, ok := want[k]; !ok {
			t.Errorf("container.LimitKeys has %q, not covered here", k)
		}
	}

	if got := DesiredLimits(ApplyOptions{Memory: MemoryLimits{Swap: "TRUE"}})["limits.memory.swap"]; got != "true" {
		t.Errorf("swap TRUE = %q, want normalised true", got)
	}

	for k, v := range DesiredLimits(ApplyOptions{}) {
		if v != "" {
			t.Errorf("empty options: %s = %q, want unset", k, v)
		}
	}
}

// fakeIncus puts an `incus` on PATH that logs its calls, answers `config
// show` with configYAML and `storage list` with poolsJSON.
func fakeIncus(t *testing.T, configYAML, poolsJSON string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	for name, body := range map[string]string{"config.yaml": configYAML, "pools.json": poolsJSON} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
case "$*" in
  *"config show "*) cat ` + filepath.Join(dir, "config.yaml") + ` ;;
  *"storage list"*) cat ` + filepath.Join(dir, "pools.json") + ` ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// A root disk size added on restart is checked like on create: a pool that
// cannot enforce it fails the reconcile, and nothing is set.
func TestReconcileResourceLimits_SizeOnNonQuotaPoolFails(t *testing.T) {
	logPath := fakeIncus(t,
		"config: {}\ndevices:\n  root:\n    path: /\n    pool: default\n    type: disk\n",
		`[{"name":"default","driver":"dir"}]`)

	_, err := ReconcileResourceLimits(context.Background(), ApplyOptions{ContainerName: "rc-quota", Disk: DiskLimits{Size: "8GiB"}})
	if err == nil || !strings.Contains(err.Error(), "quota-capable") {
		t.Fatalf("err = %v, want a quota-capable pool error", err)
	}
	if b, _ := os.ReadFile(logPath); strings.Contains(string(b), "device set") {
		t.Errorf("a device key was set; calls:\n%s", b)
	}
}

// Instance limits go in one `config set` and root disk limits in one
// `config device set`.
func TestApplyResourceLimits_OneCallPerKind(t *testing.T) {
	logPath := fakeIncus(t, "devices:\n  root:\n    path: /\n    pool: p1\n    type: disk\n", `[{"name":"p1","driver":"btrfs"}]`)
	opts := ApplyOptions{
		ContainerName: "c1",
		CPU:           CPULimits{Count: "2"},
		Memory:        MemoryLimits{Limit: "2GiB", Enforce: "hard", Swap: "false"},
		Disk:          DiskLimits{Read: "10MB", Size: "8GiB"},
		Runtime:       RuntimeLimits{MaxProcesses: 500},
	}
	if err := ApplyResourceLimits(opts); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(logPath)
	var writes []string
	for _, c := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.Contains(c, " set ") || strings.Contains(c, " add ") {
			writes = append(writes, c[strings.Index(c, "config "):])
		}
	}
	want := []string{
		"config set c1 limits.cpu=2 limits.memory=2GiB limits.memory.enforce=hard limits.memory.swap=false limits.processes=500",
		"config device add c1 root disk path=/ pool=p1",
		"config device set c1 root limits.read=10MB size=8GiB",
	}
	if !reflect.DeepEqual(writes, want) {
		t.Errorf("writes = %q, want %q", writes, want)
	}
}

func TestApplyResourceLimits_NoneSet(t *testing.T) {
	logPath := fakeIncus(t, "", "")
	if err := ApplyResourceLimits(ApplyOptions{ContainerName: "c1"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(logPath); len(b) != 0 {
		t.Errorf("calls = %q, want none", b)
	}
}
