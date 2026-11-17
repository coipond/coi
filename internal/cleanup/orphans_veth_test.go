package cleanup

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeVethHost sets up a host with four veths, of which coi recorded all but
// veth-foreign, and an incus that reports veth-routed as an instance NIC (in
// another project). It returns the incus call log.
func fakeVethHost(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	recordsDir := filepath.Join(home, ".coi", "veths")
	if err := os.MkdirAll(recordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"veth-orphan", "veth-bridged", "veth-routed", "veth-gone"} {
		if err := os.WriteFile(filepath.Join(recordsDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	netDir := t.TempDir()
	for _, name := range []string{"veth-orphan", "veth-foreign", "veth-bridged", "veth-routed", "eth0"} {
		if err := os.Mkdir(filepath.Join(netDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(netDir, "veth-bridged", "master"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := netClassDir
	netClassDir = netDir
	t.Cleanup(func() { netClassDir = old })

	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "calls")
	script := `#!/bin/sh
echo "$*" >> ` + logPath + `
printf '%s\n' '[{"name":"routed-db","project":"default","state":{"network":{"eth0":{"host_name":"veth-routed"},"lo":{"host_name":""}}}},{"name":"stopped","state":null}]'
`
	if err := os.WriteFile(filepath.Join(binDir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	oldProject := container.IncusProject
	container.IncusProject = "coi"
	t.Cleanup(func() { container.IncusProject = oldProject })
	return logPath
}

func TestInstanceHostVethsListsAllProjects(t *testing.T) {
	logPath := fakeVethHost(t)

	got, err := instanceHostVeths()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]bool{"veth-routed": true}; !reflect.DeepEqual(got, want) {
		t.Errorf("instanceHostVeths() = %v, want %v", got, want)
	}

	b, _ := os.ReadFile(logPath)
	call := strings.TrimSpace(string(b))
	if call != "list --format=json --all-projects" {
		t.Errorf("incus call = %q, want list --all-projects without --project", call)
	}
}

// Only the recorded, master-less veth no instance uses is an orphan:
// veth-foreign (another tool's, never recorded) is kept.
func TestDetectOrphanedVethsOnlyRecordedVeths(t *testing.T) {
	fakeVethHost(t)

	got, err := DetectOrphanedVeths()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"veth-orphan"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DetectOrphanedVeths() = %v, want %v", got, want)
	}
}

// Without any record, nothing is an orphan and Incus is not asked.
func TestDetectOrphanedVethsNoRecords(t *testing.T) {
	logPath := fakeVethHost(t)
	if err := os.RemoveAll(filepath.Join(os.Getenv("HOME"), ".coi", "veths")); err != nil {
		t.Fatal(err)
	}

	got, err := DetectOrphanedVeths()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("DetectOrphanedVeths() = %v, want none", got)
	}
	if _, err := os.Stat(logPath); err == nil {
		t.Error("incus called with no recorded veths")
	}
}

// Unreadable records are no error, so DetectAll still runs the other scans.
func TestDetectOrphanedVethsUnreadableRecords(t *testing.T) {
	fakeVethHost(t)
	recordsDir := filepath.Join(os.Getenv("HOME"), ".coi", "veths")
	if err := os.RemoveAll(recordsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordsDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := DetectOrphanedVeths()
	if err != nil || len(got) != 0 {
		t.Errorf("DetectOrphanedVeths() = %v, %v; want none, no error", got, err)
	}
}
