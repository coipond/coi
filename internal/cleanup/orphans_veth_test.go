package cleanup

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeVethHost sets up a host with three veths and an incus that reports
// veth-routed as an instance NIC (in another project). It returns the
// incus call log.
func fakeVethHost(t *testing.T) string {
	t.Helper()
	netDir := t.TempDir()
	for _, name := range []string{"veth-orphan", "veth-bridged", "veth-routed", "eth0"} {
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

func TestDetectOrphanedVethsKeepsInstanceVeths(t *testing.T) {
	fakeVethHost(t)

	got, err := DetectOrphanedVeths()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"veth-orphan"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DetectOrphanedVeths() = %v, want %v", got, want)
	}
}
