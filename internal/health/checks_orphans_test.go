package health

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/cleanup"
)

func TestCheckOrphanedResourcesCountsOnlyUnusedVeths(t *testing.T) {
	netDir := t.TempDir()
	for _, name := range []string{"veth-orphan", "veth-routed"} {
		if err := os.Mkdir(filepath.Join(netDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := cleanup.NetClassDir
	cleanup.NetClassDir = netDir
	t.Cleanup(func() { cleanup.NetClassDir = old })

	binDir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' '[{"name":"routed-db","state":{"network":{"eth0":{"host_name":"veth-routed"}}}}]'
`
	if err := os.WriteFile(filepath.Join(binDir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := CheckOrphanedResources()
	if n, _ := got.Details["orphaned_veths"].(int); n != 1 {
		t.Errorf("orphaned_veths = %v, want 1 (%s)", got.Details["orphaned_veths"], got.Message)
	}
}
