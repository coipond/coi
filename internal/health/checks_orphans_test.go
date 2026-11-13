package health

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckOrphanedResourcesCountsDetectedVeths(t *testing.T) {
	old := detectOrphanedVeths
	detectOrphanedVeths = func() ([]string, error) { return []string{"veth-orphan"}, nil }
	t.Cleanup(func() { detectOrphanedVeths = old })

	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "incus"), []byte("#!/bin/sh\necho '[]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := CheckOrphanedResources()
	if n, _ := got.Details["orphaned_veths"].(int); n != 1 {
		t.Errorf("orphaned_veths = %v, want 1 (%s)", got.Details["orphaned_veths"], got.Message)
	}
}
