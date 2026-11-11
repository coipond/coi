package cleanup

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInstanceHostVeths(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' '[{"name":"routed-db","state":{"network":{"eth0":{"host_name":"veth1a2b"},"lo":{"host_name":""}}}},{"name":"coi-abc12345-1","state":{"network":{"eth0":{"host_name":"veth3c4d"}}}},{"name":"stopped","state":null}]'
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := instanceHostVeths()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"veth1a2b": true, "veth3c4d": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("instanceHostVeths() = %v, want %v", got, want)
	}
}
