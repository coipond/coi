package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeScopeIncus puts an incus script on PATH that lists the given
// containers and logs every other call. It returns the log path.
func fakeScopeIncus(t *testing.T, listJSON, listCSV string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
case "$*" in
  *"list --format=json"*) printf '%s\n' '` + listJSON + `' ;;
  *"list --format csv -c ns"*) printf '` + listCSV + `' ;;
  *"--format csv -c s") echo FROZEN ;;
  *) echo "$*" >> ` + logPath + ` ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestCoiContainerPatternSkipsForeignContainers(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"default prefix", "", []string{"coi-abc12345-1", "coi-db"}},
		{"custom prefix", "coi.t-", []string{"coi.t-abc12345-1"}},
	}
	listJSON := `[{"name":"coi-abc12345-1"},{"name":"web-coi-abc12345-1"},` +
		`{"name":"coi-db"},{"name":"mycoi-db"},{"name":"postgres"},` +
		`{"name":"coi.t-abc12345-1"},{"name":"coiXt-abc12345-1"}]`
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COI_CONTAINER_PREFIX", tt.prefix)
			fakeScopeIncus(t, listJSON, "")

			got, err := container.ListContainers(coiContainerPattern())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListContainers(%q) = %v, want %v", coiContainerPattern(), got, tt.want)
			}
		})
	}
}

func TestUnfreezeAllFrozenSkipsForeignContainers(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "coi-test-")
	logPath := fakeScopeIncus(t, "[]",
		`coi-test-abc12345-1,FROZEN\ncoi-abc12345-1,FROZEN\nweb-db,FROZEN\nweb-coi-test-1,FROZEN\n`)

	if err := unfreezeAllFrozen(); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.Contains(line, "start") && !strings.Contains(line, "coi-test-abc12345-1") {
			t.Errorf("unfreeze touched a container outside the prefix: %q", line)
		}
	}
	if !strings.Contains(string(b), "start coi-test-abc12345-1") {
		t.Errorf("unfreeze did not start the coi container; calls:\n%s", b)
	}
}
