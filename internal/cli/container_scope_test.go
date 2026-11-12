package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
)

// fakeScopeIncus puts an incus script on PATH that lists the given
// containers and logs every other call. It returns the log path.
func fakeScopeIncus(t *testing.T, listNames, listCSV string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := `#!/bin/sh
case "$*" in
  *"list --format=csv --columns=n"*) printf '%s\n' '` + listNames + `' ;;
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

func TestContainerPatternSkipsForeignContainers(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{"default prefix", "", []string{"coi-abc12345-1", "coi-db"}},
		{"custom prefix", "coi.t-", []string{"coi.t-abc12345-1"}},
	}
	listNames := "coi-abc12345-1\nweb-coi-abc12345-1\n" +
		"coi-db\nmycoi-db\npostgres\ncoi.t-abc12345-1\ncoiXt-abc12345-1"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COI_CONTAINER_PREFIX", tt.prefix)
			fakeScopeIncus(t, listNames, "")

			got, err := container.ListContainers(session.ContainerPattern())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListContainers(%q) = %v, want %v", session.ContainerPattern(), got, tt.want)
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

// assertNoCallFor fails when any logged incus call names name.
func assertNoCallFor(t *testing.T, logPath, name string) {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, name) {
			t.Errorf("incus call on foreign container %s: %q", name, line)
		}
	}
}

const scopeListNames = `coi-abc12345-1
coi-abc12345-2
web-coi-abc12345-1`

func TestTmuxListSkipsForeignContainers(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	logPath := fakeScopeIncus(t, scopeListNames, "")

	if err := tmuxListCommand(tmuxListCmd, nil); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "coi-abc12345-1") {
		t.Fatalf("tmux list did not check the coi container; calls:\n%s", b)
	}
	assertNoCallFor(t, logPath, "web-coi-")
}

func TestAttachListSkipsForeignContainers(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	t.Setenv("HOME", t.TempDir())
	logPath := fakeScopeIncus(t, scopeListNames, "")
	attachCmd.SetContext(t.Context())

	if err := (&App{cfg: &config.Config{}}).attachCommand(attachCmd, nil); err != nil {
		t.Fatal(err)
	}

	b, _ := os.ReadFile(logPath)
	if !strings.Contains(string(b), "coi-abc12345-2") {
		t.Fatalf("attach did not check the coi containers; calls:\n%s", b)
	}
	assertNoCallFor(t, logPath, "web-coi-")
}
