package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeKinds is a container filesystem for resolvePushDestination: paths not
// listed are container.PathNone.
func fakeKinds(kinds map[string]container.PathKind) func(string) (container.PathKind, error) {
	return func(p string) (container.PathKind, error) {
		if k, ok := kinds[p]; ok {
			return k, nil
		}
		return container.PathNone, nil
	}
}

func TestResolvePushDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	kinds := fakeKinds(map[string]container.PathKind{
		"/":              container.PathDir,
		"/tmp":           container.PathDir,
		"/tmp/existing":  container.PathDir,
		"/tmp/taken/src": container.PathDir,
		"/tmp/taken":     container.PathDir,
		"/tmp/file":      container.PathOther,
		"/tmp/link":      container.PathOther, // a symlink
	})

	tests := []struct {
		name    string
		remote  string
		want    string
		wantErr string
	}{
		{"new name is the exact target", "/tmp/renamed", "/tmp/renamed", ""},
		{"existing dir receives src inside", "/tmp/existing", "/tmp/existing/src", ""},
		{"existing dir with trailing slash", "/tmp/existing/", "/tmp/existing/src", ""},
		{"trailing slash on a missing dir", "/tmp/renamed/", "", "trailing slash requires an existing directory"},
		{"trailing slash on a file", "/tmp/file/", "", "is not a directory"},
		{"final target already exists", "/tmp/taken", "", `"/tmp/taken/src" already exists`},
		{"existing file", "/tmp/file", "", "already exists"},
		{"symlink is not a directory", "/tmp/link", "", "already exists"},
		{"root", "/", "/src", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolvePushDestination(src, tt.remote, kinds)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolvePushDestination(%q) error = %v, want %q", tt.remote, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("resolvePushDestination(%q) = %q, %v; want %q", tt.remote, got, err, tt.want)
			}
		})
	}
}

func TestResolvePushDestination_DotUsesRealName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	got, err := resolvePushDestination(".", "/tmp", fakeKinds(map[string]container.PathKind{"/tmp": container.PathDir}))
	if err != nil || got != "/tmp/project" {
		t.Errorf("resolvePushDestination(\".\") = %q, %v; want /tmp/project", got, err)
	}
}

func TestResolvePushDestination_KindError(t *testing.T) {
	kind := func(string) (container.PathKind, error) { return "", errors.New("exec failed") }
	if _, err := resolvePushDestination(t.TempDir(), "/tmp/x", kind); err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("error = %v, want the probe error", err)
	}
}
