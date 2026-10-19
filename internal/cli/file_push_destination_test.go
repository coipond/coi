package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKinds is a container filesystem for resolvePushDestination: paths not
// listed are "none".
func fakeKinds(kinds map[string]string) func(string) (string, error) {
	return func(p string) (string, error) {
		if k, ok := kinds[p]; ok {
			return k, nil
		}
		return "none", nil
	}
}

func TestResolvePushDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	kinds := fakeKinds(map[string]string{
		"/":              "dir",
		"/tmp":           "dir",
		"/tmp/existing":  "dir",
		"/tmp/taken/src": "dir",
		"/tmp/taken":     "dir",
		"/tmp/file":      "other",
		"/tmp/link":      "link",
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
	got, err := resolvePushDestination(".", "/tmp", fakeKinds(map[string]string{"/tmp": "dir"}))
	if err != nil || got != "/tmp/project" {
		t.Errorf("resolvePushDestination(\".\") = %q, %v; want /tmp/project", got, err)
	}
}

func TestResolvePushDestination_KindError(t *testing.T) {
	kind := func(string) (string, error) { return "", errors.New("exec failed") }
	if _, err := resolvePushDestination(t.TempDir(), "/tmp/x", kind); err == nil || !strings.Contains(err.Error(), "exec failed") {
		t.Errorf("error = %v, want the probe error", err)
	}
}
