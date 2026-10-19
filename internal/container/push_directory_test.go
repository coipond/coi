package container

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIncusScript puts an `incus` script on PATH that logs its argv (one call per
// line) and runs body, and returns the log path.
func fakeIncusScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func readCalls(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestPushDirectory_SameNamePushesToParent(t *testing.T) {
	log := fakeIncusScript(t, "exit 0")
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushDirectory(src, "/tmp/src"); err != nil {
		t.Fatalf("PushDirectory() error = %v", err)
	}
	calls := readCalls(t, log)
	want := "--project " + IncusProject + " file push -r " + src + " c1/tmp/"
	if len(calls) != 1 || calls[0] != want {
		t.Errorf("incus calls = %q, want [%q]", calls, want)
	}
}

// A rename stages a copy on the host under the target name and only uses
// `incus file push`, so it also works on a stopped container (no exec).
func TestPushDirectory_RenameStagesOnHost(t *testing.T) {
	log := fakeIncusScript(t, `case "$*" in *"file push"*) ls -R "$6" > "$(dirname "$0")/staged.txt";; esac`)
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushDirectory(src, "/tmp/renamed/"); err != nil {
		t.Fatalf("PushDirectory() error = %v", err)
	}
	calls := readCalls(t, log)
	if len(calls) != 1 || !strings.Contains(calls[0], " file push -r ") || !strings.HasSuffix(calls[0], "/renamed c1/tmp/") {
		t.Fatalf("incus calls = %q, want one push of a staged .../renamed to c1/tmp/", calls)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(log), "staged.txt"))
	if err != nil || !strings.Contains(string(staged), "b.txt") {
		t.Errorf("staged copy = %q, %v; want the source tree", staged, err)
	}
	stage := strings.Fields(calls[0])[5]
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("staged copy %s should be removed after the push", stage)
	}
}

func TestPathKind(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr error
	}{
		{"directory lists its entries", `echo '["a.txt", "sub"]'`, "dir", nil},
		{"empty directory", `echo '[]'`, "dir", nil},
		{"file answers with content", `echo 'hello'`, "other", nil},
		{"missing path", `echo 'Error: Not Found' >&2; exit 1`, "none", nil},
		{"missing container", `echo 'Error: Instance not found' >&2; exit 1`, "", ErrContainerNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := fakeIncusScript(t, tt.body)
			got, err := NewManager("c1").PathKind("/tmp/x y")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("PathKind() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil || got != tt.want {
				t.Fatalf("PathKind() = %q, %v; want %q", got, err, tt.want)
			}
			calls := readCalls(t, log)
			want := "query /1.0/instances/c1/files?path=%2Ftmp%2Fx+y&project=" + IncusProject
			if len(calls) != 1 || calls[0] != want {
				t.Errorf("incus calls = %q, want [%q] (no --project: query rejects it)", calls, want)
			}
		})
	}
}
