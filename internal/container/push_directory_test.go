package container

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// stubPushArchive fixes pushArchiveSupported for one test.
func stubPushArchive(t *testing.T, ok bool) {
	t.Helper()
	orig := pushArchiveSupported
	pushArchiveSupported = func() bool { return ok }
	t.Cleanup(func() { pushArchiveSupported = orig })
}

// resetPushArchive gives one test a fresh, unprobed pushArchiveSupported.
func resetPushArchive(t *testing.T) {
	t.Helper()
	orig := pushArchiveSupported
	pushArchiveSupported = newPushArchiveCheck()
	t.Cleanup(func() { pushArchiveSupported = orig })
}

func TestPushDirectory_SameNamePushesToParent(t *testing.T) {
	stubPushArchive(t, false)
	log := fakeIncusScript(t, "exit 0")
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushDirectory(src, "/tmp/src"); err != nil {
		t.Fatalf("PushDirectory() error = %v", err)
	}
	logged := calls(t, log)
	want := "--project " + IncusProject + " file push -r " + src + " c1/tmp/"
	if len(logged) != 1 || logged[0] != want {
		t.Errorf("incus calls = %q, want [%q]", logged, want)
	}
}

// An Incus 7.5+ client, and an LTS client with the backport (7.0.2), makes a
// recursively pushed tree root-owned with umask-masked modes unless the push
// passes --archive, which older clients do not have. Every push form gets the
// flag when the client's help lists it; the help is read once.
func TestPushDirectory_ArchiveByClientHelp(t *testing.T) {
	tests := []struct {
		name    string
		help    string
		archive bool
	}{
		{"7.0.1 and 7.4 without the flag", "  -p, --create-dirs   Create any directories necessary", false},
		{"7.0.2 and 7.5+ with the flag", "  -a, --archive       Preserve ownership, timestamps and mode (implies --recursive)", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetPushArchive(t)
			log := fakeIncusScript(t, `case "$*" in *"push --help") echo "`+tt.help+`";; esac`)
			src := filepath.Join(t.TempDir(), "src")
			if err := os.Mkdir(src, 0o755); err != nil {
				t.Fatal(err)
			}

			mgr := NewManager("c1")
			for _, target := range []string{"/tmp/src", "/", "/tmp/renamed"} {
				if err := mgr.PushDirectory(src, target); err != nil {
					t.Fatalf("PushDirectory(%q) error = %v", target, err)
				}
			}
			push := "--project " + IncusProject + " file push -r "
			if tt.archive {
				push += "--archive "
			}
			logged := calls(t, log)
			want := []string{"--project " + IncusProject + " file push --help", push + src + " c1/tmp/", push + src + " c1/"}
			if len(logged) != 4 || !slices.Equal(logged[:3], want) {
				t.Fatalf("incus calls = %q, want %q + a staged push", logged, want)
			}
			if tt.archive {
				push += "-H "
			}
			if staged := logged[3]; !strings.HasPrefix(staged, push) || !strings.HasSuffix(staged, "/renamed c1/tmp/") {
				t.Errorf("staged push = %q, want %q<stage>/renamed c1/tmp/", staged, push)
			}
		})
	}
}

// A failed help probe keeps the push that works on every client.
func TestPushDirectory_HelpProbeFailurePushesWithoutArchive(t *testing.T) {
	resetPushArchive(t)
	log := fakeIncusScript(t, `case "$*" in *"push --help") exit 1;; esac`)
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushDirectory(src, "/"); err != nil {
		t.Fatalf("PushDirectory() error = %v", err)
	}
	want := "--project " + IncusProject + " file push -r " + src + " c1/"
	if logged := calls(t, log); len(logged) != 2 || logged[1] != want {
		t.Errorf("incus calls = %q, want [help probe, %q]", logged, want)
	}
}

// A rename stages a copy on the host under the target name and only uses
// `incus file push`, so it also works on a stopped container (no exec).
func TestPushDirectory_RenameStagesOnHost(t *testing.T) {
	stubPushArchive(t, false)
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
	logged := calls(t, log)
	if len(logged) != 1 || !strings.Contains(logged[0], " file push -r ") || !strings.HasSuffix(logged[0], "/renamed c1/tmp/") {
		t.Fatalf("incus calls = %q, want one push of a staged .../renamed to c1/tmp/", logged)
	}
	staged, err := os.ReadFile(filepath.Join(filepath.Dir(log), "staged.txt"))
	if err != nil || !strings.Contains(string(staged), "b.txt") {
		t.Errorf("staged copy = %q, %v; want the source tree", staged, err)
	}
	stage := strings.Fields(logged[0])[5]
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("staged copy %s should be removed after the push", stage)
	}
}

// With --archive, the push sends each entry's owner as the client sees it.
// A copy staged by a non-root coi would carry coi's UID wherever the source
// has another (e.g. root) owner, and a hard link fails across filesystems.
// So a rename pushes the source tree itself through a staged link, with -H.
func TestPushDirectory_RenameWithArchivePushesSourceTree(t *testing.T) {
	stubPushArchive(t, true)
	log := fakeIncusScript(t, `for a; do prev=$cur; cur=$a; done
readlink "$prev" > "$(dirname "$0")/link.txt"`)
	source := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "via-link")
	if err := os.Symlink(source, src); err != nil {
		t.Fatal(err)
	}

	if err := NewManager("c1").PushDirectory(src, "/tmp/renamed"); err != nil {
		t.Fatalf("PushDirectory() error = %v", err)
	}
	logged := calls(t, log)
	push := "--project " + IncusProject + " file push -r --archive -H "
	if len(logged) != 1 || !strings.HasPrefix(logged[0], push) || !strings.HasSuffix(logged[0], "/renamed c1/tmp/") {
		t.Fatalf("incus calls = %q, want [%q<stage>/renamed c1/tmp/]", logged, push)
	}
	want, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(filepath.Dir(log), "link.txt")); err != nil || strings.TrimSpace(string(b)) != want {
		t.Errorf("staged link points to %q, %v; want the real source %q", b, err, want)
	}
	stage := filepath.Dir(strings.Fields(logged[0])[7])
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Errorf("stage %s should be removed after the push", stage)
	}
	if _, err := os.Stat(source); err != nil {
		t.Errorf("source %s should be kept: %v", source, err)
	}
}

func TestPathKind(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    PathKind
		wantErr error
	}{
		{"directory lists its entries", `echo '["a.txt", "sub"]'`, PathDir, nil},
		{"empty directory", `echo '[]'`, PathDir, nil},
		{"file answers with content", `echo 'hello'`, PathOther, nil},
		{"missing path", `echo 'Error: Not Found' >&2; exit 1`, PathNone, nil},
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
			logged := calls(t, log)
			want := "query /1.0/instances/c1/files?path=%2Ftmp%2Fx+y&project=" + IncusProject
			if len(logged) != 1 || logged[0] != want {
				t.Errorf("incus calls = %q, want [%q] (no --project: query rejects it)", logged, want)
			}
		})
	}
}
