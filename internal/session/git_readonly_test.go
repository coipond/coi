package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// testBotName / testBotEmail are the single source for the fake locked identity
// used across session tests. Kept in one place so the value can't drift between
// fixtures (a duplicated copy previously went stale on the account number).
const (
	testBotName  = "coipond-coder[bot]"
	testBotEmail = "317930231+coipond-coder[bot]@users.noreply.github.com"
)

func TestGitConfigQuote(t *testing.T) {
	cases := map[string]string{
		"coipond-coder[bot]": `"coipond-coder[bot]"`, // brackets are ordinary in a value
		`a"b`:                `"a\"b"`,               // quote escaped
		`a\b`:                `"a\\b"`,               // backslash escaped
		"a\nb":               `"a\nb"`,               // newline escaped (no broken multi-line entry)
		"plain":              `"plain"`,
	}
	for in, want := range cases {
		if got := gitConfigQuote(in); got != want {
			t.Errorf("gitConfigQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderReadonlyGitConfig(t *testing.T) {
	got := renderReadonlyGitConfig(GitIdentity{
		Name:  testBotName,
		Email: testBotEmail,
	}, "")
	for _, want := range []string{
		`name = "` + testBotName + `"`,
		`email = "` + testBotEmail + `"`,
		"useConfigOnly = true",
		"[user]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config missing %q:\n%s", want, got)
		}
	}
}

func TestRenderReadonlyGitConfig_HooksPath(t *testing.T) {
	id := GitIdentity{Name: "Bot", Email: "bot@x"}
	with := renderReadonlyGitConfig(id, "/etc/coi/git-hooks")
	if !strings.Contains(with, "[core]") || !strings.Contains(with, `hooksPath = "/etc/coi/git-hooks"`) {
		t.Errorf("hooksPath must be baked into the readonly config:\n%s", with)
	}
	if without := renderReadonlyGitConfig(id, ""); strings.Contains(without, "hooksPath") {
		t.Errorf("empty hooksPath must not add a core section:\n%s", without)
	}
}

func TestReadonlyGitConfigHostPath_DistinctPerHooksPath(t *testing.T) {
	id := GitIdentity{Name: "A", Email: "a@x"}
	// Two parallel slots differing only in strip_attribution must not race on
	// one host file with different contents.
	if readonlyGitConfigHostPath("/home/u", id, "") == readonlyGitConfigHostPath("/home/u", id, "/etc/coi/git-hooks") {
		t.Error("distinct hooksPath values must map to distinct host paths")
	}
}

func TestReadonlyGitConfigHostPath_DistinctPerIdentity(t *testing.T) {
	a := readonlyGitConfigHostPath("/home/u", GitIdentity{Name: "A", Email: "a@x"}, "")
	b := readonlyGitConfigHostPath("/home/u", GitIdentity{Name: "B", Email: "b@x"}, "")
	if a == b {
		t.Error("distinct identities must map to distinct host paths")
	}
	if !strings.Contains(a, filepath.Join(".coi", "git-identity")) {
		t.Errorf("host path should live under ~/.coi/git-identity: %q", a)
	}
}

// stubMounter records the device operations so SetupGitIdentityReadonly can be
// exercised without a real container.
type stubMounter struct {
	removed     []string
	mounted     bool
	source      string
	path        string
	readonly    bool
	mountErr    error
	mountCalled bool
}

func (s *stubMounter) RemoveDevice(name string) error {
	s.removed = append(s.removed, name)
	return nil
}

func (s *stubMounter) MountDisk(name, source, path string, _, readonly bool) error {
	s.mountCalled = true
	s.mounted = true
	s.source = source
	s.path = path
	s.readonly = readonly
	return s.mountErr
}

func TestSetupGitIdentityReadonly(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // don't touch the real ~/.coi
	id := GitIdentity{Name: "Bot", Email: "bot@example.com"}

	t.Run("removes stale device then mounts read-only at the resolved home", func(t *testing.T) {
		m := &stubMounter{}
		if err := SetupGitIdentityReadonly(m, "/root", id, ""); err != nil {
			t.Fatalf("SetupGitIdentityReadonly: %v", err)
		}
		if len(m.removed) != 1 || m.removed[0] != gitReadonlyDeviceName {
			t.Errorf("must remove the stale git-identity device first, got %v", m.removed)
		}
		if m.path != "/root/.gitconfig" {
			t.Errorf("mount must target the RESOLVED home (/root here), got %q", m.path)
		}
		if !m.readonly {
			t.Error("mount must be read-only")
		}
		// Atomically installed and world-readable (0644) so the container's code
		// user can read it regardless of uid shift.
		fi, err := os.Stat(m.source)
		if err != nil {
			t.Fatalf("host gitconfig should exist: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o644 {
			t.Errorf("host gitconfig perms = %o, want 0644", perm)
		}
		data, err := os.ReadFile(m.source)
		if err != nil {
			t.Fatalf("host gitconfig should exist: %v", err)
		}
		if !strings.Contains(string(data), `name = "Bot"`) {
			t.Errorf("host gitconfig content unexpected:\n%s", data)
		}
	})

	t.Run("fails closed when the mount fails", func(t *testing.T) {
		m := &stubMounter{mountErr: errors.New("incus boom")}
		if err := SetupGitIdentityReadonly(m, "/home/code", id, ""); err == nil {
			t.Fatal("a mount failure must return an error (fail closed), not nil")
		}
	})
}

// inode returns the file's inode, so a test can tell "left alone" from
// "replaced with identical content".
func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode numbers on this platform")
	}
	return st.Ino
}

// The host gitconfig is the source of a disk device on every container using the
// identity. Replacing it (even with identical bytes) unlinks the inode Incus may
// be binding for another container's start, which aborts that start, so a
// relaunch must leave the existing file untouched.
func TestWriteReadonlyGitConfigHostFile_NeverReplacesExisting(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := GitIdentity{Name: "Bot", Email: "bot@example.com"}

	first, err := writeReadonlyGitConfigHostFile(id, "/etc/coi/git-hooks")
	if err != nil {
		t.Fatal(err)
	}
	before := inode(t, first)
	for range 3 {
		again, err := writeReadonlyGitConfigHostFile(id, "/etc/coi/git-hooks")
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("path changed between launches: %q -> %q", first, again)
		}
	}
	if after := inode(t, first); after != before {
		t.Errorf("an unchanged config was replaced (inode %d -> %d); a container starting meanwhile loses its mount", before, after)
	}
	assertNoTempFiles(t, filepath.Dir(first))
}

// Parallel launches with one identity (many slots starting at once) must all get
// the same path, and only the first may create the file.
func TestWriteReadonlyGitConfigHostFile_ConcurrentLaunches(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	id := GitIdentity{Name: "Bot", Email: "bot@example.com"}

	first, err := writeReadonlyGitConfigHostFile(id, "")
	if err != nil {
		t.Fatal(err)
	}
	before := inode(t, first)

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Go(func() {
			got, err := writeReadonlyGitConfigHostFile(id, "")
			if err == nil && got != first {
				err = fmt.Errorf("got path %q, want %q", got, first)
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if after := inode(t, first); after != before {
		t.Errorf("concurrent launches replaced the installed config (inode %d -> %d)", before, after)
	}
	assertNoTempFiles(t, filepath.Dir(first))
}

// A file with the wrong content at the content-addressed path (e.g. torn by a
// crash) is repaired, and a wrong mode is fixed in place without replacing it.
func TestWriteReadonlyGitConfigHostFile_RepairsContentAndMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	id := GitIdentity{Name: "Bot", Email: "bot@example.com"}
	want := renderReadonlyGitConfig(id, "")
	path := readonlyGitConfigHostPath(home, id, "")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("[user]\n\tname = torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeReadonlyGitConfigHostFile(id, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Errorf("wrong content not repaired:\n%s", got)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	before := inode(t, path)
	if _, err := writeReadonlyGitConfigHostFile(id, ""); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 0644 so the container user can read it", fi.Mode().Perm())
	}
	if after := inode(t, path); after != before {
		t.Error("fixing the mode must not replace the file")
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	tmps, err := filepath.Glob(filepath.Join(dir, ".gitconfig-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmps) != 0 {
		t.Errorf("temp files left behind: %v", tmps)
	}
}
