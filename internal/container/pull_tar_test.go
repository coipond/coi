package container

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

func buildTar(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: mode, Size: int64(len(e.body)), Linkname: e.link}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// Only directories and regular files land on the host; links and devices are
// dropped; setuid bits are stripped.
func TestExtractTarStrict_KeepsOnlyDirsAndFiles(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	buf := buildTar(t, []tarEntry{
		{name: ".claude/", typ: tar.TypeDir, mode: 0o755},
		{name: ".claude/projects/", typ: tar.TypeDir, mode: 0o700},
		{name: ".claude/projects/a.jsonl", body: "hello", typ: tar.TypeReg, mode: 0o4755},
		{name: ".claude/evil-link", link: victim, typ: tar.TypeSymlink},
		{name: ".claude/hard", link: ".claude/projects/a.jsonl", typ: tar.TypeLink},
		{name: ".claude/dev", typ: tar.TypeChar},
	})
	if err := extractTarStrict(buf, dir, ".claude"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".claude/projects/a.jsonl"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("file: %q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, ".claude/projects/a.jsonl")); fi.Mode()&os.ModeSetuid != 0 {
		t.Error("setuid must be stripped")
	}
	for _, n := range []string{"evil-link", "hard", "dev"} {
		if _, err := os.Lstat(filepath.Join(dir, ".claude", n)); err == nil {
			t.Errorf("%s must not be materialized", n)
		}
	}
}

// Any entry outside base/ aborts the extraction.
func TestExtractTarStrict_RejectsEscapes(t *testing.T) {
	for _, name := range []string{"../x", "/etc/passwd", ".claude/../../x", "other/file", ".claudex/f"} {
		buf := buildTar(t, []tarEntry{{name: name, body: "x", typ: tar.TypeReg}})
		if err := extractTarStrict(buf, t.TempDir(), ".claude"); !errors.Is(err, errTarPullUnsafe) {
			t.Errorf("%q: want errTarPullUnsafe, got %v", name, err)
		}
	}
}

// A truncated stream is an error, never a silently partial copy.
func TestExtractTarStrict_TruncatedStream(t *testing.T) {
	buf := buildTar(t, []tarEntry{{name: ".claude/f", body: "0123456789", typ: tar.TypeReg}})
	cut := bytes.NewReader(buf.Bytes()[:516]) // mid-body; a cut at an entry boundary is caught by tar's exit status instead
	if err := extractTarStrict(cut, t.TempDir(), ".claude"); err == nil {
		t.Error("truncated stream must fail")
	}
}

// End to end with a fake incus that runs the real tar on a host directory:
// the tree arrives intact, a planted symlink does not, and an existing
// destination is refused.
func TestPullDirectoryTar_EndToEnd(t *testing.T) {
	root := t.TempDir() // stands in for the container's filesystem
	src := filepath.Join(root, "home", "code", ".claude")
	if err := os.MkdirAll(filepath.Join(src, "projects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "projects", "s.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"# argv: --project P exec NAME -- sh -c SCRIPT NAME0 PARENT BASE\n" +
		"shift 2; [ \"$1\" = exec ] || exit 9; shift 3\n" +
		"[ \"$1\" = sh ] || exit 9\n" +
		"exec sh -c \"$3\" \"$4\" \"" + root + "$5\" \"$6\"\n"
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	dest := filepath.Join(t.TempDir(), "saved")
	m := NewManager("c1")
	if err := m.PullDirectoryTar("/home/code/.claude", dest); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "projects", "s.jsonl")); err != nil || string(b) != "{}\n" {
		t.Errorf("pulled file: %q %v", b, err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		t.Error("symlink must not be pulled")
	}
	if err := m.PullDirectoryTar("/home/code/.claude", dest); err == nil {
		t.Error("existing destination must be refused")
	}
	if err := m.PullDirectoryTar("/home/code/missing", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("missing source must fail")
	}
}

// A failing stream (any non-zero exit after the in-container 1->0 mapping)
// is never accepted, even if what arrived parses as a complete archive.
func TestPullDirectoryTar_NonZeroExitFails(t *testing.T) {
	bin := t.TempDir()
	// Emits an empty-but-valid archive, then fails like a dropped incus stream.
	script := "#!/bin/sh\nhead -c 1024 /dev/zero\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := NewManager("c1").PullDirectoryTar("/home/code/.claude", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("exit 1 from incus must fail the pull")
	}
}
