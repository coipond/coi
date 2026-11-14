package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

const testHostsFile = "127.0.0.1\tlocalhost\n" +
	userHostsBeginMarker + "\n10.0.0.1\told\n" + userHostsEndMarker + "\n" +
	"::1\tlocalhost\n"

// runHostsRewriteScript runs the rewrite script with bash on local files.
func runHostsRewriteScript(path, copyPath, begin, end, block string) ([]byte, error) {
	script := hostsRewriteScript(path, copyPath, begin, end, block)
	return exec.Command("bash", "-c", script).CombinedOutput()
}

func TestHostsRewriteScript_WritesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	copyPath := filepath.Join(dir, "coi", "hosts")
	if err := os.WriteFile(path, []byte(testHostsFile), 0o644); err != nil {
		t.Fatal(err)
	}
	block := renderUserHostsBlock(nil)

	if out, err := runHostsRewriteScript(path, copyPath, userHostsBeginMarker, userHostsEndMarker, block); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(path)
	if want := "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + block + "\n"; string(got) != want {
		t.Errorf("hosts file = %q, want %q", got, want)
	}
	if _, err := os.Stat(copyPath); err == nil {
		t.Error("a writable file needs no copy")
	}
}

// unwritableHosts writes a read-only hosts file, which a non-root user cannot
// write, as container root cannot write an unmapped one (#977).
func unwritableHosts(t *testing.T, content string) (path, copyPath string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	dir := t.TempDir()
	path = filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(dir, "coi", "hosts")
}

// An unwritable file is left alone: the new content goes to the copy, which
// the script then bind-mounts over it. The mount needs root (the integration
// test covers it), so here it fails and the write error is reported.
func TestHostsRewriteScript_UnwritableFileWritesCopy(t *testing.T) {
	path, copyPath := unwritableHosts(t, testHostsFile)
	block := renderUserHostsBlock(nil)

	out, err := runHostsRewriteScript(path, copyPath, userHostsBeginMarker, userHostsEndMarker, block)
	if err == nil || !strings.Contains(string(out), "Permission denied") {
		t.Errorf("a failed mount should report the write error, got %v: %s", err, out)
	}
	got, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("the new content should go to the copy: %v", err)
	}
	if want := "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + block + "\n"; string(got) != want {
		t.Errorf("copy = %q, want %q", got, want)
	}
	if orig, _ := os.ReadFile(path); string(orig) != testHostsFile {
		t.Errorf("an unwritable file must stay unchanged, got %q", orig)
	}
}

// After a restart the file is unwritable again but the copy exists: the copy
// is the base, so the blocks written before the restart are kept.
func TestHostsRewriteScript_UnwritableFileKeepsCopyBlocks(t *testing.T) {
	path, copyPath := unwritableHosts(t, "127.0.0.1\tlocalhost\n")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	userBlock := renderUserHostsBlock([]config.HostEntry{{IP: "10.0.0.5", Hostnames: []string{"kept.test"}}})
	if err := os.WriteFile(copyPath, []byte("127.0.0.1\tlocalhost\n"+userBlock+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	allowBlock := renderHostsBlock(map[string][]string{"api.example.com": {"192.0.2.1"}})

	_, _ = runHostsRewriteScript(path, copyPath, hostsBeginMarker, hostsEndMarker, allowBlock)
	got, _ := os.ReadFile(copyPath)
	if want := "127.0.0.1\tlocalhost\n" + userBlock + "\n" + allowBlock + "\n"; string(got) != want {
		t.Errorf("copy = %q, want %q", got, want)
	}
}
