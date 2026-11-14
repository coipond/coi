package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const testHostsFile = "127.0.0.1\tlocalhost\n" +
	userHostsBeginMarker + "\n10.0.0.1\told\n" + userHostsEndMarker + "\n" +
	"::1\tlocalhost\n"

// runHostsRewriteScript runs the rewrite script on a local file with bash.
func runHostsRewriteScript(path, block string) ([]byte, error) {
	script := hostsRewriteScript(path, userHostsBeginMarker, userHostsEndMarker, block)
	return exec.Command("bash", "-c", script).CombinedOutput()
}

func TestHostsRewriteScript_WritesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte(testHostsFile), 0o644); err != nil {
		t.Fatal(err)
	}
	block := renderUserHostsBlock(nil)

	if out, err := runHostsRewriteScript(path, block); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(path)
	if want := "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + block + "\n"; string(got) != want {
		t.Errorf("hosts file = %q, want %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, ".coi-hosts")); err == nil {
		t.Error("a writable file needs no .coi-hosts copy")
	}
}

// A file container root cannot write (#977) is left alone: the new content
// goes to .coi-hosts, which the script then bind-mounts over it. The mount
// itself needs root and is covered by the integration test.
func TestHostsRewriteScript_UnwritableFileWritesCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte(testHostsFile), 0o444); err != nil {
		t.Fatal(err)
	}
	block := renderUserHostsBlock(nil)

	_, _ = runHostsRewriteScript(path, block) // mount fails without root
	got, err := os.ReadFile(filepath.Join(dir, ".coi-hosts"))
	if err != nil {
		t.Fatalf("the new content should go to .coi-hosts: %v", err)
	}
	if want := "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + block + "\n"; string(got) != want {
		t.Errorf(".coi-hosts = %q, want %q", got, want)
	}
	if orig, _ := os.ReadFile(path); string(orig) != testHostsFile {
		t.Errorf("an unwritable file must stay unchanged, got %q", orig)
	}
}
