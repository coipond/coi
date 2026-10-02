package image

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIncus puts an `incus` stub first on PATH that appends each invocation's
// arguments to a log and answers the image-list lookup with an image carrying
// `alias`, so createImage can run without a real Incus. Returns the log path.
func fakeIncus(t *testing.T, alias string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
echo "$*" >> "` + logPath + `"
case "$*" in
  *"image list"*) echo '[{"fingerprint":"f00d","aliases":[{"name":"` + alias + `"}]}]' ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func publishCall(t *testing.T, logPath string) string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no incus calls recorded: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "publish "+BuildContainer) {
			return line
		}
	}
	t.Fatalf("no `incus publish` call recorded:\n%s", data)
	return ""
}

// [container.build] compression reaches `incus publish` (default and custom
// images share createImage). Replaces a full-network integration build that
// was flaky whenever the apt mirror was slow or erroring.
func TestCreateImage_PassesCompression(t *testing.T) {
	logPath := fakeIncus(t, "v1")
	b := NewBuilder(BuildOptions{Compression: "none", Description: "test", Logger: func(string) {}})
	fp, err := b.createImage("v1")
	if err != nil {
		t.Fatalf("createImage: %v", err)
	}
	if fp != "f00d" {
		t.Errorf("fingerprint = %q", fp)
	}
	if call := publishCall(t, logPath); !strings.Contains(call, "--compression none") {
		t.Errorf("publish call lacks --compression none: %q", call)
	}
}

// Without a compression setting, incus's own default applies (no flag).
func TestCreateImage_OmitsCompressionWhenUnset(t *testing.T) {
	logPath := fakeIncus(t, "v1")
	b := NewBuilder(BuildOptions{Description: "test", Logger: func(string) {}})
	if _, err := b.createImage("v1"); err != nil {
		t.Fatalf("createImage: %v", err)
	}
	if call := publishCall(t, logPath); strings.Contains(call, "--compression") {
		t.Errorf("publish call should not set --compression: %q", call)
	}
}
