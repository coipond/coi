package container

import (
	"path/filepath"
	"strings"
	"testing"
)

// A relative container path must address the named instance, as in PullFile:
// "c1" + "workspace/x" must not become instance "c1workspace".
func TestPullDirectory_RelativePathKeepsInstance(t *testing.T) {
	log := fakeIncusScript(t, `for a; do d=$a; done; mkdir -p "$d/x"`)
	dest := filepath.Join(t.TempDir(), "out")

	if err := NewManager("c1").PullDirectory("workspace/x", dest); err != nil {
		t.Fatalf("PullDirectory() error = %v", err)
	}
	got := strings.Join(calls(t, log), "\n")
	if !strings.Contains(got, " c1/workspace/x ") {
		t.Fatalf("incus calls = %q, want source c1/workspace/x", got)
	}
}
