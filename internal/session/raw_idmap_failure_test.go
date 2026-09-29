package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSubuid points the package's /etc/subuid reader at a fixture for the test.
func withSubuid(t *testing.T, content string) {
	t.Helper()
	orig := subuidPath
	p := filepath.Join(t.TempDir(), "subuid")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	subuidPath = p
	t.Cleanup(func() { subuidPath = orig })
}

func TestRawIdmapFailure_NamesSubuidCause(t *testing.T) {
	uid := os.Getuid()
	// A multi-ID range covering the current UID → the subid cause must be named.
	withSubuid(t, "root:0:2000000000\n")

	err := rawIdmapFailure(errors.New("exit status 1"), uid)
	msg := err.Error()

	for _, want := range []string{"/etc/subuid", "root:0:2000000000", "coi health", "uid-1000"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	// The misleading disable_shift hint must be gone (it doesn't help this case).
	if strings.Contains(msg, "disable_shift") {
		t.Errorf("message should not suggest disable_shift:\n%s", msg)
	}
}

func TestRawIdmapFailure_PlainWhenNotSubordinate(t *testing.T) {
	// No range covers the current UID → the generic message, no subuid guidance.
	withSubuid(t, "root:1000000:65536\n")

	msg := rawIdmapFailure(errors.New("boom"), 424242).Error()
	if strings.Contains(msg, "/etc/subuid") {
		t.Errorf("should not name /etc/subuid when the UID is not subordinate:\n%s", msg)
	}
	if !strings.Contains(msg, "unwritable") {
		t.Errorf("expected the generic unwritable-workspace message:\n%s", msg)
	}
}
