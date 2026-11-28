package image

import (
	"os"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestGetImageFingerprint_UsesConfiguredProject is the regression guard for
// #777: getImageFingerprint used to look up the freshly-published image with a
// hardcoded "--project", "default", so on any non-default `[incus] project` the
// lookup ran against the wrong project and `coi build` failed with "image not
// found" immediately after a SUCCESSFUL publish. The lookup must follow the
// configured project (container.IncusProject) and never pin "default".
func TestGetImageFingerprint_UsesConfiguredProject(t *testing.T) {
	// container.IncusProject is package-global; restore it so we don't leak state
	// into other tests that read the default project.
	origProject, origUser, origUID := container.IncusProject, container.CodeUser, container.CodeUID
	t.Cleanup(func() { container.Configure(origProject, origUser, origUID) })

	const sentinel = "coi-nondefault-project"
	container.Configure(sentinel, origUser, origUID)
	logPath := fakeIncus(t, "coi-default")

	fingerprint, err := getImageFingerprint("coi-default")
	if err != nil || fingerprint != "f00d" {
		t.Fatalf("getImageFingerprint = %q, %v; want f00d", fingerprint, err)
	}
	data, _ := os.ReadFile(logPath)
	calls := string(data)
	if !strings.Contains(calls, "--project "+sentinel+" image list") {
		t.Errorf("fingerprint lookup must target the configured project %q (#777 regression); calls:\n%s", sentinel, calls)
	}
	if strings.Contains(calls, "--project default") {
		t.Errorf("fingerprint lookup is pinned to hardcoded \"default\" — reintroduces #777; calls:\n%s", calls)
	}
}

func TestGetImageFingerprint_NotFound(t *testing.T) {
	fakeIncus(t, "other")
	if _, err := getImageFingerprint("coi-missing"); err == nil || !strings.Contains(err.Error(), "image not found: coi-missing") {
		t.Errorf("getImageFingerprint of a missing alias: err = %v, want image not found", err)
	}
}
