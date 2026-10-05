package image

import (
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestImageFingerprintListArgs_UsesConfiguredProject is the regression guard for
// #777: getImageFingerprint used to look up the freshly-published image with a
// hardcoded "--project", "default", so on any non-default `[incus] project` the
// lookup ran against the wrong project and `coi build` failed with "image not
// found" immediately after a SUCCESSFUL publish. The fix routes the lookup
// through container.IncusProject; this test asserts the argv follows the
// configured project and never pins "default". It runs in the incus-less unit
// job, so the regression is caught without a running Incus.
func TestImageFingerprintListArgs_UsesConfiguredProject(t *testing.T) {
	// container.IncusProject is package-global; restore it so we don't leak state
	// into other tests that read the default project.
	origProject, origUser, origUID := container.IncusProject, container.CodeUser, container.CodeUID
	t.Cleanup(func() { container.Configure(origProject, origUser, origUID) })

	const sentinel = "coi-nondefault-project"
	container.Configure(sentinel, origUser, origUID)

	args := imageFingerprintListArgs("coi-default")

	project := ""
	for i, a := range args {
		if a == "--project" && i+1 < len(args) {
			project = args[i+1]
		}
	}
	if project == "" {
		t.Fatalf("fingerprint lookup argv has no --project flag: %v", args)
	}
	if project != sentinel {
		t.Errorf("fingerprint lookup must target the configured project %q, got %q (#777 regression: %v)",
			sentinel, project, args)
	}
	if project == "default" {
		t.Errorf("fingerprint lookup is pinned to hardcoded \"default\" — reintroduces #777: %v", args)
	}
}
