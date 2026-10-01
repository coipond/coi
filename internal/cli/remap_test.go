package cli

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeRemapManager is a minimal container.ContainerManager double for
// remapContainerUserIfNeeded. Embedding the nil interface satisfies every
// method we don't override (they panic if called, which fails the test
// loudly instead of silently doing the wrong thing); only ExecCommand and
// ExecArgsCapture — the two methods the remap path actually calls — are
// implemented.
type fakeRemapManager struct {
	container.ContainerManager

	// execCommandErrs is consumed in order, one per ExecCommand call
	// (remapCmd, then the best-effort chownCmd). A nil entry means success.
	execCommandErrs []error
	execCommandCall int

	// idProbeUIDs is consumed in order, one per ExecArgsCapture call. The
	// remap path probes twice: once via DetectCodeUser (before attempting
	// the remap) and once via ResolveCodeUID (only when the remap command
	// itself errors, to check whether the UID change actually landed).
	idProbeUIDs []string
	idProbeCall int
}

func (f *fakeRemapManager) ExecCommand(_ string, _ container.ExecCommandOptions) (string, error) {
	var err error
	if f.execCommandCall < len(f.execCommandErrs) {
		err = f.execCommandErrs[f.execCommandCall]
	}
	f.execCommandCall++
	return "", err
}

func (f *fakeRemapManager) ExecArgsCapture(_ []string, _ container.ExecCommandOptions) (string, error) {
	if f.idProbeCall >= len(f.idProbeUIDs) {
		return "", errors.New("fakeRemapManager: unexpected extra id -u probe")
	}
	out := f.idProbeUIDs[f.idProbeCall]
	f.idProbeCall++
	return out, nil
}

// withCodeUID temporarily overrides the package-level container.CodeUID for
// the duration of a test.
func withCodeUID(t *testing.T, uid int) {
	t.Helper()
	orig := container.CodeUID
	container.CodeUID = uid
	t.Cleanup(func() { container.CodeUID = orig })
}

func TestRemapContainerUserIfNeeded_TolerantOfReadOnlyMountChownFailure(t *testing.T) {
	// Reproduces the fitout bug: usermod -u changes the UID successfully but
	// exits non-zero because its internal home-directory ownership walk hits
	// a read-only mount already living under /home/code (e.g. the
	// auto-mounted ~/.claude/plugins). The remap must not be treated as
	// fatal when the UID actually landed.
	withCodeUID(t, 1001)

	mgr := &fakeRemapManager{
		execCommandErrs: []error{
			errors.New("chown: changing ownership of '/home/code/.claude/plugins/...': Read-only file system"),
			nil,
		},
		idProbeUIDs: []string{"1000", "1001"},
	}

	if err := remapContainerUserIfNeeded(mgr, false); err != nil {
		t.Fatalf("expected remap to succeed despite the read-only-mount chown failure, got: %v", err)
	}
}

func TestRemapContainerUserIfNeeded_FatalWhenUIDNeverChanged(t *testing.T) {
	// A genuine remap failure (UID never actually moved) must still abort —
	// only a confirmed-successful UID change may downgrade the error to a
	// warning.
	withCodeUID(t, 1001)

	mgr := &fakeRemapManager{
		execCommandErrs: []error{
			errors.New("usermod: user code is currently used by process 1"),
		},
		idProbeUIDs: []string{"1000", "1000"},
	}

	err := remapContainerUserIfNeeded(mgr, false)
	if err == nil {
		t.Fatal("expected an error when the UID never actually changed, got nil")
	}
}

func TestRemapContainerUserIfNeeded_SkipsWhenUIDMatchesImageDefault(t *testing.T) {
	withCodeUID(t, 1000)

	mgr := &fakeRemapManager{}
	if err := remapContainerUserIfNeeded(mgr, false); err != nil {
		t.Fatalf("expected no-op when CodeUID matches the image default, got: %v", err)
	}
	if mgr.execCommandCall != 0 || mgr.idProbeCall != 0 {
		t.Fatalf("expected no exec calls at all, got execCommandCall=%d idProbeCall=%d", mgr.execCommandCall, mgr.idProbeCall)
	}
}
