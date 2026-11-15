package health

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// A host UID above the isolated container's ID range (directory-service
// accounts) can't be idmapped into the probe workspace: the secret masking
// probe must skip with a named WARNING and must NOT launch a container.
func TestSecretMasking_SkipWhenHostUIDTooLarge(t *testing.T) {
	origRange, origUID, origLaunch := hostUIDInSubidRange, hostUID, probeLaunch
	t.Cleanup(func() { hostUIDInSubidRange, hostUID, probeLaunch = origRange, origUID, origLaunch })

	hostUIDInSubidRange = func() (string, bool) { return "", false }
	hostUID = func() int { return 916200003 }
	probeLaunch = func(imageAlias, containerName, pool string, ephemeral bool, preStart func() error, policy container.HardeningPolicy) error {
		t.Fatalf("probe must not launch a container when the host UID is too large to map")
		return nil
	}

	hc := CheckSecretMasking("coi-default", container.HardeningPolicy{})
	if hc.Status != StatusWarning {
		t.Errorf("status = %v, want WARNING", hc.Status)
	}
	if !strings.Contains(hc.Message, "host UID 916200003") {
		t.Errorf("message should name the host UID, got: %q", hc.Message)
	}
	if !strings.Contains(hc.Message, "not a masking failure") {
		t.Errorf("message should clarify it's not a masking failure, got: %q", hc.Message)
	}
}

// Boundary: the last ID inside the isolated range is mappable, the first one
// outside is not.
func TestLargeUIDSkip_Boundary(t *testing.T) {
	orig := hostUID
	t.Cleanup(func() { hostUID = orig })

	for _, tc := range []struct {
		uid      int
		wantSkip bool
	}{
		{0, false},
		{1000, false},
		{isolatedIdmapSize - 1, false},
		{isolatedIdmapSize, true},
		{916200003, true},
	} {
		hostUID = func() int { return tc.uid }
		if _, ok := largeUIDSkip("secret_masking"); ok != tc.wantSkip {
			t.Errorf("uid %d: skip = %v, want %v", tc.uid, ok, tc.wantSkip)
		}
	}
}
