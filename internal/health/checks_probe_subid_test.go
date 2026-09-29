package health

import (
	"strings"
	"testing"

	"github.com/mensfeld/code-on-incus/internal/container"
)

// When the host UID can't be idmapped (#838), the mount/idmap probes must skip
// with a named WARNING and must NOT launch a container.
func TestProbes_SkipWhenHostUIDUnmappable(t *testing.T) {
	origRange := hostUIDInSubidRange
	origLaunch := probeLaunch
	t.Cleanup(func() { hostUIDInSubidRange = origRange; probeLaunch = origLaunch })

	hostUIDInSubidRange = func() (string, bool) { return "root:1000000:1000000000", true }
	probeLaunch = func(imageAlias, containerName, pool string, ephemeral bool, preStart func() error, policy container.HardeningPolicy) error {
		t.Fatalf("probe must not launch a container when the host UID is unmappable")
		return nil
	}

	for _, tc := range []struct {
		name  string
		check func() HealthCheck
	}{
		{"secret_masking", func() HealthCheck { return CheckSecretMasking("coi-default", container.HardeningPolicy{}) }},
		{"host_credential_isolation", func() HealthCheck { return CheckHostCredentialIsolation("coi-default", container.HardeningPolicy{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hc := tc.check()
			if hc.Status != StatusWarning {
				t.Errorf("status = %v, want WARNING", hc.Status)
			}
			if !strings.Contains(hc.Message, "/etc/subuid range root:1000000:1000000000") {
				t.Errorf("message should name the subuid range, got: %q", hc.Message)
			}
			if !strings.Contains(hc.Message, "not a masking failure") {
				t.Errorf("message should clarify it's not a masking failure, got: %q", hc.Message)
			}
		})
	}
}

// When the host UID is mappable, subidSkip must not fire (the probe proceeds).
func TestSubidSkip_NoOpWhenMappable(t *testing.T) {
	orig := hostUIDInSubidRange
	t.Cleanup(func() { hostUIDInSubidRange = orig })
	hostUIDInSubidRange = func() (string, bool) { return "", false }

	if _, ok := subidSkip("secret_masking"); ok {
		t.Error("subidSkip should not fire when the UID is mappable")
	}
}
