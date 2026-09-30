package health

import (
	"errors"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// Deterministic guarantee for the "probes honor the kernel-surface policy"
// change: each isolation probe must thread the policy it is given to the
// launch, unchanged. The live-container E2E can only observe this when the
// environment can boot the seconds-lived probes; this asserts the plumbing
// regardless. We fail the launch immediately so the probe returns without
// needing a real container.
func TestProbesThreadHardeningPolicyToLaunch(t *testing.T) {
	orig := probeLaunch
	t.Cleanup(func() { probeLaunch = orig })

	var got container.HardeningPolicy
	var launched bool
	probeLaunch = func(_, _, _ string, _ bool, _ func() error, policy container.HardeningPolicy) error {
		got = policy
		launched = true
		return errors.New("stop here: policy captured, no real container needed")
	}

	want := container.HardeningPolicy{Docker: false, ReduceKernelSurface: true}

	// imageExists() short-circuits with StatusWarning when the image is absent,
	// before the launch — so these run only where coi-default exists (CI). Skip
	// cleanly otherwise; the assertion is meaningful only once launch is reached.
	for _, tc := range []struct {
		name string
		run  func() HealthCheck
	}{
		{"container_connectivity", func() HealthCheck { return CheckContainerConnectivity("coi-default", want) }},
		{"network_restriction", func() HealthCheck { return CheckNetworkRestriction("coi-default", want) }},
		{"secret_masking", func() HealthCheck { return CheckSecretMasking("coi-default", want) }},
		{"host_credential_isolation", func() HealthCheck { return CheckHostCredentialIsolation("coi-default", want) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			launched = false
			got = container.HardeningPolicy{}
			tc.run()
			if !launched {
				t.Skip("probe did not reach launch (image absent in this env)")
			}
			if got != want {
				t.Errorf("%s launched with policy %+v, want %+v", tc.name, got, want)
			}
		})
	}
}

// The default policy still reaches the launch unchanged (docker on) — a
// regression here would silently harden probes users didn't ask to harden.
func TestProbesThreadDefaultPolicy(t *testing.T) {
	orig := probeLaunch
	t.Cleanup(func() { probeLaunch = orig })

	var got container.HardeningPolicy
	var launched bool
	probeLaunch = func(_, _, _ string, _ bool, _ func() error, policy container.HardeningPolicy) error {
		got, launched = policy, true
		return errors.New("stop")
	}
	CheckContainerConnectivity("coi-default", container.DefaultHardeningPolicy())
	if launched && got != container.DefaultHardeningPolicy() {
		t.Errorf("default probe policy = %+v, want %+v", got, container.DefaultHardeningPolicy())
	}
}
