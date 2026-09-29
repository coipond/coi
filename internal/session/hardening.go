package session

import (
	"github.com/mensfeld/coi/internal/container"
)

// hardeningPolicyFrom builds the container-level kernel-surface policy from
// SetupOptions. It passes the raw flags through; the docker-vs-hardening
// precedence ("reduce_kernel_surface wins") is resolved in exactly one place,
// container.HardeningPolicy.DockerEnabled, so callers never re-encode the rule.
func hardeningPolicyFrom(opts *SetupOptions) container.HardeningPolicy {
	return container.HardeningPolicy{
		Docker:                    opts.Security.Docker,
		ReduceKernelSurface:       opts.Security.ReduceKernelSurface,
		ReduceKernelSurfaceStrict: opts.Security.ReduceKernelSurfaceStrict,
	}
}

// warnHardeningMismatch compares the desired kernel-surface policy against a
// RUNNING container and logs how to apply a change. Running containers can't
// be reconciled (security.nesting changes are rejected, seccomp changes are
// racy) — that happens on the next stopped->start cycle in
// restartStoppedContainer. Two distinct checks with two distinct remedies:
// instance-LOCAL drift means a restart will converge it (the reconcile fixes
// local config), while an EFFECTIVE-surface violation means an attached Incus
// profile pins a key the policy needs unset — a restart alone won't fix that,
// so the warning names the profile as the thing to edit.
func warnHardeningMismatch(containerName string, p container.HardeningPolicy, log func(string)) {
	current, err := container.ReadKernelSurfaceConfig(containerName)
	if err != nil {
		return // best-effort: a probe failure is not worth a warning of its own
	}
	if !container.KernelSurfaceMatches(current, p) {
		log("Warning: this running container was created with different docker/kernel-hardening settings than the current config; restart it (coi shutdown, then relaunch) to apply them")
		return // after a restart the reconcile runs Verify and surfaces any profile conflict
	}
	if err := container.VerifyKernelSurfacePolicy(containerName, p); err != nil {
		log("Warning: " + err.Error())
	}
}
