package container

import (
	"fmt"
	"strconv"
	"strings"
)

// HardeningPolicy selects how much kernel-facing surface a container gets.
// The zero value is maximally hardened; DefaultHardeningPolicy() preserves the
// historical behavior (Docker support on).
type HardeningPolicy struct {
	// Docker configures the container for Docker/nested containers:
	// security.nesting, mknod/setxattr syscall interception, and the
	// unprivileged low-port sysctl. Off, those four knobs are unset,
	// shrinking the shared-kernel attack surface.
	Docker bool
	// ReduceKernelSurface additionally denies the syscall families behind
	// most recent kernel escape chains via security.syscalls.deny. It wins
	// over Docker: nesting is part of the surface being reduced, and dockerd
	// itself needs bpf.
	ReduceKernelSurface bool
	// ReduceKernelSurfaceStrict is the opt-in strict tier: everything
	// ReduceKernelSurface does, plus perf_event_open on the deny list.
	// perf_event_open has a long kernel-LPE history and nothing in a normal
	// coding workflow needs it, but denying it removes kernel-level profiling
	// (perf, JVM async-profiler's perf mode) — a real capability loss, unlike
	// the base list's transparently-substituted syscalls — so it is a separate
	// opt-in rather than part of the default hardened list. Implies (and does
	// not require separately setting) ReduceKernelSurface.
	ReduceKernelSurfaceStrict bool
}

// reducesKernelSurface reports whether either hardening tier is active. The
// strict tier implies the base tier, so callers never have to set both.
func (p HardeningPolicy) reducesKernelSurface() bool {
	return p.ReduceKernelSurface || p.ReduceKernelSurfaceStrict
}

// DefaultHardeningPolicy returns the pre-flag behavior: Docker support on,
// no syscall denies.
func DefaultHardeningPolicy() HardeningPolicy { return HardeningPolicy{Docker: true} }

// DockerEnabled resolves the docker/hardening conflict: either kernel-surface
// tier wins over Docker (nesting is part of the surface being reduced).
func (p HardeningPolicy) DockerEnabled() bool { return p.Docker && !p.reducesKernelSurface() }

// KernelSurfaceDenySyscalls is the space-separated list of syscall NAMES denied
// by ReduceKernelSurface: io_uring, bpf, userfaultfd, and the kernel keyring —
// the syscall families behind most recent container-escape/LPE chains, none
// required by a typical agent workflow. Denied syscalls fail with EPERM (see
// kernelSurfaceDenyAction); libuv (Node >= 20.3) probes io_uring at startup and
// silently falls back to its thread pool, so Node/npm keep working. Incus >= 6.1
// (Coi's hard floor) always supports the key. This is the canonical NAME list;
// the actual config value is built by kernelSurfaceDenyValue.
const KernelSurfaceDenySyscalls = "io_uring_setup io_uring_enter io_uring_register bpf userfaultfd keyctl add_key request_key"

// KernelSurfaceStrictExtraSyscalls are the additional denies of the opt-in
// strict tier (ReduceKernelSurfaceStrict) on top of KernelSurfaceDenySyscalls.
// perf_event_open is a long-standing kernel-LPE vector unused by normal coding
// workflows; unlike the base list it removes real capability (kernel profiling
// via perf / async-profiler degrades gracefully — EPERM, no crash — but stops
// working), which is why it lives behind a separate opt-in.
const KernelSurfaceStrictExtraSyscalls = "perf_event_open"

// kernelSurfaceDenyAction is the per-syscall action appended to every entry in
// security.syscalls.deny. It MUST be present: a bare syscall name inherits
// LXC's default denylist action, which on current Incus is SIGSYS-KILL — so a
// process that makes the call (e.g. systemd's own boot helpers calling
// add_key/bpf, or libuv probing io_uring) is killed and the container falls
// over instead of the syscall simply returning an error. "errno 1" makes it
// return EPERM — the graceful failure this deny list was always documented to
// produce.
const kernelSurfaceDenyAction = "errno 1"

// kernelSurfaceDenySyscallNames returns the ordered syscall NAMES the policy
// denies — the base list, plus perf_event_open under the strict tier — or nil
// when no tier is active.
func kernelSurfaceDenySyscallNames(p HardeningPolicy) []string {
	if !p.reducesKernelSurface() {
		return nil
	}
	names := strings.Fields(KernelSurfaceDenySyscalls)
	if p.ReduceKernelSurfaceStrict {
		names = append(names, strings.Fields(KernelSurfaceStrictExtraSyscalls)...)
	}
	return names
}

// kernelSurfaceDenyValue is the exact security.syscalls.deny value Coi writes:
// each syscall on its OWN line with an explicit "errno 1" action. Two hard-won
// format requirements are encoded here:
//   - Incus wants a \n-separated list; a space-separated value is parsed as one
//     malformed "<syscall> <action>" rule and the container fails to boot.
//   - Every entry carries kernelSurfaceDenyAction so denies return EPERM rather
//     than SIGSYS-killing the caller.
//
// Empty when no tier is active.
func kernelSurfaceDenyValue(p HardeningPolicy) string {
	names := kernelSurfaceDenySyscallNames(p)
	if len(names) == 0 {
		return ""
	}
	lines := make([]string, len(names))
	for i, n := range names {
		lines[i] = n + " " + kernelSurfaceDenyAction
	}
	return strings.Join(lines, "\n")
}

// kernelSurfaceDenySyscallSet extracts the set of syscall NAMES from a stored
// security.syscalls.deny value, ignoring per-entry actions ("add_key errno 1")
// and blank lines. Entries are newline-separated (Coi's own format); the name
// is the first field of each entry. Comparing by name set keeps convergence
// stable regardless of how Incus echoes actions/whitespace back.
func kernelSurfaceDenySyscallSet(value string) map[string]bool {
	set := make(map[string]bool)
	for _, entry := range strings.Split(value, "\n") {
		if f := strings.Fields(entry); len(f) > 0 {
			set[f[0]] = true
		}
	}
	return set
}

// kernelSurfaceKeys are the instance config keys ApplyKernelSurfacePolicy owns.
// Every launch/reconcile writes ALL of them (a wanted key to its value, an
// unwanted key to "") so re-applying a changed policy to an existing stopped
// container converges instead of leaking the previous policy's settings. An
// empty value removes the key (Incus treats `config set key=` as unset), so
// the whole policy applies in ONE `incus config set` — atomic and fail-closed.
var kernelSurfaceKeys = []string{
	"security.nesting",
	"security.syscalls.intercept.mknod",
	"security.syscalls.intercept.setxattr",
	"linux.sysctl.net.ipv4.ip_unprivileged_port_start",
	"security.syscalls.deny",
}

// hardeningConfigArgs returns the `key=value` pairs realizing the policy: the
// four Docker-support keys set to their values (or "" to unset) per
// DockerEnabled, and security.syscalls.deny set to the deny list (or "") per
// ReduceKernelSurface. Every key in kernelSurfaceKeys appears exactly once so
// the result fully specifies the policy.
func hardeningConfigArgs(p HardeningPolicy) []string {
	docker := "" // "" unsets the key
	if p.DockerEnabled() {
		docker = "true"
	}
	lowPort := ""
	if p.DockerEnabled() {
		lowPort = "0"
	}
	deny := kernelSurfaceDenyValue(p)
	return []string{
		"security.nesting=" + docker,
		"security.syscalls.intercept.mknod=" + docker,
		"security.syscalls.intercept.setxattr=" + docker,
		"linux.sysctl.net.ipv4.ip_unprivileged_port_start=" + lowPort,
		"security.syscalls.deny=" + deny,
	}
}

// ApplyKernelSurfacePolicy applies (or re-applies) the hardening policy to a
// container in a single `incus config set`. Like the Docker flags it replaces,
// this must run before the container's first boot so the kernel loads the
// correct seccomp profile — setting security.nesting or security.syscalls.deny
// on a running container is rejected or racy. It is idempotent: call it again
// on a STOPPED persistent container to converge it to a changed policy. Unlike
// the previous per-key implementation it is FAIL-CLOSED — a failed write
// returns an error (the caller must decide, e.g. abort the launch) rather than
// silently leaving a hardened config partly applied.
func ApplyKernelSurfacePolicy(containerName string, p HardeningPolicy) error {
	args := append([]string{"config", "set", containerName}, hardeningConfigArgs(p)...)
	return IncusExec(args...)
}

// ReadKernelSurfaceConfig returns the INSTANCE-LOCAL values of the keys
// ApplyKernelSurfacePolicy owns — the layer Coi actually writes, so the
// convergence check compares like with like and reaches a stable state in one
// write even when an attached Incus profile also supplies these keys (profile
// values are invisible here on purpose; whether they DEFEAT the policy is the
// separate, expanded-config question VerifyKernelSurfacePolicy answers). A key
// absent from the config maps to "" in the result.
func ReadKernelSurfaceConfig(containerName string) (map[string]string, error) {
	return readKernelSurfaceConfig(containerName, false)
}

func readKernelSurfaceConfig(containerName string, expanded bool) (map[string]string, error) {
	result := make(map[string]string, len(kernelSurfaceKeys))
	for _, key := range kernelSurfaceKeys {
		args := []string{"config", "get"}
		if expanded {
			args = append(args, "--expanded")
		}
		args = append(args, containerName, key)
		v, err := IncusOutput(args...)
		if err != nil {
			return nil, fmt.Errorf("read %s from %s: %w", key, containerName, err)
		}
		result[key] = v
	}
	return result, nil
}

// ReconcileKernelSurfacePolicy converges an existing STOPPED container to the
// policy, but only when its instance-local config does not already match — so
// a reuse that changes nothing performs no writes and, crucially, cannot
// clobber a deny list or nesting value the container already carries. Returns
// whether a change was made. Fail-closed twice over: a read or write failure
// is returned so the caller can abort rather than start a container whose
// kernel-surface config is unknown or half-applied, and after converging it
// verifies the EFFECTIVE (profile-inherited) surface actually honors the
// policy — an instance-local unset cannot override a profile-supplied
// security.nesting=true, and booting anyway would silently defeat the
// hardening the user asked for.
func ReconcileKernelSurfacePolicy(containerName string, p HardeningPolicy) (changed bool, err error) {
	current, err := ReadKernelSurfaceConfig(containerName)
	if err != nil {
		return false, err
	}
	if !KernelSurfaceMatches(current, p) {
		if err := ApplyKernelSurfacePolicy(containerName, p); err != nil {
			return false, err
		}
		changed = true
	}
	return changed, VerifyKernelSurfacePolicy(containerName, p)
}

// VerifyKernelSurfacePolicy checks the EXPANDED (profile-inherited) config
// against the policy and errors when the effective kernel surface is WIDER
// than the policy allows — the one case instance-local writes cannot fix,
// because a profile-supplied value survives an instance-local unset. Free for
// the default policy (docker on wants every surface key set, and instance-local
// values always override profiles, so there is nothing a profile could widen —
// no reads are performed). Values the profile only NARROWS (e.g. an extra
// syscall deny under the default policy) are tolerated: they are the user's
// own tightening, not a policy violation.
func VerifyKernelSurfacePolicy(containerName string, p HardeningPolicy) error {
	if p.DockerEnabled() {
		return nil
	}
	expanded, err := readKernelSurfaceConfig(containerName, true)
	if err != nil {
		return err
	}
	if v := kernelSurfaceViolations(expanded, p); len(v) > 0 {
		return fmt.Errorf(
			"kernel-surface policy cannot be enforced: %s remain(s) in effect via an attached Incus profile, and an instance-local unset cannot override profile config; remove the key(s) from the container's Incus profile(s), or relax [container] docker / [security] reduce_kernel_surface",
			strings.Join(v, ", "))
	}
	return nil
}

// kernelSurfaceViolations is the pure core of VerifyKernelSurfacePolicy: given
// EXPANDED config, it lists the keys whose effective values widen the surface
// beyond the policy. Boolean keys use Incus's truthy spellings (true/1/yes/on);
// the low-port sysctl only widens below the kernel default of 1024 (an
// unparseable value fails closed as a violation).
func kernelSurfaceViolations(expanded map[string]string, p HardeningPolicy) []string {
	if p.DockerEnabled() {
		return nil
	}
	var violations []string
	for _, key := range []string{
		"security.nesting",
		"security.syscalls.intercept.mknod",
		"security.syscalls.intercept.setxattr",
	} {
		if incusTruthy(expanded[key]) {
			violations = append(violations, key+"="+strings.TrimSpace(expanded[key]))
		}
	}
	if s := strings.TrimSpace(expanded["linux.sysctl.net.ipv4.ip_unprivileged_port_start"]); s != "" {
		if n, err := strconv.Atoi(s); err != nil || n < 1024 {
			violations = append(violations, "linux.sysctl.net.ipv4.ip_unprivileged_port_start="+s)
		}
	}
	if p.reducesKernelSurface() {
		// Instance-local deny (which we write) overrides any profile deny, so
		// this cannot realistically fire — kept as a cheap invariant so a
		// future write-path regression surfaces here instead of shipping a
		// hardened container without its deny list. Compared by NAME so an
		// "errno 1" action on each entry doesn't read as a missing syscall.
		have := kernelSurfaceDenySyscallSet(expanded["security.syscalls.deny"])
		var missing []string
		for _, name := range kernelSurfaceDenySyscallNames(p) {
			if !have[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			violations = append(violations, "security.syscalls.deny missing "+strings.Join(missing, " "))
		}
	}
	return violations
}

// incusTruthy reports whether an Incus boolean config value is effectively
// true, accepting the spellings Incus itself accepts (true/1/yes/on,
// case-insensitive).
func incusTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// KernelSurfaceMatches reports whether current (as returned by
// ReadKernelSurfaceConfig, instance-local) already realizes the policy, so a
// reconcile can skip the write — avoiding both wasted `config set` calls and
// clobbering a container whose config already matches. A missing key reads
// as "".
func KernelSurfaceMatches(current map[string]string, p HardeningPolicy) bool {
	for _, kv := range hardeningConfigArgs(p) {
		key, want, _ := strings.Cut(kv, "=")
		if key == "security.syscalls.deny" {
			// Compare by syscall-name set, not exact string: the value carries
			// per-entry "errno 1" actions and \n separators, and Incus may echo
			// them back with different surrounding whitespace. A set compare
			// converges reliably without a spurious rewrite each launch.
			if !kernelSurfaceDenyMatches(current[key], p) {
				return false
			}
			continue
		}
		if strings.TrimSpace(current[key]) != want {
			return false
		}
	}
	return true
}

// kernelSurfaceDenyMatches reports whether a stored security.syscalls.deny value
// denies exactly the syscalls the policy requires (by name, order/action/
// separator-insensitive).
func kernelSurfaceDenyMatches(current string, p HardeningPolicy) bool {
	want := kernelSurfaceDenySyscallNames(p)
	have := kernelSurfaceDenySyscallSet(current)
	if len(have) != len(want) {
		return false
	}
	for _, n := range want {
		if !have[n] {
			return false
		}
	}
	return true
}
