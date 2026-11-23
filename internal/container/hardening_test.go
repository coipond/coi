package container

import (
	"strings"
	"testing"
)

// argsMap parses hardeningConfigArgs("key=value"...) into a map, asserting each
// key appears exactly once (a duplicate would make the applied value
// order-dependent).
func argsMap(t *testing.T, p HardeningPolicy) map[string]string {
	t.Helper()
	m := make(map[string]string)
	for _, kv := range hardeningConfigArgs(p) {
		key, val, _ := strings.Cut(kv, "=")
		if _, dup := m[key]; dup {
			t.Fatalf("key %q appears twice in args", key)
		}
		m[key] = val
	}
	return m
}

// Every kernel-surface key must be specified by every policy (set to a value,
// or "" to unset) so re-applying a changed policy converges — the same
// create/reconcile coupling idea as security devices (#610).
func TestHardeningConfigArgs_EveryKeyAlwaysSpecified(t *testing.T) {
	for _, p := range []HardeningPolicy{
		{Docker: true},
		{Docker: false},
		{Docker: false, ReduceKernelSurface: true},
		{Docker: true, ReduceKernelSurface: true},
	} {
		m := argsMap(t, p)
		for _, k := range kernelSurfaceKeys {
			if _, ok := m[k]; !ok {
				t.Errorf("policy %+v: key %q not specified", p, k)
			}
		}
		if len(m) != len(kernelSurfaceKeys) {
			t.Errorf("policy %+v: unexpected extra keys (%d != %d)", p, len(m), len(kernelSurfaceKeys))
		}
	}
}

func TestHardeningConfigArgs_DefaultPolicy(t *testing.T) {
	m := argsMap(t, DefaultHardeningPolicy())
	for k, want := range map[string]string{
		"security.nesting":                                 "true",
		"security.syscalls.intercept.mknod":                "true",
		"security.syscalls.intercept.setxattr":             "true",
		"linux.sysctl.net.ipv4.ip_unprivileged_port_start": "0",
	} {
		if m[k] != want {
			t.Errorf("default policy: %s = %q, want %q", k, m[k], want)
		}
	}
	if m["security.syscalls.deny"] != "" {
		t.Errorf("default policy must leave security.syscalls.deny empty, got %q", m["security.syscalls.deny"])
	}
}

func TestHardeningConfigArgs_DockerOff(t *testing.T) {
	m := argsMap(t, HardeningPolicy{Docker: false})
	for _, k := range kernelSurfaceKeys {
		if m[k] != "" {
			t.Errorf("docker-off policy must leave %s empty (unset), got %q", k, m[k])
		}
	}
}

func TestHardeningConfigArgs_ReduceKernelSurface(t *testing.T) {
	// ReduceKernelSurface wins even when Docker is (mis)set alongside it.
	m := argsMap(t, HardeningPolicy{Docker: true, ReduceKernelSurface: true})
	if m["security.nesting"] != "" {
		t.Error("reduce_kernel_surface must leave security.nesting empty even with Docker=true")
	}
	want := kernelSurfaceDenyValue(HardeningPolicy{Docker: true, ReduceKernelSurface: true})
	if m["security.syscalls.deny"] != want {
		t.Errorf("reduce_kernel_surface must set the deny list, got %q want %q", m["security.syscalls.deny"], want)
	}
	// Every entry must carry an explicit errno action (never a bare name, which
	// SIGSYS-kills), and entries must be newline-separated (space-separated is a
	// malformed LXC rule).
	for _, entry := range strings.Split(m["security.syscalls.deny"], "\n") {
		if !strings.HasSuffix(entry, " "+kernelSurfaceDenyAction) {
			t.Errorf("deny entry %q lacks the %q action", entry, kernelSurfaceDenyAction)
		}
	}
}

func TestHardeningPolicy_DockerEnabled(t *testing.T) {
	cases := []struct {
		p    HardeningPolicy
		want bool
	}{
		{HardeningPolicy{Docker: true}, true},
		{HardeningPolicy{Docker: false}, false},
		{HardeningPolicy{Docker: true, ReduceKernelSurface: true}, false},
		{HardeningPolicy{Docker: false, ReduceKernelSurface: true}, false},
	}
	for _, c := range cases {
		if got := c.p.DockerEnabled(); got != c.want {
			t.Errorf("%+v.DockerEnabled() = %v, want %v", c.p, got, c.want)
		}
	}
}

// KernelSurfaceMatches must accept exactly the config ApplyKernelSurfacePolicy
// would write, and reject any drift.
func TestKernelSurfaceMatches(t *testing.T) {
	p := HardeningPolicy{Docker: false, ReduceKernelSurface: true}
	match := map[string]string{
		"security.nesting":                                 "",
		"security.syscalls.intercept.mknod":                "",
		"security.syscalls.intercept.setxattr":             "",
		"linux.sysctl.net.ipv4.ip_unprivileged_port_start": "",
		"security.syscalls.deny":                           kernelSurfaceDenyValue(p),
	}
	if !KernelSurfaceMatches(match, p) {
		t.Error("expected match for the exact hardened config")
	}
	// Whitespace around the value must not defeat the match.
	match["security.syscalls.deny"] = " " + kernelSurfaceDenyValue(p) + " "
	if !KernelSurfaceMatches(match, p) {
		t.Error("expected match despite surrounding whitespace")
	}
	// The same syscalls in a different order (and without actions) still match —
	// comparison is by name set.
	match["security.syscalls.deny"] = "add_key\nrequest_key\nkeyctl\nuserfaultfd\nbpf\nio_uring_register\nio_uring_enter\nio_uring_setup"
	if !KernelSurfaceMatches(match, p) {
		t.Error("expected match for the same syscall set in a different order")
	}
	// A deny list missing one syscall is drift.
	match["security.syscalls.deny"] = "io_uring_setup errno 1\nbpf errno 1"
	if KernelSurfaceMatches(match, p) {
		t.Error("expected mismatch when the deny list is incomplete")
	}
	match["security.syscalls.deny"] = kernelSurfaceDenyValue(p)
	// A stray nesting=true is drift.
	drift := map[string]string{"security.nesting": "true"}
	if KernelSurfaceMatches(drift, p) {
		t.Error("expected mismatch when nesting is still on")
	}
	// Default policy matches a docker-on container.
	dockerOn := map[string]string{
		"security.nesting":                                 "true",
		"security.syscalls.intercept.mknod":                "true",
		"security.syscalls.intercept.setxattr":             "true",
		"linux.sysctl.net.ipv4.ip_unprivileged_port_start": "0",
		"security.syscalls.deny":                           "",
	}
	if !KernelSurfaceMatches(dockerOn, DefaultHardeningPolicy()) {
		t.Error("default policy should match a docker-on container")
	}
}

// kernelSurfaceViolations must flag EXPANDED (profile-inherited) values that
// widen the surface beyond the policy — the case an instance-local unset
// cannot fix — while tolerating values that only narrow it.
func TestKernelSurfaceViolations(t *testing.T) {
	hardened := HardeningPolicy{Docker: false, ReduceKernelSurface: true}
	dockerOff := HardeningPolicy{Docker: false}
	fullDeny := kernelSurfaceDenyValue(hardened) // the complete base list, as stored

	// Clean hardened container: no violations.
	clean := map[string]string{"security.syscalls.deny": fullDeny}
	if v := kernelSurfaceViolations(clean, hardened); len(v) != 0 {
		t.Errorf("clean hardened config should have no violations, got %v", v)
	}

	// Profile-pinned nesting defeats hardening — every truthy spelling counts.
	for _, spelling := range []string{"true", "1", "yes", "on", "True", " true "} {
		cfg := map[string]string{
			"security.nesting":       spelling,
			"security.syscalls.deny": fullDeny,
		}
		if v := kernelSurfaceViolations(cfg, hardened); len(v) != 1 {
			t.Errorf("nesting=%q should be one violation, got %v", spelling, v)
		}
	}
	// Falsy spellings are fine.
	for _, spelling := range []string{"", "false", "0", "off"} {
		cfg := map[string]string{
			"security.nesting":       spelling,
			"security.syscalls.deny": fullDeny,
		}
		if v := kernelSurfaceViolations(cfg, hardened); len(v) != 0 {
			t.Errorf("nesting=%q should not violate, got %v", spelling, v)
		}
	}

	// Low-port sysctl: only values below the kernel default 1024 widen;
	// unparseable fails closed.
	for val, want := range map[string]int{"0": 1, "80": 1, "1024": 0, "4096": 0, "junk": 1} {
		cfg := map[string]string{
			"linux.sysctl.net.ipv4.ip_unprivileged_port_start": val,
			"security.syscalls.deny":                           fullDeny,
		}
		if v := kernelSurfaceViolations(cfg, hardened); len(v) != want {
			t.Errorf("low-port=%q: want %d violations, got %v", val, want, v)
		}
	}

	// A missing deny token under reduce_kernel_surface is a violation
	// (write-path regression backstop).
	partial := map[string]string{"security.syscalls.deny": "io_uring_setup errno 1\nbpf errno 1"}
	if v := kernelSurfaceViolations(partial, hardened); len(v) != 1 {
		t.Errorf("partial deny list should be one violation, got %v", v)
	}

	// docker=false without reduce: nesting pinned by profile still violates,
	// but a profile-supplied deny list is a NARROWING and is tolerated.
	if v := kernelSurfaceViolations(map[string]string{"security.nesting": "true"}, dockerOff); len(v) != 1 {
		t.Errorf("docker-off with pinned nesting should violate, got %v", v)
	}
	if v := kernelSurfaceViolations(map[string]string{"security.syscalls.deny": "bpf"}, dockerOff); len(v) != 0 {
		t.Errorf("profile deny under docker-off is a narrowing, not a violation, got %v", v)
	}

	// Default (docker-on) policy: nothing to verify — instance-local writes
	// override profiles for every wanted-set key, and extra denies narrow.
	junk := map[string]string{
		"security.nesting":       "true",
		"security.syscalls.deny": "bpf",
	}
	if v := kernelSurfaceViolations(junk, DefaultHardeningPolicy()); v != nil {
		t.Errorf("default policy must never report violations, got %v", v)
	}
}

// The deny list itself: each syscall exactly once, no accidental edits.
func TestKernelSurfaceDenySyscalls(t *testing.T) {
	want := []string{
		"io_uring_setup", "io_uring_enter", "io_uring_register",
		"bpf", "userfaultfd", "keyctl", "add_key", "request_key",
	}
	got := strings.Fields(KernelSurfaceDenySyscalls)
	seen := make(map[string]bool)
	for _, s := range got {
		if seen[s] {
			t.Errorf("syscall %q listed twice", s)
		}
		seen[s] = true
	}
	for _, s := range want {
		if !seen[s] {
			t.Errorf("syscall %q missing from deny list", s)
		}
	}
	if len(got) != len(want) {
		t.Errorf("deny list has %d entries, want %d", len(got), len(want))
	}
}

// The strict tier is exactly the base list plus perf_event_open, and it implies
// the base tier (setting only ReduceKernelSurfaceStrict still reduces surface).
func TestKernelSurfaceStrictTier(t *testing.T) {
	if KernelSurfaceStrictExtraSyscalls != "perf_event_open" {
		t.Errorf("strict extras = %q, want %q", KernelSurfaceStrictExtraSyscalls, "perf_event_open")
	}

	// Strict implies base even when only the strict field is set.
	strict := HardeningPolicy{ReduceKernelSurfaceStrict: true}
	if !strict.reducesKernelSurface() {
		t.Error("strict tier must imply the base tier")
	}
	if strict.DockerEnabled() {
		// docker=false already, but assert the precedence explicitly
		t.Error("strict tier must win over Docker")
	}
	// Strict tier denies exactly the base names + perf_event_open, and every
	// entry is newline-separated with an explicit errno action.
	strictNames := kernelSurfaceDenySyscallNames(strict)
	wantNames := append(strings.Fields(KernelSurfaceDenySyscalls), "perf_event_open")
	if strings.Join(strictNames, ",") != strings.Join(wantNames, ",") {
		t.Errorf("strict names = %v, want %v", strictNames, wantNames)
	}
	strictVal := kernelSurfaceDenyValue(strict)
	if !strings.Contains(strictVal, "perf_event_open "+kernelSurfaceDenyAction) {
		t.Errorf("strict deny value must include perf_event_open with the errno action, got %q", strictVal)
	}
	for _, entry := range strings.Split(strictVal, "\n") {
		if !strings.HasSuffix(entry, " "+kernelSurfaceDenyAction) {
			t.Errorf("deny entry %q lacks the errno action", entry)
		}
	}

	// Base tier alone must NOT deny perf_event_open (that is the whole point of
	// keeping it a separate opt-in).
	base := HardeningPolicy{ReduceKernelSurface: true}
	if kernelSurfaceDenySyscallSet(kernelSurfaceDenyValue(base))["perf_event_open"] {
		t.Error("base tier must not deny perf_event_open")
	}

	// No tier -> empty deny value.
	if got := kernelSurfaceDenyValue(HardeningPolicy{Docker: true}); got != "" {
		t.Errorf("no-tier deny value = %q, want empty", got)
	}

	// The strict deny value is what actually lands in the config args.
	if denyArg := argsMap(t, strict)["security.syscalls.deny"]; denyArg != strictVal {
		t.Errorf("config arg security.syscalls.deny = %q, want %q", denyArg, strictVal)
	}
}

// A container whose effective (profile-expanded) deny list is missing the strict
// extra is a violation under the strict policy but fine under the base policy.
func TestKernelSurfaceStrictViolation(t *testing.T) {
	// Effective config carrying only the base list (as actually stored).
	baseOnly := map[string]string{
		"security.syscalls.deny": kernelSurfaceDenyValue(HardeningPolicy{ReduceKernelSurface: true}),
	}

	if v := kernelSurfaceViolations(baseOnly, HardeningPolicy{ReduceKernelSurface: true}); v != nil {
		t.Errorf("base policy satisfied by base list, got violations %v", v)
	}
	v := kernelSurfaceViolations(baseOnly, HardeningPolicy{ReduceKernelSurfaceStrict: true})
	if len(v) == 0 {
		t.Error("strict policy must flag a base-only deny list as missing perf_event_open")
	}
}

// passwordless_sudo = false wins over Docker: the docker socket is root.
func TestHardeningPolicy_NoSudoDisablesDocker(t *testing.T) {
	if (HardeningPolicy{Docker: true, NoSudo: true}).DockerEnabled() {
		t.Error("NoSudo must turn Docker off")
	}
	if !(HardeningPolicy{Docker: true}).DockerEnabled() {
		t.Error("Docker stays on with sudo")
	}
}
