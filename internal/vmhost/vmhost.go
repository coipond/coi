// Package vmhost detects which VM (if any) is hosting the current container
// runtime, so callers can answer VM-specific behavior questions — such as
// whether the host already handles UID mapping for shared/mounted
// directories — from a single, shared piece of detection logic.
package vmhost

import (
	"os"
	"strings"
)

// Kind identifies the detected VM host, or KindUnknown if none matched.
type Kind int

const (
	// KindUnknown means no known VM host was detected.
	KindUnknown Kind = iota
	// KindLimaLike is Colima or Lima: both mount host directories via
	// virtiofs and already handle UID mapping at the VM level.
	KindLimaLike
	// KindOrbStack also mounts host directories via virtiofs, but does NOT
	// handle UID mapping at the VM level the way Lima/Colima do.
	KindOrbStack
)

// HandlesUIDMapping reports whether this VM host already handles UID mapping
// for shared/mounted directories, making Incus's own shift=true redundant
// (and potentially harmful) on top of it.
func (k Kind) HandlesUIDMapping() bool {
	return k == KindLimaLike
}

// String returns the label used in user-facing messages, or "" for KindUnknown.
func (k Kind) String() string {
	switch k {
	case KindLimaLike:
		return "colima"
	case KindOrbStack:
		return "orbstack"
	default:
		return ""
	}
}

// Detect identifies the current VM host by reading /proc/mounts, the USER
// env var, and the guest kernel's release string.
func Detect() Kind {
	mounts, _ := os.ReadFile("/proc/mounts")
	osRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return detect(string(mounts), os.Getenv("USER"), string(osRelease))
}

// detect is the pure decision logic behind Detect, split out so it can be
// unit tested without touching the real filesystem.
func detect(mounts, user, osRelease string) Kind {
	// OrbStack also mounts the host filesystem via virtiofs, so it must be
	// excluded before the generic virtiofs check below, or it would
	// false-positive as Lima/Colima. It is detected via its guest kernel's
	// release string (e.g. "7.0.11-orbstack-...") and, unlike Lima/Colima, does
	// NOT handle UID mapping at the VM level — hence KindOrbStack.HandlesUIDMapping()
	// is false and coi maps UIDs itself. Whether OrbStack's virtiofs mounts
	// support Incus's idmapped ("shift") mounts is kernel-dependent and NOT
	// assumed here: some OrbStack kernels can't, so a shift=true workspace mount
	// fails at container start, and on 2.2.2 and later it attaches but produces
	// junk ownership instead. Neither is decided by this string match. The
	// question is answered from the source path's filesystem instead, in
	// SourceBlocksIdmappedMounts (#683), with the reactive raw.idmap fallback at
	// start (StartWithIsolationFallback / #678) left underneath as the backstop.
	if strings.Contains(strings.ToLower(osRelease), "orbstack") {
		return KindOrbStack
	}

	// Lima mounts host directories via virtiofs (e.g., "mount0 on /Users/... type virtiofs")
	// Colima uses Lima under the hood, so same detection applies
	if strings.Contains(mounts, "virtiofs") {
		return KindLimaLike
	}

	// Additional check: Lima typically runs as the "lima" user
	if user == "lima" {
		return KindLimaLike
	}

	return KindUnknown
}
