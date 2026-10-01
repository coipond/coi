package vmhost

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HostToolConfigDir returns the host directory a tool's credentials/config
// should be seeded from for a container launched from THIS process.
//
// Normally that is simply <guestHome>/<configDirName>. But on macOS coi runs
// inside a Colima/Lima/OrbStack Linux VM (see install.sh — a native darwin
// build is refused), so os.UserHomeDir() is the *guest* home (e.g.
// /home/lima), not the Mac user's home. The Mac home is instead shared into
// the guest over virtiofs/9p under /Users. A fresh guest home has no
// ~/.claude, so the default path finds nothing to seed and the container boots
// an unauthenticated tool. When we detect a Mac VM and the guest's own config
// dir holds no real config, fall back to the same config dir under the shared
// Mac home so `coi shell` picks up the Mac user's real credentials. On Linux
// (KindUnknown) this is a no-op and returns the guest path unchanged.
//
// The guest and candidate sides are judged asymmetrically (see
// ResolveHostConfigDir). configFiles are the tool's essential config filenames
// (e.g. [".credentials.json", "settings.json", …]); the guest wins only if it
// holds one of them, so a guest dir of stray files can't shadow a populated Mac
// home. A shared Mac home, by contrast, is used when it merely exists and is
// non-empty — even a Mac ~/.claude whose OAuth token lives in the Keychain
// (so it has no .credentials.json) still carries settings and the sibling
// ~/.claude.json onboarding state worth seeding.
//
// It also returns the detected VM Kind so callers can reuse it (e.g. the macOS
// Keychain hint) without re-reading /proc/mounts.
func HostToolConfigDir(guestHome, configDirName string, configFiles []string) (string, Kind) {
	if configDirName == "" {
		return filepath.Join(guestHome, configDirName), KindUnknown
	}
	// Read /proc/mounts (and the kernel release) ONCE and reuse the blob for
	// both VM detection and shared-home candidate discovery — previously the
	// detection and candidate steps each read /proc/mounts independently.
	mounts, _ := os.ReadFile("/proc/mounts")
	osRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	kind := detect(string(mounts), os.Getenv("USER"), string(osRelease))
	path := resolveToolConfigDir(guestHome, configDirName, configFiles, kind, string(mounts), listSubdirs, dirHasAnyFile, dirNonEmpty)
	return path, kind
}

// resolveToolConfigDir is the testable core of HostToolConfigDir: given the
// already-detected VM kind and the already-read /proc/mounts blob, it builds the
// shared-home candidates and picks the config dir. Every filesystem touch is
// injected (listSubdirs, guestHasConfig, candidateUsable) so the wiring —
// including that the tool's configFiles reach the guest check and that
// KindUnknown short-circuits — is unit-testable without a real Mac VM.
func resolveToolConfigDir(
	guestHome, configDirName string,
	configFiles []string,
	kind Kind,
	mounts string,
	listSubdirs func(string) []string,
	guestHasConfig func(string, []string) bool,
	candidateUsable func(string) bool,
) string {
	guestPath := filepath.Join(guestHome, configDirName)
	if kind == KindUnknown {
		return guestPath
	}
	candidates := buildMacHostConfigCandidates(mounts, configDirName, listSubdirs)
	return ResolveHostConfigDir(guestPath, candidates,
		func(dir string) bool { return guestHasConfig(dir, configFiles) },
		candidateUsable)
}

// ResolveHostConfigDir chooses between the guest's own config dir and config
// dirs found under a shared Mac home, judging the two sides asymmetrically:
//
//   - The guest path wins only if guestHasConfig reports it already holds real
//     tool config (the user authenticated inside the VM). This is strict — a
//     dir of stray files must NOT win, or it would shadow the real Mac home.
//   - Otherwise the first shared-home candidate that candidateUsable accepts is
//     returned. This is deliberately lax ("exists and is non-empty"): a Mac
//     ~/.claude whose credentials live in the Keychain has no .credentials.json
//     yet still carries settings and the sibling onboarding state worth
//     seeding, so requiring a specific config file here would wrongly skip it.
//
// If nothing qualifies the guest path is returned unchanged, so the seeding
// step simply skips the missing files as before. Pure and injectable so the
// selection logic is unit-testable without a real filesystem.
func ResolveHostConfigDir(guestPath string, candidates []string, guestHasConfig, candidateUsable func(string) bool) string {
	if guestHasConfig(guestPath) {
		return guestPath
	}
	for _, c := range candidates {
		if c != guestPath && candidateUsable(c) {
			return c
		}
	}
	return guestPath
}

// buildMacHostConfigCandidates builds the list of <configDirName> paths to look
// for under the Mac homes shared into this guest, from an already-read
// /proc/mounts blob with directory listing injected for testability. A shared
// mount is normally the Mac home itself (/Users/alice), so <mount>/<configDirName> is the sole
// candidate — no descent, so we neither read the whole home over virtiofs nor
// mistake a nested stray .claude for the real one. Only when the whole /Users
// parent is shared do we descend one level (/Users/*/<configDirName>).
// Deduplicated, order-stable.
func buildMacHostConfigCandidates(mounts, configDirName string, listSubdirs func(string) []string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, m := range macHostMounts(mounts) {
		if m == "/Users" {
			for _, name := range listSubdirs(m) {
				add(filepath.Join(m, name, configDirName))
			}
			continue
		}
		add(filepath.Join(m, configDirName))
	}
	return out
}

// listSubdirs returns the names of the immediate subdirectories of p, or nil
// if p can't be read.
func listSubdirs(p string) []string {
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

// macHostMounts returns the mountpoints under /Users that a Mac VM shares into
// the guest via virtiofs (Lima/Colima/OrbStack) or 9p (Lima with
// mountType: 9p) — i.e. where the Mac user's real home is visible from inside
// the VM. Pure over a /proc/mounts blob; sorted and deduplicated for stable
// candidate ordering.
func macHostMounts(mounts string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// /proc/mounts fields: source mountpoint fstype ...; the mountpoint is
		// octal-escaped by the kernel (space -> \040, etc.), so decode it before
		// use or a Mac home path containing those characters never resolves.
		mountpoint := unescapeMountField(fields[1])
		fstype := fields[2]
		if fstype != "virtiofs" && fstype != "9p" {
			continue
		}
		if mountpoint != "/Users" && !strings.HasPrefix(mountpoint, "/Users/") {
			continue
		}
		if !seen[mountpoint] {
			seen[mountpoint] = true
			out = append(out, mountpoint)
		}
	}
	sort.Strings(out)
	return out
}

// mountFieldUnescaper decodes the octal escapes the kernel writes into
// /proc/mounts fields: space, tab, newline, and backslash (see the kernel's
// mangle_path). These are the only characters escaped there.
var mountFieldUnescaper = strings.NewReplacer(
	`\040`, " ",
	`\011`, "\t",
	`\012`, "\n",
	`\134`, `\`,
)

func unescapeMountField(s string) string { return mountFieldUnescaper.Replace(s) }

// dirHasAnyFile reports whether dir contains at least one of the named files —
// the strict "guest already holds real tool config" signal for
// ResolveHostConfigDir. Keyed on actual config files rather than mere directory
// non-emptiness so a guest dir holding only unrelated/stray files does not
// shadow a real shared Mac home.
func dirHasAnyFile(dir string, files []string) bool {
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// dirNonEmpty reports whether a directory exists and contains at least one
// entry — the lax "shared Mac home worth seeding from" signal for
// ResolveHostConfigDir. Non-empty (not marker-file) on purpose: a Mac config
// dir whose credentials live in the Keychain still carries settings and other
// state we want to bring across.
func dirNonEmpty(p string) bool {
	entries, err := os.ReadDir(p)
	return err == nil && len(entries) > 0
}

// MacHostHome returns the Mac user's real home directory as seen from inside a
// Colima/Lima/OrbStack Mac VM, or "" on Linux (KindUnknown) or when it cannot be
// pinned down unambiguously. There os.UserHomeDir() is the guest home, so
// `git config --global` reads the VM's gitconfig and misses the Mac user's
// user.name/user.email; the Mac home is visible under /Users via the shared
// mount.
//
// Only a real home (/Users/<name>) qualifies: a deeper project mount such as
// /Users/alice/code does not expose the home's dotfiles. When the whole /Users
// parent is shared, several homes are visible, and picking the first one
// alphabetically would seed SOMEONE ELSE's identity on a multi-user Mac — so
// only the guest user's own home (VMs mirror the Mac username) is accepted, and
// an ambiguous setup yields "" rather than a guess.
func MacHostHome() string {
	mounts, _ := os.ReadFile("/proc/mounts")
	osRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	user := os.Getenv("USER")
	kind := detect(string(mounts), user, string(osRelease))
	return macHostHome(kind, string(mounts), user, dirExists)
}

// macHostHome is the testable core of MacHostHome.
func macHostHome(kind Kind, mounts, user string, isDir func(string) bool) string {
	if kind == KindUnknown {
		return ""
	}
	// $USER is joined into a path below: accept only a single plain path
	// component, so a value like "../../etc" can never steer the lookup out of
	// /Users.
	if user == "" || user == "." || user == ".." || strings.ContainsAny(user, `/\`) {
		user = ""
	} else {
		user = filepath.Base(user) // no-op for a validated component; marks it as sanitized
	}
	var homes []string
	seen := make(map[string]bool)
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			homes = append(homes, p)
		}
	}
	for _, m := range macHostMounts(mounts) {
		switch {
		case m == "/Users":
			if user != "" && isDir(filepath.Join(m, user)) {
				add(filepath.Join(m, user))
			}
		case filepath.Dir(m) == "/Users":
			add(m)
		}
	}
	if len(homes) == 1 {
		return homes[0]
	}
	for _, h := range homes {
		if user != "" && filepath.Base(h) == user {
			return h
		}
	}
	return ""
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
