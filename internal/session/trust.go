package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// TrustEnvVar is the environment variable that, when set to a truthy value (1/true/yes), bypasses the
// untrusted-resource gate. Intended for CI/automation where the operator already
// controls the config and prompting is impractical. It is safe because only the
// invoking shell can set it — a cloned repo's config cannot.
const TrustEnvVar = "COI_TRUST_ALL"

// trustStore is the on-disk format: a map from an untrusted config file's
// absolute path to a single fingerprint covering ALL host-affecting resources it
// declares that need approval — its escaping mounts AND its forwarded sockets.
// `coi trust` approves a source for everything it declares; changing any gated
// mount or socket re-arms the prompt.
type trustStore struct {
	Approvals map[string]string `toml:"approvals"`
}

// TrustAllViaEnv reports whether the COI_TRUST_ALL opt-out is set.
func TrustAllViaEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(TrustEnvVar))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// TrustStorePath returns the trust store location (~/.coi/trust.toml). The store
// lives in the trusted user scope; inside a container .coi is a read-only mount,
// so an agent cannot forge entries.
func TrustStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".coi", "trust.toml"), nil
}

func loadTrustStore() (map[string]string, error) {
	path, err := TrustStorePath()
	if err != nil {
		return nil, err
	}
	var ts trustStore
	if _, err := toml.DecodeFile(path, &ts); err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	if ts.Approvals == nil {
		ts.Approvals = map[string]string{}
	}
	return ts.Approvals, nil
}

func saveTrustStore(m map[string]string) error {
	path, err := TrustStorePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Write to a temp file in the same dir then rename, so a crash mid-write
	// can't truncate/corrupt the live store (which would silently drop all
	// approvals on the next launch).
	tmp, err := os.CreateTemp(dir, ".trust-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	// os.CreateTemp already creates the file 0600 on Unix, which is what we want.
	if err := toml.NewEncoder(tmp).Encode(trustStore{Approvals: m}); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// isWithinWorkspace reports whether hostPath is the workspace dir or nested in
// it. Both arguments should be absolute.
func isWithinWorkspace(workspace, hostPath string) bool {
	workspace = filepath.Clean(workspace)
	hostPath = filepath.Clean(hostPath)
	if hostPath == workspace {
		return true
	}
	rel, err := filepath.Rel(workspace, hostPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// realPath resolves symlinks in p as far as it can: it resolves the longest
// existing prefix with filepath.EvalSymlinks and re-appends the non-existent
// remainder, following a dangling symlink via Readlink. This makes the
// workspace-escape check robust against an in-workspace symlink that points
// outside — a purely lexical check would miss it, but Incus follows the link at
// mount time. Best-effort and bounded against symlink cycles; falls back to the
// cleaned lexical path if nothing resolves.
func realPath(p string) string {
	if p == "" {
		return ""
	}
	cur := filepath.Clean(p)
	var rest []string
	rejoin := func(base string) string {
		full := base
		for i := len(rest) - 1; i >= 0; i-- {
			full = filepath.Join(full, rest[i])
		}
		return full
	}
	for i := 0; i < 256; i++ { // bound: defend against symlink cycles
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			return rejoin(resolved)
		}
		// cur doesn't fully resolve. If it is itself a (possibly dangling)
		// symlink, follow its target and retry.
		if fi, lerr := os.Lstat(cur); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			if target, rerr := os.Readlink(cur); rerr == nil {
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(cur), target)
				}
				cur = filepath.Clean(target)
				continue
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur { // reached root without resolving — lexical fallback
			return rejoin(cur)
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
	return rejoin(cur)
}

// hostEscapesWorkspace reports whether hostPath resolves outside the workspace,
// resolving symlinks on both so an in-workspace symlink to an outside directory
// cannot pass as contained.
func hostEscapesWorkspace(workspace, hostPath string) bool {
	return !isWithinWorkspace(realPath(workspace), realPath(hostPath))
}

// escapingUntrustedMounts returns the untrusted mounts whose host path resolves
// outside the workspace — the gated set.
func escapingUntrustedMounts(mounts []MountEntry, workspace string) []MountEntry {
	var out []MountEntry
	for _, m := range mounts {
		if m.Untrusted && m.HostPath != "" && hostEscapesWorkspace(workspace, m.HostPath) {
			out = append(out, m)
		}
	}
	return out
}

// untrustedSockets returns the untrusted forwarded sockets — the gated set. A
// forwarded host socket exposes a host capability with no "within workspace"
// notion, so ALL untrusted sockets need approval (not just escaping ones).
func untrustedSockets(sockets []SocketEntry) []SocketEntry {
	var out []SocketEntry
	for _, s := range sockets {
		if s.Untrusted && s.HostPath != "" {
			out = append(out, s)
		}
	}
	return out
}

// untrustedCredentials returns the untrusted ad-hoc credential entries, the
// gated set. Like a forwarded socket, a credential entry has no "within
// workspace" notion, so ALL untrusted ad-hoc entries need approval. Entries
// resolved from a named catalog bundle are never marked Untrusted by
// ParseCredentialConfig (their host path is fixed by coi's own catalog, not
// chosen by the referencing config); BundleName == "" is checked here too as
// a second line of defense.
func untrustedCredentials(creds []CredentialEntry) []CredentialEntry {
	var out []CredentialEntry
	for _, c := range creds {
		if c.Untrusted && c.HostPath != "" && c.BundleName == "" {
			out = append(out, c)
		}
	}
	return out
}

// untrustedPorts returns the untrusted published-port entries — the gated
// set. A host port listener exposes a host capability (and can squat
// well-known localhost ports another host process would connect to), so ALL
// untrusted entries need approval, like forwarded sockets.
func untrustedPorts(ports []PortEntry) []PortEntry {
	var out []PortEntry
	for _, p := range ports {
		if p.Untrusted && p.ContainerPort != 0 {
			out = append(out, p)
		}
	}
	return out
}

// sourceFingerprint returns a stable sha256 over the gated mounts, sockets,
// ad-hoc credential, and published-port entries a single source declares
// (order-independent).
// Adding/removing/changing any gated resource changes the hash and re-arms
// the trust prompt; unrelated config edits do not. Lines are type-prefixed
// and %q-quoted so distinct sets cannot collide via embedded separators.
func sourceFingerprint(mounts []MountEntry, sockets []SocketEntry, creds []CredentialEntry, ports []PortEntry, pool int) string {
	lines := make([]string, 0, len(mounts)+len(sockets)+len(creds))
	for _, m := range mounts {
		// Shift is a three-state override (nil=inherit / true / false) and
		// changes the effective writability of an approved mount, so it must
		// re-arm trust like readonly does (#604).
		lines = append(lines, fmt.Sprintf("mount:%q|%q|%t|shift=%s", m.HostPath, m.ContainerPath, m.Readonly, shiftFingerprint(m.Shift)))
	}
	for _, s := range sockets {
		lines = append(lines, fmt.Sprintf("socket:%q|%q|%q", s.HostPath, s.ContainerPath, s.EnvVar))
	}
	for _, c := range creds {
		lines = append(lines, fmt.Sprintf("credential:%q|%q|%q", c.HostPath, c.ContainerPath, c.Mode))
	}
	for _, p := range ports {
		lines = append(lines, fmt.Sprintf("port:%q|%d|%d|%q", p.Name, p.ContainerPort, p.HostPort, p.Listen))
	}
	if pool > 0 {
		lines = append(lines, fmt.Sprintf("port-pool:%d", pool))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// shiftFingerprint renders a mount's three-state *bool shift override as a
// stable, collision-free token for the trust fingerprint: unset, true, and
// false must all hash differently so any change re-arms the trust prompt.
func shiftFingerprint(shift *bool) string {
	if shift == nil {
		return "unset"
	}
	if *shift {
		return "true"
	}
	return "false"
}

// trustedSources computes, per source path, whether the source's gated
// mounts, sockets, and ad-hoc credentials are all approved (combined
// fingerprint matches the store).
func trustedSources(mc *MountConfig, sc *SocketConfig, cc *CredentialConfig, pc *PortConfig, workspace string, store map[string]string) map[string]bool {
	mountsBySrc := map[string][]MountEntry{}
	if mc != nil {
		for _, m := range escapingUntrustedMounts(mc.Mounts, workspace) {
			mountsBySrc[m.SourcePath] = append(mountsBySrc[m.SourcePath], m)
		}
	}
	socketsBySrc := map[string][]SocketEntry{}
	if sc != nil {
		for _, s := range untrustedSockets(sc.Sockets) {
			socketsBySrc[s.SourcePath] = append(socketsBySrc[s.SourcePath], s)
		}
	}
	credsBySrc := map[string][]CredentialEntry{}
	if cc != nil {
		for _, c := range untrustedCredentials(cc.Entries) {
			credsBySrc[c.SourcePath] = append(credsBySrc[c.SourcePath], c)
		}
	}
	portsBySrc := map[string][]PortEntry{}
	poolBySrc := map[string]int{}
	if pc != nil {
		for _, p := range untrustedPorts(pc.Ports) {
			portsBySrc[p.SourcePath] = append(portsBySrc[p.SourcePath], p)
		}
		if pc.Pool > 0 && pc.PoolUntrusted {
			poolBySrc[pc.PoolSourcePath] = pc.Pool
		}
	}
	srcs := map[string]bool{}
	for src := range mountsBySrc {
		srcs[src] = true
	}
	for src := range socketsBySrc {
		srcs[src] = true
	}
	for src := range credsBySrc {
		srcs[src] = true
	}
	for src := range portsBySrc {
		srcs[src] = true
	}
	for src := range poolBySrc {
		srcs[src] = true
	}
	out := map[string]bool{}
	for src := range srcs {
		out[src] = store[src] != "" && store[src] == sourceFingerprint(mountsBySrc[src], socketsBySrc[src], credsBySrc[src], portsBySrc[src], poolBySrc[src])
	}
	return out
}

// FilterTrusted removes untrusted mounts that escape the workspace, untrusted
// forwarded sockets, and untrusted ad-hoc credential entries, unless their
// source's combined fingerprint is recorded as trusted (or COI_TRUST_ALL is
// set). Returns filtered configs plus the dropped resources (so the caller
// can warn). Trusted-scope and in-workspace mounts are never gated;
// catalog-referenced credential entries (BundleName != "") are never gated.
func FilterTrusted(mc *MountConfig, sc *SocketConfig, cc *CredentialConfig, pc *PortConfig, workspace string) (*MountConfig, []MountEntry, *SocketConfig, []SocketEntry, *CredentialConfig, []CredentialEntry, *PortConfig, []PortEntry) {
	if TrustAllViaEnv() {
		return mc, nil, sc, nil, cc, nil, pc, nil
	}
	// Cheap exit when there's nothing gated, before loading the store.
	var escMounts []MountEntry
	if mc != nil {
		escMounts = escapingUntrustedMounts(mc.Mounts, workspace)
	}
	var untSockets []SocketEntry
	if sc != nil {
		untSockets = untrustedSockets(sc.Sockets)
	}
	var untCreds []CredentialEntry
	if cc != nil {
		untCreds = untrustedCredentials(cc.Entries)
	}
	var untPorts []PortEntry
	untPool := false
	if pc != nil {
		untPorts = untrustedPorts(pc.Ports)
		untPool = pc.Pool > 0 && pc.PoolUntrusted
	}
	if len(escMounts) == 0 && len(untSockets) == 0 && len(untCreds) == 0 && len(untPorts) == 0 && !untPool {
		return mc, nil, sc, nil, cc, nil, pc, nil
	}

	store, _ := loadTrustStore() // missing/unreadable store → nothing trusted
	trusted := trustedSources(mc, sc, cc, pc, workspace, store)

	keptMC := mc
	var droppedMounts []MountEntry
	if mc != nil {
		keptMC = &MountConfig{Mounts: make([]MountEntry, 0, len(mc.Mounts))}
		for _, m := range mc.Mounts {
			if m.Untrusted && m.HostPath != "" && hostEscapesWorkspace(workspace, m.HostPath) && !trusted[m.SourcePath] {
				droppedMounts = append(droppedMounts, m)
				continue
			}
			keptMC.Mounts = append(keptMC.Mounts, m)
		}
	}

	keptSC := sc
	var droppedSockets []SocketEntry
	if sc != nil {
		keptSC = &SocketConfig{Sockets: make([]SocketEntry, 0, len(sc.Sockets))}
		for _, s := range sc.Sockets {
			if s.Untrusted && s.HostPath != "" && !trusted[s.SourcePath] {
				droppedSockets = append(droppedSockets, s)
				continue
			}
			keptSC.Sockets = append(keptSC.Sockets, s)
		}
	}

	keptCC := cc
	var droppedCreds []CredentialEntry
	if cc != nil {
		keptCC = &CredentialConfig{Entries: make([]CredentialEntry, 0, len(cc.Entries))}
		for _, c := range cc.Entries {
			if c.Untrusted && c.HostPath != "" && c.BundleName == "" && !trusted[c.SourcePath] {
				droppedCreds = append(droppedCreds, c)
				continue
			}
			keptCC.Entries = append(keptCC.Entries, c)
		}
	}

	keptPC := pc
	var droppedPorts []PortEntry
	if pc != nil {
		keptPC = &PortConfig{
			Pool:                pc.Pool,
			PoolUntrusted:       pc.PoolUntrusted,
			PoolSourcePath:      pc.PoolSourcePath,
			PoolTrustedFallback: pc.PoolTrustedFallback,
			Ports:               make([]PortEntry, 0, len(pc.Ports)),
		}
		for _, p := range pc.Ports {
			if p.Untrusted && p.ContainerPort != 0 && !trusted[p.SourcePath] {
				droppedPorts = append(droppedPorts, p)
				continue
			}
			keptPC.Ports = append(keptPC.Ports, p)
		}
		if pc.Pool > 0 && pc.PoolUntrusted && !trusted[pc.PoolSourcePath] {
			// Report the dropped pool as a synthetic entry so callers can
			// warn uniformly; ContainerPort 0 marks it as the pool (see
			// DescribeDroppedPort for how it is rendered).
			droppedPorts = append(droppedPorts, PortEntry{
				Name:       fmt.Sprintf("pool of %d ports", pc.Pool),
				SourcePath: pc.PoolSourcePath,
				Untrusted:  true,
			})
			// An untrusted overlay must not disable the user's own pool: fall
			// back to the last trusted value it overwrote (0 if none).
			keptPC.Pool = pc.PoolTrustedFallback
			keptPC.PoolUntrusted = false
			keptPC.PoolSourcePath = ""
		}
	}

	return keptMC, droppedMounts, keptSC, droppedSockets, keptCC, droppedCreds, keptPC, droppedPorts
}

// TrustSources records trust for every source that declares gated mounts,
// sockets, and/or ad-hoc credentials in mc/sc/cc, pinning the current
// combined fingerprint. Returns the set of source paths that were trusted.
func TrustSources(mc *MountConfig, sc *SocketConfig, cc *CredentialConfig, pc *PortConfig, workspace string) ([]string, error) {
	mountsBySrc := map[string][]MountEntry{}
	if mc != nil {
		for _, m := range escapingUntrustedMounts(mc.Mounts, workspace) {
			mountsBySrc[m.SourcePath] = append(mountsBySrc[m.SourcePath], m)
		}
	}
	socketsBySrc := map[string][]SocketEntry{}
	if sc != nil {
		for _, s := range untrustedSockets(sc.Sockets) {
			socketsBySrc[s.SourcePath] = append(socketsBySrc[s.SourcePath], s)
		}
	}
	credsBySrc := map[string][]CredentialEntry{}
	if cc != nil {
		for _, c := range untrustedCredentials(cc.Entries) {
			credsBySrc[c.SourcePath] = append(credsBySrc[c.SourcePath], c)
		}
	}
	portsBySrc := map[string][]PortEntry{}
	poolBySrc := map[string]int{}
	if pc != nil {
		for _, p := range untrustedPorts(pc.Ports) {
			portsBySrc[p.SourcePath] = append(portsBySrc[p.SourcePath], p)
		}
		if pc.Pool > 0 && pc.PoolUntrusted {
			poolBySrc[pc.PoolSourcePath] = pc.Pool
		}
	}
	srcs := map[string]bool{}
	for src := range mountsBySrc {
		srcs[src] = true
	}
	for src := range socketsBySrc {
		srcs[src] = true
	}
	for src := range credsBySrc {
		srcs[src] = true
	}
	for src := range portsBySrc {
		srcs[src] = true
	}
	for src := range poolBySrc {
		srcs[src] = true
	}
	if len(srcs) == 0 {
		return nil, nil
	}
	store, err := loadTrustStore()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(srcs))
	for src := range srcs {
		store[src] = sourceFingerprint(mountsBySrc[src], socketsBySrc[src], credsBySrc[src], portsBySrc[src], poolBySrc[src])
		out = append(out, src)
	}
	sort.Strings(out)
	if err := saveTrustStore(store); err != nil {
		return nil, err
	}
	return out, nil
}

// UntrustSources removes trust entries for the given source paths. Returns the
// number of entries removed.
func UntrustSources(sources []string) (int, error) {
	store, err := loadTrustStore()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range sources {
		if _, ok := store[s]; ok {
			delete(store, s)
			n++
		}
	}
	if n > 0 {
		if err := saveTrustStore(store); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// ListTrusted returns the current trust store (source path -> fingerprint).
func ListTrusted() (map[string]string, error) {
	return loadTrustStore()
}

// UntrustedSourcePaths returns the distinct source config paths of untrusted
// mounts, sockets, and ad-hoc credential entries, the keys under which trust
// is recorded. `coi untrust` uses this to revoke by the exact stored key
// (resolved at load) rather than reconstructing it, which would diverge on
// symlinked/alias/non-default paths.
func UntrustedSourcePaths(mc *MountConfig, sc *SocketConfig, cc *CredentialConfig, pc *PortConfig) []string {
	seen := map[string]bool{}
	var out []string
	add := func(src string) {
		if src != "" && !seen[src] {
			seen[src] = true
			out = append(out, src)
		}
	}
	if mc != nil {
		for _, m := range mc.Mounts {
			if m.Untrusted {
				add(m.SourcePath)
			}
		}
	}
	if sc != nil {
		for _, s := range sc.Sockets {
			if s.Untrusted {
				add(s.SourcePath)
			}
		}
	}
	if cc != nil {
		for _, c := range cc.Entries {
			if c.Untrusted && c.BundleName == "" {
				add(c.SourcePath)
			}
		}
	}
	if pc != nil {
		for _, p := range pc.Ports {
			if p.Untrusted {
				add(p.SourcePath)
			}
		}
		if pc.PoolUntrusted {
			add(pc.PoolSourcePath)
		}
	}
	sort.Strings(out)
	return out
}
