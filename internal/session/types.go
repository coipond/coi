package session

// MountEntry represents a single directory mount at runtime
type MountEntry struct {
	HostPath      string // Absolute path on host (expanded)
	ContainerPath string // Absolute path in container
	DeviceName    string // Unique device name for Incus
	UseShift      bool   // Whether to use UID shifting
	Readonly      bool   // Mount read-only

	// Shift, when non-nil, overrides the session-wide shift decision for this
	// mount (#604). See config.MountEntry.Shift for the semantics; nil inherits
	// the session default. Resolved to the effective flag by ResolveMountShift.
	Shift *bool

	// Untrusted is true when this mount came from an untrusted (project-scope)
	// config file. SourcePath is that file's absolute path. Used to gate mounts
	// whose host path escapes the workspace behind explicit trust (`coi trust`).
	Untrusted  bool
	SourcePath string

	// MigrateFrom, when set, is an older location of this mount's data: the
	// first time the mount is added, it is moved to HostPath (see
	// PrepareMountSource). Only set on coi-generated mounts.
	MigrateFrom string
}

// MountConfig holds all mount configurations for a session
type MountConfig struct {
	Mounts []MountEntry
}

// SocketEntry represents a host unix socket forwarded into the container at
// runtime (via an Incus proxy device). It generalizes SSH agent forwarding.
type SocketEntry struct {
	HostPath      string // Absolute host socket path (expanded)
	ContainerPath string // In-container socket path
	EnvVar        string // Optional env var NAME set to ContainerPath ("" = none)
	DeviceName    string // Unique Incus proxy-device name

	// Untrusted is true when this entry came from an untrusted (project-scope)
	// config file. SourcePath is that file's absolute path. Untrusted sockets are
	// gated behind explicit trust (`coi trust`).
	Untrusted  bool
	SourcePath string
}

// SocketConfig holds all forwarded-socket entries for a session.
type SocketConfig struct {
	Sockets []SocketEntry
}

// PortEntry is a resolved container-TCP-port publication: the container port
// is exposed on the host (localhost by default) via an Incus proxy device so
// agent-started services are reachable as localhost:<HostPort> (#558).
// HostPort 0 means "allocate per workspace/slot at publish time" (see
// AllocateHostPort); a non-zero HostPort is an exact user pin.
type PortEntry struct {
	Name          string // Identifier; exported as COI_PORT_<NAME>
	ContainerPort int    // TCP port inside the container
	HostPort      int    // Exact host port, or 0 = auto per workspace/slot
	Listen        string // Host listen address ("" = 127.0.0.1)
	DeviceName    string // Unique Incus proxy-device name

	// Untrusted/SourcePath: set when the entry came from an untrusted
	// project-scope config. Host listeners can squat well-known localhost
	// ports, so untrusted entries are gated behind `coi trust`.
	Untrusted  bool
	SourcePath string
}

// PortConfig holds the session's port publications: an identity-mapped pool
// (host port == container port, allocated per workspace/slot) plus named
// fixed-container-port entries.
type PortConfig struct {
	Pool  int // number of identity-mapped ports to publish (0 = none)
	Ports []PortEntry

	// PoolUntrusted/PoolSourcePath: set when the pool value came from an
	// untrusted project-scope config (map entries carry per-entry flags).
	// PoolTrustedFallback is the trusted pool value the untrusted overlay
	// overwrote, restored by FilterTrusted when the overlay is unapproved.
	PoolUntrusted       bool
	PoolSourcePath      string
	PoolTrustedFallback int
}

// HasPorts reports whether there is anything to publish.
func (pc *PortConfig) HasPorts() bool {
	return pc != nil && (pc.Pool > 0 || len(pc.Ports) > 0)
}

// CredentialEntry represents a single host file to copy into a container: a
// host path pushed to a container path, chowned to the container's code
// user, and chmod'd to Mode if set. Expanded either from a named catalog
// bundle (see internal/tool/credentials) or an ad-hoc profile entry.
type CredentialEntry struct {
	HostPath string // Absolute path on host (expanded)
	// ContainerPath is either absolute (ad-hoc entries, used as-is, exactly
	// like MountEntry.ContainerPath) or relative to the container's home
	// directory (bundle entries, resolved by setupCredentials at apply
	// time, since the home directory, e.g. /root vs /home/code, isn't known
	// until the container exists).
	ContainerPath string
	Mode          string // Optional chmod mode, e.g. "0600"; "" = leave as pushed

	// BundleName is set when this entry was expanded from a named catalog
	// bundle. Bundle-sourced entries are never gated by trust; see
	// Untrusted below.
	BundleName string

	// Untrusted is true when this entry came from an untrusted (project-scope)
	// config file AND is an ad-hoc entry (BundleName == ""). SourcePath is
	// that file's absolute path. Used to gate ad-hoc credential entries whose
	// source config isn't trusted, behind `coi trust`, mirroring
	// SocketEntry, since a credential file (like a forwarded socket) has no
	// "within workspace" notion that would make it safe to leave ungated.
	Untrusted  bool
	SourcePath string
}

// CredentialConfig holds all credential entries for a session.
type CredentialConfig struct {
	Entries []CredentialEntry
}
