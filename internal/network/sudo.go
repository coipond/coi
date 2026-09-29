package network

import "sync/atomic"

// sudoAllowed gates whether Coi may invoke `sudo` for network operations
// (nft/iptables). It defaults to true and is set once at startup from
// `[network] use_sudo` (via SetSudoAllowed in the CLI's PersistentPreRunE), so
// EVERY network sudo entry point honors the config without threading it through
// every caller. When false, the low-level probes/helpers behave as if
// passwordless sudo were unavailable and never shell out to sudo.
//
// This is a process-wide derived value, not a user-facing flag: the source of
// truth is the `use_sudo` config field. Operations that REQUIRE sudo
// (restricted/allowlist enforcement) still fail-closed via NftUsable/the mode
// dispatch; best-effort operations (open-mode rules, boot block, cleanup,
// health probes) simply skip.
var sudoAllowed atomic.Bool

func init() { sudoAllowed.Store(true) }

// SetSudoAllowed configures whether Coi may invoke sudo for network operations.
// Call once at startup from the resolved `[network] use_sudo` value.
func SetSudoAllowed(allowed bool) { sudoAllowed.Store(allowed) }

// SudoEnabled reports whether Coi may invoke sudo for network operations.
func SudoEnabled() bool { return sudoAllowed.Load() }
