package session

import (
	"fmt"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// nicSecurityRequired reports whether mode needs the eth0 anti-spoofing keys:
// restricted and allowlist enforce egress with saddr-keyed nft rules that a
// second source IP bypasses. Open mode and no network config do not.
func nicSecurityRequired(mode config.NetworkMode) bool {
	return mode == config.NetworkModeRestricted || mode == config.NetworkModeAllowlist
}

// networkMode is the mode of cfg, "" when there is no network config.
func networkMode(cfg *config.NetworkConfig) config.NetworkMode {
	if cfg == nil {
		return ""
	}
	return cfg.Mode
}

// NICSecurityError turns a failed eth0 hardening into the launch error in
// restricted/allowlist mode, and returns nil in open mode (the caller then
// warns).
func NICSecurityError(mode config.NetworkMode, err error) error {
	if !nicSecurityRequired(mode) {
		return nil
	}
	return fmt.Errorf("NIC anti-spoofing (eth0 security.ipv4_filtering, security.mac_filtering, security.port_isolation) could not be applied in %s mode: without it the container can bypass the egress rules with a second source IP; use a bridged eth0 or network mode open: %w", mode, err)
}

// ReconcileNICSecurity sets the eth0 anti-spoofing keys on a STOPPED reused
// container in restricted/allowlist mode when they are not in effect (a
// persistent container created by an older coi lacks them), and fails closed
// when they cannot be set. Open mode is left as it is.
func ReconcileNICSecurity(containerName string, mode config.NetworkMode, logger func(string)) error {
	if !nicSecurityRequired(mode) {
		return nil
	}
	changed, err := container.ReconcileNICSecurity(containerName)
	if err != nil {
		return NICSecurityError(mode, err)
	}
	if changed {
		logger("Applied NIC anti-spoofing and port isolation to eth0 (missing on this container)")
	}
	return nil
}
