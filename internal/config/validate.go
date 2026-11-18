package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Validate checks that a profile's configuration is valid.
// Called when the profile is actually used (--profile flag), not at load time.
func (p *ProfileConfig) Validate(name string) error {
	// Validate context file exists if specified
	if p.Context != "" {
		if _, err := os.Stat(p.Context); err != nil {
			return fmt.Errorf("profile '%s': context file %q does not exist", name, p.Context)
		}
	}

	// Validate build script exists if specified
	if p.Container.Build.Script != "" {
		if _, err := os.Stat(p.Container.Build.Script); err != nil {
			return fmt.Errorf("profile '%s': build script %q does not exist", name, p.Container.Build.Script)
		}
	}

	// Validate mount entries are complete
	for i, m := range p.Mounts {
		if m.Host == "" {
			return fmt.Errorf("profile '%s': mount[%d] is missing 'host' path", name, i)
		}
		if m.Container == "" {
			return fmt.Errorf("profile '%s': mount[%d] is missing 'container' path", name, i)
		}
	}

	// Validate credential entries: exactly one of bundle or host+container.
	for i, cr := range p.Credentials {
		hasBundle := cr.Bundle != ""
		hasAdHoc := cr.Host != "" || cr.Container != ""
		if hasBundle && hasAdHoc {
			return fmt.Errorf("profile '%s': credentials[%d] must set either 'bundle' or 'host'+'container', not both", name, i)
		}
		if !hasBundle && !hasAdHoc {
			return fmt.Errorf("profile '%s': credentials[%d] must set either 'bundle' or 'host'+'container'", name, i)
		}
		if hasAdHoc {
			if cr.Host == "" {
				return fmt.Errorf("profile '%s': credentials[%d] is missing 'host' path", name, i)
			}
			if cr.Container == "" {
				return fmt.Errorf("profile '%s': credentials[%d] is missing 'container' path", name, i)
			}
		}
		if cr.Mode != "" {
			if _, err := strconv.ParseUint(cr.Mode, 8, 32); err != nil {
				return fmt.Errorf("profile '%s': credentials[%d] has invalid 'mode' %q (must be an octal file mode, e.g. \"0600\"): %w", name, i, cr.Mode, err)
			}
		}
	}

	// Validate port entries
	var portEntries []PortEntry
	if p.Ports != nil {
		if p.Ports.Pool < 0 || p.Ports.Pool > 10 {
			return fmt.Errorf("profile '%s': [ports] pool must be 0-10, got %d", name, p.Ports.Pool)
		}
		portEntries = p.Ports.Map
	}
	if err := validatePortEntries(portEntries); err != nil {
		return fmt.Errorf("profile '%s': %w", name, err)
	}

	// Validate network mode if set
	if p.Network != nil && p.Network.Mode != "" {
		switch p.Network.Mode {
		case "open", "restricted", "allowlist":
			// valid
		default:
			return fmt.Errorf("profile '%s': invalid network mode %q (must be open, restricted, or allowlist)", name, p.Network.Mode)
		}
	}

	// Validate [[network.hosts]] entries if set
	if p.Network != nil && len(p.Network.Hosts) > 0 {
		if err := ValidateNetworkHosts(p.Network.Hosts); err != nil {
			return fmt.Errorf("profile '%s': %w", name, err)
		}
	}

	return nil
}

// validatePortEntries checks [[ports.map]] entries: name required and unique,
// container port in range, optional host pin in range, listen a bare address
// if set.
func validatePortEntries(entries []PortEntry) error {
	seenNames := map[string]bool{}
	for i, pe := range entries {
		if pe.Name == "" {
			return fmt.Errorf("ports[%d] is missing 'name'", i)
		}
		if seenNames[pe.Name] {
			return fmt.Errorf("ports[%d] duplicates name %q", i, pe.Name)
		}
		seenNames[pe.Name] = true
		if pe.Container < 1 || pe.Container > 65535 {
			return fmt.Errorf("ports[%d] (%s) 'container' must be a TCP port (1-65535), got %d", i, pe.Name, pe.Container)
		}
		if pe.Host != 0 && (pe.Host < 1 || pe.Host > 65535) {
			return fmt.Errorf("ports[%d] (%s) 'host' must be a TCP port (1-65535) or omitted for auto-allocation, got %d", i, pe.Name, pe.Host)
		}
		if pe.Listen != "" && net.ParseIP(pe.Listen) == nil {
			return fmt.Errorf("ports[%d] (%s) 'listen' must be an IP address (e.g. \"127.0.0.1\"), got %q", i, pe.Name, pe.Listen)
		}
	}
	return nil
}
