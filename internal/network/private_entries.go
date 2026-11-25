package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/coipond/coi/internal/config"
)

// metadataCIDR is the link-local range holding the cloud metadata endpoint,
// rejected under block_metadata_endpoint.
const metadataCIDR = "169.254.0.0/16"

// allowlistPrivateCIDRs are the ranges allowlist mode rejects ahead of its
// allowed_domains accepts unless allow_local_network_access is set
// (metadataCIDR also under block_metadata_endpoint).
var allowlistPrivateCIDRs = append(config.PrivateNetworkCIDRs(), metadataCIDR)

// blockedEntry is an allowed_domains literal entry the forward chain rejects,
// wholly or in part.
type blockedEntry struct {
	Entry    string
	Private  bool // overlaps a private range, not only metadataCIDR
	Metadata bool // overlaps metadataCIDR
}

// blockedPrivateEntries returns the tuples that overlap allowlistPrivateCIDRs,
// leaving out the addresses in skip.
func blockedPrivateEntries(tuples []staticTuple, skip map[string]bool) []blockedEntry {
	var entries []blockedEntry
	for _, t := range tuples {
		ip := strings.TrimSuffix(t.CIDR, "/32")
		if skip[ip] {
			continue
		}
		_, entryNet, err := net.ParseCIDR(t.CIDR)
		if err != nil {
			continue
		}
		var private, metadata bool
		for _, cidr := range allowlistPrivateCIDRs {
			_, privNet, _ := net.ParseCIDR(cidr)
			if entryNet.Contains(privNet.IP) || privNet.Contains(entryNet.IP) {
				if cidr == metadataCIDR {
					metadata = true
				} else {
					private = true
				}
			}
		}
		if private || metadata {
			entries = append(entries, blockedEntry{Entry: ip, Private: private, Metadata: metadata})
		}
	}
	return entries
}

// AllowlistPrivateWarnings returns one warning per allowed_domains IP/CIDR
// entry that allowlist mode blocks because it overlaps a private range and
// allow_local_network_access is off, or overlaps metadataCIDR and
// block_metadata_endpoint is on. Left out: an address of the host (the
// input chain opens it, allowlistHostAccepts) and an address that private
// [[network.hosts]] entries open on all of the entry's ports
// (applyHostFirewall). Callers show the warnings: the package logger is a
// session log file or discarded.
func AllowlistPrivateWarnings(cfg *config.NetworkConfig) []string {
	local := config.BoolVal(cfg.AllowLocalNetworkAccess)
	if cfg.Mode != config.NetworkModeAllowlist || (local && !config.BoolVal(cfg.BlockMetadataEndpoint)) {
		return nil
	}
	policy, err := NewAllowPolicy(cfg.AllowedDomains)
	if err != nil {
		return nil // setupAllowlist reports it
	}
	globalPorts := intsToPortRanges(cfg.AllowedPorts)
	hostPorts := make(map[string][]portRange)
	for _, h := range cfg.Hosts {
		if classifyHostIP(h.IP) == hostPrivate {
			hostPorts[h.IP] = append(hostPorts[h.IP], resolvePorts(intsToPortRanges(h.Ports), globalPorts)...)
		}
	}
	skip := hostIPv4Addrs()
	for _, t := range policy.staticTuples() {
		ip := strings.TrimSuffix(t.CIDR, "/32")
		if opened, ok := hostPorts[ip]; ok && portsCover(opened, resolvePorts(t.Ports, globalPorts)) {
			skip[ip] = true
		}
	}
	var warnings []string
	for _, b := range blockedPrivateEntries(policy.staticTuples(), skip) {
		if local && !b.Metadata {
			continue
		}
		if b.Private && !local {
			warnings = append(warnings, fmt.Sprintf("Warning: allowed_domains entry %s is in a private range, which allowlist mode blocks; "+
				"set network.allow_local_network_access = true (opens the whole LAN), "+
				"or reach one service with a [[network.hosts]] entry and its ports", b.Entry))
			continue
		}
		warnings = append(warnings, fmt.Sprintf("Warning: allowed_domains entry %s is in the link-local range 169.254.0.0/16, "+
			"which allowlist mode blocks; only network.allow_local_network_access = true "+
			"with network.block_metadata_endpoint = false opens it (and the whole LAN)", b.Entry))
	}
	return warnings
}

// portsCover reports whether the ranges in have cover every port in want.
func portsCover(have, want []portRange) bool {
	for _, w := range want {
		next := int(w.Lo)
		for moved := true; moved && next <= int(w.Hi); {
			moved = false
			for _, h := range have {
				if int(h.Lo) <= next && next <= int(h.Hi) {
					next = int(h.Hi) + 1
					moved = true
				}
			}
		}
		if next <= int(w.Hi) {
			return false
		}
	}
	return true
}
