// Package config defines coi's configuration model and loads, merges and
// validates it from the embedded defaults, config files and profiles.
package config

import (
	"net"
	"regexp"
)

// hostnameRe matches a single DNS name (RFC1123-ish): dot-separated labels of
// letters/digits/hyphens, each 1–63 chars and not starting/ending with a hyphen.
var hostnameRe = regexp.MustCompile(
	`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// DefaultShutdownTimeoutSeconds is the graceful-shutdown window applied when
// [container] shutdown_timeout is unset — the single source for every
// consumer (coi shutdown, session cleanup's wait for an in-flight poweroff).
const DefaultShutdownTimeoutSeconds = 60

const (
	// NetworkModeRestricted blocks local/internal networks, allows internet
	NetworkModeRestricted NetworkMode = "restricted"
	// NetworkModeOpen allows all network access but the metadata range under
	// block_metadata_endpoint
	NetworkModeOpen NetworkMode = "open"
	// NetworkModeAllowlist allows only specific domains; private and metadata
	// ranges stay blocked unless allow_local_network_access is set (metadata
	// also under block_metadata_endpoint)
	NetworkModeAllowlist NetworkMode = "allowlist"
)

// ToolMemory is the [tool] memory setting: whether a new session in a reused
// persistent container keeps the tool's conversation history and memory files
// from earlier sessions.
type ToolMemory string

const (
	// ToolMemoryKeep keeps the tool's memory files (the default).
	ToolMemoryKeep ToolMemory = "keep"
	// ToolMemoryFresh removes them before a new (not resumed) session.
	ToolMemoryFresh ToolMemory = "fresh"
)

// PrivateNetworkCIDRs returns the private ranges restricted and allowlist mode
// block unless allow_local_network_access is set: RFC1918 and the RFC 6598
// shared address space 100.64.0.0/10 (CGNAT; Tailscale, Headscale and NetBird
// number their peers there).
func PrivateNetworkCIDRs() []string {
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
}

// privateNetworks is PrivateNetworkCIDRs parsed once: the security monitors
// ask for every connection.
var privateNetworks = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range PrivateNetworkCIDRs() {
		_, n, _ := net.ParseCIDR(cidr)
		nets = append(nets, n)
	}
	return nets
}()

// IsPrivateNetworkIP reports whether ipStr is an address in
// PrivateNetworkCIDRs. An unparseable address is not.
func IsPrivateNetworkIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// HardenedProfileSecretPaths is the default secret-mask set bundled by the
// built-in "hardened" profile. Exported so docs/tests can reference one source.
var HardenedProfileSecretPaths = []string{
	// Generic env / key material
	".env", "*.pem", "*.key", "*.p12", "id_rsa", "id_ed25519",
	// Credential / config files that commonly carry secrets in a repo
	".npmrc", ".netrc", ".git-credentials",
	"credentials.json", "service_account.json", "kubeconfig", "database.yml",
	// Terraform state/vars (frequently contain plaintext secrets)
	"*.tfvars", "*.tfstate",
	// Catch-all secret dir
	"secrets/**",
}

// HardenedProfileAllowedDomains is the allowed_domains set bundled by the
// built-in "hardened" profile: the package registries and code hosts an agent
// needs to install dependencies and fetch code. The configured tool's
// api_domains (internal/tool/credentials/catalog.toml) are added to it. A
// profile that inherits "hardened" and sets allowed_domains replaces the list,
// so it lists these hosts again with its own.
var HardenedProfileAllowedDomains = []string{
	// Ruby
	"rubygems.org", "index.rubygems.org",
	// JavaScript
	"registry.npmjs.org",
	// Python
	"pypi.org", "files.pythonhosted.org",
	// Go
	"proxy.golang.org", "sum.golang.org",
	// GitHub
	"github.com", "codeload.github.com", "objects.githubusercontent.com",
	"raw.githubusercontent.com",
}

// maxInheritanceDepth is the maximum allowed inheritance chain depth
const maxInheritanceDepth = 10
