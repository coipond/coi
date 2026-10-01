// Package config defines coi's configuration model and loads, merges and
// validates it from the embedded defaults, config files and profiles.
package config

import (
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
	// NetworkModeOpen allows all network access (current behavior)
	NetworkModeOpen NetworkMode = "open"
	// NetworkModeAllowlist allows only specific domains (with RFC1918 always blocked)
	NetworkModeAllowlist NetworkMode = "allowlist"
)

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

// maxInheritanceDepth is the maximum allowed inheritance chain depth
const maxInheritanceDepth = 10
