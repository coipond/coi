// Package credentials holds the embedded catalog of named credential
// bundles: which host config directory and files to copy into a container
// for a given tool or third-party provider. Builtin AI tools (claude,
// opencode, pi) source their ToolWithConfigDirFiles metadata from here;
// profile [[credentials]] entries can reference any bundle by name.
package credentials

import (
	_ "embed"
	"fmt"
	"path"
	"sort"

	"github.com/BurntSushi/toml"
)

//go:embed catalog.toml
var catalogTOML string

// Bundle describes a named, coi-known set of host credential files: which
// directory they live in on both host and container (relative to the
// respective home directory), which files to copy, and how to treat them
// once copied.
type Bundle struct {
	ConfigDir           string   `toml:"config_dir"`
	Files               []string `toml:"files"`
	SecretFiles         []string `toml:"secret_files"`
	StateFile           string   `toml:"state_file"`
	SandboxSettingsFile string   `toml:"sandbox_settings_file"`
	AlwaysSetup         bool     `toml:"always_setup"`
	AutoContextFile     string   `toml:"auto_context_file"`
	Mode                string   `toml:"mode"`
	// KeychainService/KeychainFile describe a credential that, on macOS, the
	// tool keeps in the login Keychain rather than on disk (e.g. Claude Code's
	// "Claude Code-credentials" item instead of ~/.claude/.credentials.json).
	// coi runs in the Linux guest VM and can't read the Keychain, so it uses
	// these to hint the user how to materialize it on the Mac (#818). Empty for
	// tools without a Keychain-backed credential.
	KeychainService string `toml:"keychain_service"`
	KeychainFile    string `toml:"keychain_file"`
}

var catalog map[string]Bundle

func init() {
	if _, err := toml.Decode(catalogTOML, &catalog); err != nil {
		panic(fmt.Sprintf("credentials: embedded catalog.toml is invalid: %v", err))
	}
}

// Lookup returns the named bundle and whether it exists in the catalog.
func Lookup(name string) (Bundle, bool) {
	b, ok := catalog[name]
	return b, ok
}

// Names returns the sorted list of known bundle names, for error messages.
func Names() []string {
	names := make([]string, 0, len(catalog))
	for n := range catalog {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SecretPaths returns the home-relative paths of every bundle's secret
// files, sorted and without duplicates.
func SecretPaths() []string {
	seen := make(map[string]bool)
	var paths []string
	for _, b := range catalog {
		for _, f := range b.SecretFiles {
			p := path.Join(b.ConfigDir, f)
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)
	return paths
}
