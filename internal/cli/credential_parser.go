package cli

import (
	"fmt"
	"path/filepath"

	"github.com/mensfeld/coi/internal/config"
	"github.com/mensfeld/coi/internal/session"
	"github.com/mensfeld/coi/internal/tool/credentials"
)

// ParseCredentialConfig creates a CredentialConfig from config file
// [[credentials]] entries. A bundle reference (entry.Bundle != "") expands
// into one session.CredentialEntry per file in the bundle, plus its state
// file if any (rooted at the container home directory rather than under the
// bundle's config dir, matching StateConfigFileName's existing semantics). An
// ad-hoc entry expands into exactly one session.CredentialEntry with an
// absolute container path, used as-is (like ParseMountConfig).
func ParseCredentialConfig(cfg *config.Config) (*session.CredentialConfig, error) {
	cc := &session.CredentialConfig{Entries: []session.CredentialEntry{}}

	for i, entry := range cfg.Credentials {
		if entry.Bundle != "" {
			bundle, ok := credentials.Lookup(entry.Bundle)
			if !ok {
				return nil, fmt.Errorf("credentials[%d]: unknown bundle %q (known bundles: %v)", i, entry.Bundle, credentials.Names())
			}
			for _, filename := range bundle.Files {
				cc.Entries = append(cc.Entries, session.CredentialEntry{
					HostPath:      config.ExpandPath(filepath.Join("~", bundle.ConfigDir, filename)),
					ContainerPath: filepath.Join(bundle.ConfigDir, filename),
					Mode:          bundle.Mode,
					BundleName:    entry.Bundle,
				})
			}
			if bundle.StateFile != "" {
				cc.Entries = append(cc.Entries, session.CredentialEntry{
					HostPath:      config.ExpandPath(filepath.Join("~", bundle.StateFile)),
					ContainerPath: bundle.StateFile,
					Mode:          bundle.Mode,
					BundleName:    entry.Bundle,
				})
			}
			continue
		}

		hostPath := config.ExpandPath(entry.Host)
		absHost, err := filepath.Abs(hostPath)
		if err != nil {
			return nil, fmt.Errorf("invalid credentials[%d] host path '%s': %w", i, entry.Host, err)
		}
		if !filepath.IsAbs(entry.Container) {
			return nil, fmt.Errorf("credentials[%d] container path must be absolute: %s", i, entry.Container)
		}
		cc.Entries = append(cc.Entries, session.CredentialEntry{
			HostPath:      absHost,
			ContainerPath: filepath.Clean(entry.Container),
			Mode:          entry.Mode,
			Untrusted:     entry.Untrusted,
			SourcePath:    entry.SourcePath,
		})
	}

	return cc, nil
}
