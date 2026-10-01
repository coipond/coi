package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// This file holds the pre-0.8.0 → 0.8.0 migration error machinery.
//
// As of 0.8.0, container-shape settings (image, persistent, storage_pool,
// build) live under the [container] section in both global config and
// profile config. The legacy locations:
//
//   - [defaults] image
//   - [defaults] persistent
//   - top-level [build] (in global config)
//   - root-level image / persistent / [build] (in profile config)
//
// are no longer accepted. We refuse to load files that still use them and
// emit an actionable error pointing at the new layout.
//
// Implementation: a "trap struct" is decoded from the same TOML file. Any
// non-zero field on the trap struct means a deprecated key was present. The
// trap struct is local to this file so the production schema in config.go
// stays free of dead fields. Remove this file when the deprecation window
// closes.

// deprecatedConfigFields catches pre-0.8.0 global config layouts.
type deprecatedConfigFields struct {
	Defaults struct {
		Image      string `toml:"image"`
		Persistent *bool  `toml:"persistent"`
	} `toml:"defaults"`
	Build deprecatedBuildField `toml:"build"` // root-level [build]
}

// deprecatedProfileFields catches pre-0.8.0 profile config layouts.
type deprecatedProfileFields struct {
	Image      string                `toml:"image"`
	Persistent *bool                 `toml:"persistent"`
	Build      *deprecatedBuildField `toml:"build"`
}

// deprecatedBuildField is a minimal stand-in used purely to detect that a
// [build] section was present. We don't care about its contents — only that
// the user hit it. Mirroring BuildConfig fields would couple this trap to
// the live schema; this lighter shape stays decoupled.
type deprecatedBuildField struct {
	Base     string   `toml:"base"`
	Script   string   `toml:"script"`
	Commands []string `toml:"commands"`
}

// isSet reports whether the trap saw any field set.
func (b deprecatedBuildField) isSet() bool {
	return b.Base != "" || b.Script != "" || len(b.Commands) > 0
}

// migrationDocURL points users to the wiki section that explains the new
// layout. Surfaced in every migration error so the fix is one click away.
const migrationDocURL = "https://github.com/coipond/coi/wiki/Configuration#container-section"

// checkDeprecatedConfigFields decodes a global-config file into the trap
// struct and returns a non-nil error if any pre-0.8.0 fields are present.
// All offending fields are reported in a single error so the user can fix
// them in one pass instead of running the loader N times.
func checkDeprecatedConfigFields(path string) error {
	var trap deprecatedConfigFields
	if _, err := toml.DecodeFile(path, &trap); err != nil {
		// Decoding errors are surfaced by the real loader; the trap is
		// best-effort and silent on parse failures.
		return nil
	}

	var problems []string
	if trap.Defaults.Image != "" {
		problems = append(problems, fmt.Sprintf(
			`  [defaults] image = %q is no longer supported in 0.8.0.
  Move it under [container]:

      [container]
      image = %q`,
			trap.Defaults.Image, trap.Defaults.Image))
	}
	if trap.Defaults.Persistent != nil {
		problems = append(problems, fmt.Sprintf(
			`  [defaults] persistent = %v is no longer supported in 0.8.0.
  Move it under [container]:

      [container]
      persistent = %v`,
			*trap.Defaults.Persistent, *trap.Defaults.Persistent))
	}
	if trap.Build.isSet() {
		problems = append(problems, `  Top-level [build] is no longer supported in 0.8.0.
  Move it under [container.build]:

      [container.build]
      base = "coi"
      script = "build.sh"`)
	}

	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("config error in %s:\n%s\n\nSee: %s",
		path, strings.Join(problems, "\n\n"), migrationDocURL)
}

// checkDeprecatedProfileFields decodes a profile config file into the
// profile trap struct and returns a non-nil error if any pre-0.8.0 root-level
// fields are present.
func checkDeprecatedProfileFields(path string) error {
	var trap deprecatedProfileFields
	if _, err := toml.DecodeFile(path, &trap); err != nil {
		return nil
	}

	var problems []string
	if trap.Image != "" {
		problems = append(problems, fmt.Sprintf(
			`  Root-level image = %q is no longer supported in 0.8.0.
  Move it under [container]:

      [container]
      image = %q`,
			trap.Image, trap.Image))
	}
	if trap.Persistent != nil {
		problems = append(problems, fmt.Sprintf(
			`  Root-level persistent = %v is no longer supported in 0.8.0.
  Move it under [container]:

      [container]
      persistent = %v`,
			*trap.Persistent, *trap.Persistent))
	}
	if trap.Build != nil && trap.Build.isSet() {
		problems = append(problems, `  Root-level [build] is no longer supported in 0.8.0.
  Move it under [container.build]:

      [container.build]
      base = "coi"
      script = "build.sh"`)
	}

	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("profile error in %s:\n%s\n\nSee: %s",
		path, strings.Join(problems, "\n\n"), migrationDocURL)
}
