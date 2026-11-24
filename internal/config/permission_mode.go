package config

import (
	"fmt"
	"slices"
	"strings"
)

// PermissionMode is the [tool] permission_mode setting.
type PermissionMode string

const (
	// PermissionModeBypass auto-grants the tool's permissions (the default).
	PermissionModeBypass PermissionMode = "bypass"
	// PermissionModeInteractive makes the tool ask the user.
	PermissionModeInteractive PermissionMode = "interactive"
)

// PermissionModes are the valid permission_mode values, as in the profile
// schema's enum (schema/defs/ToolConfig.json). Empty means unset.
var PermissionModes = []PermissionMode{PermissionModeBypass, PermissionModeInteractive}

// UnknownPermissionModeWarning returns a warning for a permission_mode that is
// not empty and not one of PermissionModes, or "" for a valid one. Profiles
// are schema-checked, config files are not; the tools run any value other
// than "interactive" as bypass.
func UnknownPermissionModeWarning(mode PermissionMode) string {
	if mode == "" || slices.Contains(PermissionModes, mode) {
		return ""
	}
	valid := make([]string, len(PermissionModes))
	for i, m := range PermissionModes {
		valid[i] = fmt.Sprintf("%q", m)
	}
	return fmt.Sprintf("Warning: [tool] permission_mode = %q is not valid (valid: %s); using %q",
		mode, strings.Join(valid, ", "), PermissionModeBypass)
}
