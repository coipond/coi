package session

import (
	"path/filepath"
	"slices"

	"github.com/coipond/coi/internal/tool"
)

// GetSessionsDir returns the sessions directory path for a given tool.
// For example: ~/.coi/sessions-claude, ~/.coi/sessions-aider, etc.
func GetSessionsDir(baseDir string, t tool.Tool) string {
	return filepath.Join(baseDir, t.SessionsDirName())
}

// AllSessionsDirs returns the sessions dir of every supported tool, without
// duplicates: the configured tool's first, so its save wins over a stale one
// of another tool for the same container name, then the rest by tool name.
func AllSessionsDirs(baseDir string, configured tool.Tool) []string {
	dirs := []string{GetSessionsDir(baseDir, configured)}
	for _, name := range tool.ListSupported() {
		t, err := tool.Get(name)
		if err != nil {
			continue
		}
		if dir := GetSessionsDir(baseDir, t); !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}
