// Package alias persists workspace aliases (alias -> workspace and optional
// profile) and resolves them to running or launchable containers.
package alias

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// AliasEntry maps an alias to a workspace and optional profile.
type AliasEntry struct {
	Workspace string `json:"workspace"`
	Profile   string `json:"profile,omitempty"`
}

// Registry persists alias → {workspace, profile} mappings in ~/.coi/aliases.json.
type Registry struct {
	mu      sync.Mutex
	path    string
	entries map[string]AliasEntry
}

// RegistryPath returns the default path to the alias registry file.
func RegistryPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	return filepath.Join(homeDir, ".coi", "aliases.json")
}

// Load reads the registry from disk, creating an empty one if the file does not exist.
func Load() (*Registry, error) {
	return LoadFrom(RegistryPath())
}

// LoadFrom reads the registry from a specific path.
func LoadFrom(path string) (*Registry, error) {
	r := &Registry{
		path:    path,
		entries: make(map[string]AliasEntry),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil // empty registry
		}
		return nil, fmt.Errorf("failed to read alias registry: %w", err)
	}

	if len(data) == 0 {
		return r, nil
	}

	if err := json.Unmarshal(data, &r.entries); err != nil {
		return nil, fmt.Errorf("failed to parse alias registry: %w", err)
	}

	return r, nil
}

// Register adds or updates an alias. It returns an error if the alias is
// already mapped to a different workspace (conflict).
func (r *Registry) Register(alias, workspace, profile string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.entries[alias]; ok {
		if existing.Workspace != workspace {
			return fmt.Errorf("alias %q is already registered to workspace %q (current request: %q)", alias, existing.Workspace, workspace)
		}
	}

	r.entries[alias] = AliasEntry{
		Workspace: workspace,
		Profile:   profile,
	}
	return nil
}

// Lookup returns the entry for an alias, or nil if not found.
func (r *Registry) Lookup(alias string) *AliasEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.entries[alias]; ok {
		return &entry
	}
	return nil
}

// Save writes the registry to disk atomically (temp file + rename).
func (r *Registry) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Ensure parent directory exists
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create registry directory: %w", err)
	}

	data, err := json.MarshalIndent(r.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal alias registry: %w", err)
	}

	// Atomic write: unique temp file + rename
	tmpFile, err := os.CreateTemp(dir, ".aliases-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file for alias registry: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write alias registry: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, r.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename alias registry: %w", err)
	}

	return nil
}

// aliasPattern matches valid aliases: starts with a letter, alphanumeric + hyphens/underscores, max 64 chars.
var aliasPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)

// ValidateAlias checks that an alias is well-formed.
func ValidateAlias(alias string) error {
	if alias == "" {
		return nil // empty is valid (means "no alias")
	}
	if len(alias) > 64 {
		return fmt.Errorf("alias %q is too long (max 64 characters)", alias)
	}
	if !aliasPattern.MatchString(alias) {
		return fmt.Errorf("alias %q is invalid: must start with a letter and contain only letters, digits, hyphens, and underscores", alias)
	}
	return nil
}
