package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/coipond/coi/internal/config"
)

// IPCache stores resolved domain IPs with timestamp
type IPCache struct {
	Domains    map[string][]string `json:"domains"`
	TTLs       map[string]uint32   `json:"ttls,omitempty"`
	LastUpdate time.Time           `json:"last_update"`
}

// CacheManager handles persistent IP cache storage
type CacheManager struct {
	cacheDir string
}

// NewCacheManager creates a new cache manager
func NewCacheManager(baseDir string) *CacheManager {
	return &CacheManager{
		cacheDir: filepath.Join(baseDir, ".coi", "network-cache"),
	}
}

// defaultCacheManager is the cache manager under the user's home directory, or
// /tmp when it is unknown, as NewManager uses it.
func defaultCacheManager() *CacheManager {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}
	return NewCacheManager(homeDir)
}

// Load reads the IP cache for a container
func (c *CacheManager) Load(containerName string) (*IPCache, error) {
	cachePath := filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", containerName))

	data, err := os.ReadFile(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty cache if file doesn't exist
			return &IPCache{
				Domains:    make(map[string][]string),
				TTLs:       make(map[string]uint32),
				LastUpdate: time.Time{},
			}, nil
		}
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var cache IPCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to parse cache file: %w", err)
	}

	// Initialize maps if nil (backwards-compatible with old cache files)
	if cache.Domains == nil {
		cache.Domains = make(map[string][]string)
	}
	if cache.TTLs == nil {
		cache.TTLs = make(map[string]uint32)
	}

	return &cache, nil
}

// Save writes the IP cache for a container
func (c *CacheManager) Save(containerName string, cache *IPCache) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}
	return c.writeFile(fmt.Sprintf("%s.json", containerName), data)
}

// writeFile writes data to name in the cache directory (mode 0644), creating
// the directory. Temp file + rename: the refresher rewrites the IP cache while a
// launch of the same container may be reading it, and a monitor reads the host
// ports record while `coi hosts add` rewrites it; a plain WriteFile (truncate,
// then write) lets that reader see a torn file.
func (c *CacheManager) writeFile(name string, data []byte) error {
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(c.cacheDir, ".cache-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to chmod cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close cache file: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(c.cacheDir, name)); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	return nil
}

// hostPortsFile names a container's runtime host ports record: the
// `coi hosts add --ports` entries, so the monitors in the session's own coi
// process see those runtime permits. ClearRuntimeHostPorts removes it at every
// session setup, with the firewall it describes.
func hostPortsFile(containerName string) string {
	return containerName + ".host-ports.json"
}

// LoadHostPorts reads a container's runtime host ports record (nil when there
// is none).
func (c *CacheManager) LoadHostPorts(containerName string) ([]config.HostEntry, error) {
	data, err := os.ReadFile(filepath.Join(c.cacheDir, hostPortsFile(containerName)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read host ports record: %w", err)
	}
	var entries []config.HostEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse host ports record: %w", err)
	}
	return entries, nil
}

// SaveHostPorts writes a container's runtime host ports record.
func (c *CacheManager) SaveHostPorts(containerName string, entries []config.HostEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("failed to marshal host ports record: %w", err)
	}
	return c.writeFile(hostPortsFile(containerName), data)
}

// DeleteHostPorts removes a container's runtime host ports record.
func (c *CacheManager) DeleteHostPorts(containerName string) error {
	if err := os.Remove(filepath.Join(c.cacheDir, hostPortsFile(containerName))); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete host ports record: %w", err)
	}
	return nil
}

// Delete removes the cache file for a container
func (c *CacheManager) Delete(containerName string) error {
	cachePath := filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", containerName))

	if err := os.Remove(cachePath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to delete cache file: %w", err)
	}

	return nil
}
