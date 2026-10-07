package network

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
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
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	cachePath := filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", containerName))

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	// Temp file + rename: the refresher rewrites this while a launch of the same
	// container may be reading it, and a plain WriteFile (truncate, then write)
	// lets that reader see a torn file.
	tmp, err := os.CreateTemp(c.cacheDir, ".cache-*.json.tmp")
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
	if err := os.Rename(tmpName, cachePath); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
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
