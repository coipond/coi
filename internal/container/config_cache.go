package container

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Instance config read cache.
//
// A launch reads the same container's config many times in a row — workspace
// device source/path, the five kernel-surface keys (local and expanded),
// raw.idmap, env markers, the device list — each as its own `incus config
// get`/`config device get` subprocess (~50-150 ms apiece). The cache answers
// those reads from ONE `incus config show [--expanded]` per container.
//
// Correctness rules:
//   - Any incus command that is not a known read-only one drops the whole
//     cache before it runs (runIncus/outputIncus), so a read after a write
//     always goes to Incus. Writes made by other processes are bounded by a
//     short TTL.
//   - Only exact, simple argv shapes are answered; anything else (and any
//     read the cache cannot answer, e.g. a device that doesn't exist, so the
//     caller still gets Incus's real error) goes to Incus.
const configCacheTTL = 10 * time.Second

type cachedInstanceConfig struct {
	at      time.Time
	config  map[string]string
	devices map[string]map[string]string
}

var (
	configCacheMu sync.Mutex
	configCache   = map[string]*cachedInstanceConfig{} // key: name + "\x00" + expanded
	// configCacheGen is bumped by every invalidation (before AND after each
	// write). A load stores its result only if no invalidation happened while
	// it ran, so a read racing a write can never cache the pre-write state.
	configCacheGen uint64
)

func configCacheKey(name string, expanded bool) string {
	if expanded {
		return name + "\x00expanded"
	}
	return name + "\x00local"
}

// invalidateConfigCache drops every cached instance config.
func invalidateConfigCache() {
	configCacheMu.Lock()
	configCache = map[string]*cachedInstanceConfig{}
	configCacheGen++
	configCacheMu.Unlock()
}

// readOnlyIncusVerbs are incus subcommands that never change instance config
// or devices, so they don't invalidate the cache. `exec` and `file` change
// the guest filesystem, not the instance config.
var readOnlyIncusVerbs = map[string]bool{
	"list": true, "info": true, "version": true, "exec": true, "file": true,
	"monitor": true, "console": true, "export": true,
}

// incusArgsAreReadOnly reports whether argv (without the "--project X"
// prefix) is a command that cannot change any instance's config.
func incusArgsAreReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if readOnlyIncusVerbs[args[0]] {
		return true
	}
	if len(args) >= 2 {
		switch args[0] {
		case "config":
			switch args[1] {
			case "get", "show":
				return true
			case "device":
				return len(args) >= 3 && (args[2] == "get" || args[2] == "list" || args[2] == "show")
			}
		case "image", "network", "profile", "storage", "project", "snapshot", "remote", "cluster", "operation", "warning":
			switch args[1] {
			case "list", "show", "get", "info":
				return true
			}
		}
	}
	return false
}

// noteIncusCommand drops the cache before a command that may change config
// and returns the function to call once it finished (which drops it again).
// argv is the full argv including the "--project X" prefix (or not).
func noteIncusCommand(argv []string) (done func()) {
	args := argv
	if len(args) >= 2 && args[0] == "--project" {
		args = args[2:]
	}
	if incusArgsAreReadOnly(args) {
		return func() {}
	}
	invalidateConfigCache()
	return invalidateConfigCache
}

// loadInstanceConfig returns the (cached) config and devices of name.
func loadInstanceConfig(ctx context.Context, name string, expanded bool) (*cachedInstanceConfig, bool) {
	key := configCacheKey(name, expanded)
	configCacheMu.Lock()
	c, ok := configCache[key]
	gen := configCacheGen
	configCacheMu.Unlock()
	if ok && time.Since(c.at) < configCacheTTL {
		return c, true
	}

	args := []string{"config", "show"}
	if expanded {
		args = append(args, "--expanded")
	}
	out, err := incusOutputUncached(ctx, append(args, name)...)
	if err != nil {
		return nil, false
	}
	var parsed struct {
		Config  map[string]string            `yaml:"config"`
		Devices map[string]map[string]string `yaml:"devices"`
	}
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil || (parsed.Config == nil && parsed.Devices == nil) {
		return nil, false // unparseable or not an instance config: let Incus answer
	}
	c = &cachedInstanceConfig{at: time.Now(), config: parsed.Config, devices: parsed.Devices}
	configCacheMu.Lock()
	if configCacheGen == gen {
		configCache[key] = c
	}
	configCacheMu.Unlock()
	return c, true
}

// cachedConfigRead answers a simple config read from the cache. handled is
// false when the read must go to Incus.
func cachedConfigRead(ctx context.Context, args []string) (out string, handled bool) {
	switch {
	// config get [--expanded] NAME KEY
	case len(args) == 4 && args[0] == "config" && args[1] == "get" && !strings.HasPrefix(args[2], "-") && !strings.HasPrefix(args[3], "-"):
		return cachedConfigValue(ctx, args[2], args[3], false)
	case len(args) == 5 && args[0] == "config" && args[1] == "get" && args[2] == "--expanded":
		return cachedConfigValue(ctx, args[3], args[4], true)
	// config device get NAME DEVICE KEY
	case len(args) == 6 && args[0] == "config" && args[1] == "device" && args[2] == "get":
		c, ok := loadInstanceConfig(ctx, args[3], false)
		if !ok {
			return "", false
		}
		dev, ok := c.devices[args[4]]
		if !ok {
			return "", false // let Incus produce the real "device doesn't exist" error
		}
		return strings.TrimSpace(dev[args[5]]), true
	// config device list NAME
	case len(args) == 4 && args[0] == "config" && args[1] == "device" && args[2] == "list":
		c, ok := loadInstanceConfig(ctx, args[3], false)
		if !ok {
			return "", false
		}
		names := make([]string, 0, len(c.devices))
		for n := range c.devices {
			names = append(names, n)
		}
		sort.Strings(names)
		return strings.Join(names, "\n"), true
	}
	return "", false
}

func cachedConfigValue(ctx context.Context, name, key string, expanded bool) (string, bool) {
	c, ok := loadInstanceConfig(ctx, name, expanded)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(c.config[key]), true
}

// InstanceDevices returns the instance's own (non-profile) devices and their
// config, from the cache when fresh.
func InstanceDevices(name string) (map[string]map[string]string, error) {
	c, ok := loadInstanceConfig(context.Background(), name, false)
	if !ok {
		out, err := incusOutputUncached(context.Background(), "config", "show", name)
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Devices map[string]map[string]string `yaml:"devices"`
		}
		if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
			return nil, err
		}
		return parsed.Devices, nil
	}
	out := make(map[string]map[string]string, len(c.devices))
	for k, v := range c.devices {
		out[k] = v
	}
	return out, nil
}
