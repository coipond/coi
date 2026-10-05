package alias

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
)

// ResolvedAlias is the result of resolving an alias for launching a new session.
type ResolvedAlias struct {
	Workspace string
	Profile   string
	Slot      int // >0 if alias had a slot suffix (e.g. "myproject-2")
}

// containerNamePattern matches the deterministic container name format: <prefix><hex8>-<digits>
var containerNamePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(session.GetContainerPrefix()) + `[a-f0-9]{8}-\d+$`)

// IsContainerName returns true if the argument looks like a container name
// (either exact match or starts with the container prefix).
// Names starting with the container prefix are never treated as aliases.
func IsContainerName(arg string) bool {
	return containerNamePattern.MatchString(arg) || strings.HasPrefix(arg, session.GetContainerPrefix())
}

// ResolveAliasForRunning resolves an alias (or alias-N) to a running container name.
// If the arg is an exact container name, it is returned unchanged.
// Errors if the alias matches 0 or >1 running containers (listing them for disambiguation).
func ResolveAliasForRunning(arg string) (string, error) {
	// 1. Exact container name → pass through
	if IsContainerName(arg) {
		return arg, nil
	}

	// 2. Try alias with optional slot suffix
	alias, slotNum := splitAliasSlot(arg)

	containers, err := FindContainersByAlias(alias)
	if err != nil {
		return "", fmt.Errorf("failed to find containers by alias: %w", err)
	}

	if len(containers) == 0 {
		return "", fmt.Errorf("container or alias %q not found — no running container matches", alias)
	}

	// If a slot suffix was given, filter to matching slot
	if slotNum > 0 {
		for _, name := range containers {
			if _, s, err := session.ParseContainerName(name); err == nil && s == slotNum {
				return name, nil
			}
		}
		return "", fmt.Errorf("container or alias %q not found at slot %d", alias, slotNum)
	}

	// No slot suffix — must be exactly one match
	if len(containers) == 1 {
		return containers[0], nil
	}

	return "", fmt.Errorf("alias %q matches %d running containers — specify a slot suffix to disambiguate:\n  %s",
		alias, len(containers), strings.Join(containers, "\n  "))
}

// ResolveAliasForLaunch looks up the alias registry to find the workspace and profile.
// Returns an error if the alias is not found in the registry.
func ResolveAliasForLaunch(arg string) (*ResolvedAlias, error) {
	alias, slotNum := splitAliasSlot(arg)

	reg, err := Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load alias registry: %w", err)
	}

	entry := reg.Lookup(alias)
	if entry == nil {
		// Fallback: check CWD project config for matching alias.
		// This handles the chicken-and-egg case where the user runs
		// `coi shell <alias> --profile X` before the alias has been registered.
		cwd, cwdErr := os.Getwd()
		if cwdErr == nil {
			if projectAlias := loadProjectAlias(cwd); projectAlias == alias {
				absWorkspace, err := filepath.Abs(cwd)
				if err != nil {
					return nil, fmt.Errorf("failed to resolve workspace path for alias %q: %w", alias, err)
				}
				// Auto-register so subsequent lookups succeed.
				if err := reg.Register(alias, absWorkspace, ""); err != nil {
					return nil, fmt.Errorf("failed to auto-register alias %q: %w", alias, err)
				}
				if err := reg.Save(); err != nil {
					return nil, fmt.Errorf("failed to persist auto-registered alias %q: %w", alias, err)
				}
				return &ResolvedAlias{Workspace: absWorkspace, Slot: slotNum}, nil
			}
		}
		return nil, fmt.Errorf("alias %q not found — register it by adding [container] alias = %q to .coi/config.toml and running a session", alias, alias)
	}

	return &ResolvedAlias{
		Workspace: entry.Workspace,
		Profile:   entry.Profile,
		Slot:      slotNum,
	}, nil
}

// loadProjectAlias reads only the [container] alias field from a project's
// .coi/config.toml.  Returns "" if the file doesn't exist or has no alias.
func loadProjectAlias(dir string) string {
	var cfg struct {
		Container struct {
			Alias string `toml:"alias"`
		} `toml:"container"`
	}
	if _, err := toml.DecodeFile(filepath.Join(dir, ".coi", "config.toml"), &cfg); err != nil {
		return ""
	}
	return cfg.Container.Alias
}

// FindContainersByAlias queries Incus for Coi containers whose user.coi.alias
// config key matches the given alias.
func FindContainersByAlias(alias string) ([]string, error) {
	prefix := session.GetContainerPrefix()
	pattern := fmt.Sprintf("^%s", prefix)

	output, err := container.IncusOutput("list", pattern, "--format=json")
	if err != nil {
		return nil, err
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	var matches []string
	for _, c := range containers {
		name, _ := c["name"].(string)
		status, _ := c["status"].(string)

		// Only consider running containers
		if !container.StatusIsRunning(status) {
			continue
		}

		cfg, _ := c["config"].(map[string]interface{})
		containerAlias, _ := cfg["user.coi.alias"].(string)

		if containerAlias == alias {
			matches = append(matches, name)
		}
	}

	return matches, nil
}

// splitAliasSlot splits "myproject-2" into ("myproject", 2).
// If there is no numeric suffix, returns (arg, 0).
func splitAliasSlot(arg string) (string, int) {
	idx := strings.LastIndex(arg, "-")
	if idx <= 0 || idx == len(arg)-1 {
		return arg, 0
	}

	suffix := arg[idx+1:]
	slotNum, err := strconv.Atoi(suffix)
	if err != nil {
		return arg, 0
	}

	return arg[:idx], slotNum
}
