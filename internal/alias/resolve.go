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
	Slot      int // >0 if the argument was split into alias + slot (e.g. "myproject-2")
}

// containerNamePattern matches the deterministic container name format: <prefix><hex8>-<digits>
var containerNamePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(session.GetContainerPrefix()) + `[a-f0-9]{8}-\d+$`)

// IsContainerName returns true if the argument looks like a container name
// (either exact match or starts with the container prefix) and is not a
// registered alias.
func IsContainerName(arg string) bool {
	if !containerNamePattern.MatchString(arg) && !strings.HasPrefix(arg, session.GetContainerPrefix()) {
		return false
	}
	return !hasRegisteredAliasFor(arg)
}

// ResolveAliasForRunning resolves an alias (or alias-N) to a running container name.
// If the arg is an exact container name, it is returned unchanged. A name
// with the container prefix is an alias only when it, or its alias part
// before a slot suffix, is registered and no container has that exact name.
// Errors if the alias matches 0 or >1 running containers (listing them for disambiguation).
func ResolveAliasForRunning(arg string) (string, error) {
	return resolveAlias(arg, runningMatch)
}

// ResolveAliasForFrozen resolves an alias (or alias-N) to a frozen container
// name, like ResolveAliasForRunning. When no frozen container has the alias,
// it resolves to a running one, so the caller can report it is not frozen.
func ResolveAliasForFrozen(arg string) (string, error) {
	return resolveAlias(arg, frozenMatch, runningMatch)
}

// statusMatch accepts container statuses; state names them in errors.
type statusMatch struct {
	state string
	match func(status string) bool
}

var (
	runningMatch = statusMatch{"running", container.StatusIsRunning}
	frozenMatch  = statusMatch{"frozen", container.StatusIsFrozen}
)

// resolveAlias resolves arg to a container whose status matches. matches are
// tried in order: the first that accepts a container with the alias wins.
func resolveAlias(arg string, matches ...statusMatch) (string, error) {
	// 1. Container name that is no registered alias → pass through
	if IsContainerName(arg) {
		return arg, nil
	}

	// 2. Exact name of an existing container → that container
	all, err := coiContainers()
	if err != nil {
		return "", fmt.Errorf("failed to find containers by alias: %w", err)
	}
	if all.has(arg) {
		return arg, nil
	}

	// 3. Try the whole argument as an alias. Split a slot suffix (alias-N,
	// N > 0) only when no matching container has that alias and no
	// registered alias has that name.
	alias, slotNum := arg, 0
	containers, state := all.withAlias(alias, matches)
	if len(containers) == 0 && !mayBeRegisteredAlias(arg) {
		if a, s := splitAliasSlot(arg); s > 0 {
			alias, slotNum = a, s
			containers, state = all.withAlias(alias, matches)
		}
	}

	if len(containers) == 0 {
		return "", fmt.Errorf("container or alias %q not found — no %s container matches", alias, matches[0].state)
	}

	// If a slot suffix was given, filter to matching slot. The slot names
	// one container, so every match counts, not only the first one.
	if slotNum > 0 {
		for _, c := range all {
			if c.alias != alias || !c.matchesAny(matches) {
				continue
			}
			if _, s, err := session.ParseContainerName(c.name); err == nil && s == slotNum {
				return c.name, nil
			}
		}
		return "", fmt.Errorf("container or alias %q not found at slot %d", alias, slotNum)
	}

	// No slot suffix — must be exactly one match
	if len(containers) == 1 {
		return containers[0], nil
	}

	return "", fmt.Errorf("alias %q matches %d %s containers — specify a slot suffix to disambiguate:\n  %s",
		alias, len(containers), state, strings.Join(containers, "\n  "))
}

// ResolveAliasForLaunch looks up the alias registry to find the workspace and profile.
// Returns an error if the alias is not found in the registry.
func ResolveAliasForLaunch(arg string) (*ResolvedAlias, error) {
	reg, err := Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load alias registry: %w", err)
	}

	cwd, cwdErr := os.Getwd()
	projectAlias := ""
	if cwdErr == nil {
		projectAlias = loadProjectAlias(cwd)
	}

	// The whole argument wins; split a slot suffix (alias-N) only when no
	// alias has that name.
	alias, slotNum := arg, 0
	entry := reg.Lookup(alias)
	if entry == nil && projectAlias != arg {
		if a, s := splitAliasSlot(arg); s > 0 {
			alias, slotNum = a, s
			entry = reg.Lookup(alias)
		}
	}

	if entry == nil {
		// Fallback: check CWD project config for matching alias.
		// This handles the chicken-and-egg case where the user runs
		// `coi shell <alias> --profile X` before the alias has been registered.
		if cwdErr == nil {
			if projectAlias == alias {
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

// aliasedContainer is a Coi container, its status and its user.coi.alias value.
type aliasedContainer struct {
	name   string
	alias  string
	status string
}

// matchesAny reports whether any of matches accepts the container's status.
func (c aliasedContainer) matchesAny(matches []statusMatch) bool {
	for _, m := range matches {
		if m.match(c.status) {
			return true
		}
	}
	return false
}

type aliasedContainers []aliasedContainer

// withAlias returns the names of the containers whose alias is alias and
// whose status the first of matches that accepts any of them accepts, and
// that match's state.
func (cs aliasedContainers) withAlias(alias string, matches []statusMatch) ([]string, string) {
	for _, m := range matches {
		var names []string
		for _, c := range cs {
			if c.alias == alias && m.match(c.status) {
				names = append(names, c.name)
			}
		}
		if len(names) > 0 {
			return names, m.state
		}
	}
	return nil, ""
}

// has reports whether a container of any status is named name.
func (cs aliasedContainers) has(name string) bool {
	for _, c := range cs {
		if c.name == name {
			return true
		}
	}
	return false
}

// coiContainers lists Coi containers with their aliases in one Incus call.
func coiContainers() (aliasedContainers, error) {
	output, err := container.IncusOutput("list", session.ContainerPattern(), "--format=json")
	if err != nil {
		return nil, err
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}

	var all aliasedContainers
	for _, c := range containers {
		name, _ := c["name"].(string)
		status, _ := c["status"].(string)
		cfg, _ := c["config"].(map[string]interface{})
		containerAlias, _ := cfg["user.coi.alias"].(string)

		all = append(all, aliasedContainer{
			name:   name,
			alias:  containerAlias,
			status: status,
		})
	}

	return all, nil
}

// hasRegisteredAliasFor reports whether the alias registry has an entry named
// arg, or named its alias part when arg ends in a slot suffix. An unreadable
// registry has none, so container names keep passing through.
func hasRegisteredAliasFor(arg string) bool {
	reg, err := Load()
	if err != nil {
		return false
	}
	if reg.Lookup(arg) != nil {
		return true
	}
	a, s := splitAliasSlot(arg)
	return s > 0 && reg.Lookup(a) != nil
}

// mayBeRegisteredAlias reports whether the alias registry has an entry named
// alias. An unreadable registry counts as an entry, so a load error never
// lets the slot split pick another workspace's container.
func mayBeRegisteredAlias(alias string) bool {
	reg, err := Load()
	return err != nil || reg.Lookup(alias) != nil
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
