package session

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// GetContainerPrefix returns the container prefix to use.
// Checks COI_CONTAINER_PREFIX environment variable first, defaults to "coi-".
// This allows tests to use a different prefix (e.g., "coi-test-") to avoid
// interfering with user's active sessions.
func GetContainerPrefix() string {
	if prefix := os.Getenv("COI_CONTAINER_PREFIX"); prefix != "" {
		return prefix
	}
	return "coi-"
}

// Identity returns the string every session-scoped resource is keyed on: the
// configured `[container] session_name` (namespaced so a name can never
// collide with a real path) when set, else the workspace's absolute path.
// A session name decouples the session from where its workspace lives — the
// same name resolves to the same container, slots, ports, and saved-session
// store from any workspace location.
func Identity(workspacePath, sessionName string) string {
	if sessionName != "" {
		return "session-name:" + sessionName
	}
	absPath, err := filepath.Abs(workspacePath)
	if err != nil {
		absPath = workspacePath
	}
	return absPath
}

// IdentityHash returns the first 8 hex characters of the SHA256 of the
// session identity — the key embedded in container names and used to scope
// slots, ports, and saved sessions.
func IdentityHash(workspacePath, sessionName string) string {
	hash := sha256.Sum256([]byte(Identity(workspacePath, sessionName)))
	return fmt.Sprintf("%x", hash)[:8]
}

// WorkspaceHash generates a short hash from the workspace path alone —
// IdentityHash without a session name. Kept for callers that key strictly by
// location (and for pre-session_name call sites).
func WorkspaceHash(workspacePath string) string {
	return IdentityHash(workspacePath, "")
}

// ContainerName generates a container name from the session identity and slot
// Format: <prefix><identity-hash>-<slot> where prefix defaults to "coi-"
// Can be customized via COI_CONTAINER_PREFIX environment variable
func ContainerName(workspacePath, sessionName string, slot int) string {
	hash := IdentityHash(workspacePath, sessionName)
	prefix := GetContainerPrefix()
	return fmt.Sprintf("%s%s-%d", prefix, hash, slot)
}

// slotInstance is one instance as seen by slot allocation: just its name and
// status, which is all the slot logic needs.
type slotInstance struct {
	Name   string
	Status string
}

// listSlotInstances lists instance names and statuses. It asks Incus for the
// name and status columns only (CSV), so the daemon skips the per-instance
// state fetch (network counters, processes, disk usage) that `--format=json`
// always pays for — that fetch grows with every container on the host and
// dominated launch latency. A variable so tests can stub Incus.
var listSlotInstances = func() ([]slotInstance, error) {
	output, err := container.IncusOutput("list", "--format=csv", "--columns=ns")
	if err != nil {
		return nil, err
	}
	return parseSlotInstancesCSV(output), nil
}

// parseSlotInstancesCSV parses `incus list --format=csv --columns=ns` output
// ("name,STATUS" per line). Instance names cannot contain commas.
func parseSlotInstancesCSV(output string) []slotInstance {
	var out []slotInstance
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, status, _ := strings.Cut(line, ",")
		out = append(out, slotInstance{Name: name, Status: status})
	}
	return out
}

// slotOf returns the slot number of an instance name for the given identity
// prefix, or (0, false) when the name is not one of that identity's slots.
func slotOf(re *regexp.Regexp, name string) (int, bool) {
	m := re.FindStringSubmatch(name)
	if len(m) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

func slotNameRegexp(workspacePath, sessionName string) *regexp.Regexp {
	prefix := fmt.Sprintf("%s%s-", GetContainerPrefix(), IdentityHash(workspacePath, sessionName))
	return regexp.MustCompile(fmt.Sprintf(`^%s(\d+)$`, regexp.QuoteMeta(prefix)))
}

// usedSlots lists the slots that have an instance (in any state) for the
// identity.
func usedSlots(workspacePath, sessionName string) (map[int]bool, error) {
	instances, err := listSlotInstances()
	if err != nil {
		return nil, err
	}
	re := slotNameRegexp(workspacePath, sessionName)
	used := make(map[int]bool)
	for _, c := range instances {
		if n, ok := slotOf(re, c.Name); ok {
			used[n] = true
		}
	}
	return used, nil
}

// AllocateSlot finds the next available slot for a session identity
// (workspace path, or session_name when set)
// Returns the slot number (1, 2, 3, ...) or 0 if no slots available
func AllocateSlot(workspacePath, sessionName string, maxSlots int) (int, error) {
	if maxSlots == 0 {
		maxSlots = 10 // Default max 10 parallel sessions
	}
	used, err := usedSlots(workspacePath, sessionName)
	if err != nil {
		return 0, err
	}
	for slot := 1; slot <= maxSlots; slot++ {
		if !used[slot] {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("all %d slots are in use", maxSlots)
}

// FindReusablePersistentSlot returns the lowest slot whose container for the
// workspace exists and is STOPPED — the natural reuse target for persistent
// mode. Without this, auto-allocation treats the stopped persistent container
// as occupying its slot and silently launches a fresh container on the next
// slot (state never persists, and slots exhaust after maxSlots runs).
// Running containers are never returned: they may belong to an active
// session, and parallel invocations should keep taking fresh slots.
// Returns (0, false) when no stopped container exists or listing fails.
func FindReusablePersistentSlot(workspacePath, sessionName string, maxSlots int) (int, bool) {
	if maxSlots == 0 {
		maxSlots = 10
	}
	instances, err := listSlotInstances()
	if err != nil {
		return 0, false
	}
	re := slotNameRegexp(workspacePath, sessionName)
	best := 0
	for _, c := range instances {
		if !container.StatusIsStopped(c.Status) {
			continue
		}
		if n, ok := slotOf(re, c.Name); ok && n >= 1 && n <= maxSlots {
			if best == 0 || n < best {
				best = n
			}
		}
	}
	return best, best != 0
}

// AllocateSlotFrom finds the next available slot starting from a specific slot number
// Returns the slot number or error if no slots available
func AllocateSlotFrom(workspacePath, sessionName string, startSlot, maxSlots int) (int, error) {
	if maxSlots == 0 {
		maxSlots = 10 // Default max 10 parallel sessions
	}
	used, err := usedSlots(workspacePath, sessionName)
	if err != nil {
		return 0, err
	}
	for slot := startSlot; slot <= maxSlots; slot++ {
		if !used[slot] {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("no available slots from %d to %d", startSlot, maxSlots)
}

// IsSlotAvailable checks if a specific slot is available
func IsSlotAvailable(workspacePath, sessionName string, slot int) (bool, error) {
	containerName := ContainerName(workspacePath, sessionName, slot)
	running, err := container.ContainerRunning(containerName)
	if err != nil {
		return false, err
	}
	return !running, nil
}

// ParseContainerName extracts workspace hash and slot from container name
// Returns (hash, slot, error)
func ParseContainerName(containerName string) (string, int, error) {
	prefix := regexp.QuoteMeta(GetContainerPrefix())
	re := regexp.MustCompile(fmt.Sprintf(`^%s([a-f0-9]{8})-(\d+)$`, prefix))
	matches := re.FindStringSubmatch(containerName)
	if len(matches) != 3 {
		return "", 0, fmt.Errorf("invalid container name format: %s", containerName)
	}

	hash := matches[1]
	slot, err := strconv.Atoi(matches[2])
	if err != nil {
		return "", 0, fmt.Errorf("invalid slot number in container name: %s", containerName)
	}

	return hash, slot, nil
}

// ListWorkspaceSessions lists all sessions for a session identity — the
// workspace path, or session_name when set (a named session's containers are
// found from ANY workspace location)
// Returns map of slot -> container name
func ListWorkspaceSessions(workspacePath, sessionName string) (map[int]string, error) {
	hash := IdentityHash(workspacePath, sessionName)
	prefix := fmt.Sprintf("%s%s-", GetContainerPrefix(), hash)

	output, err := container.IncusOutput("list", "--format=json")
	if err != nil {
		return nil, err
	}

	sessions := make(map[int]string)
	re := regexp.MustCompile(fmt.Sprintf(`^%s(\d+)$`, regexp.QuoteMeta(prefix)))

	// Parse JSON array of containers
	var containers []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		// Fallback: if JSON parsing fails, try regex on raw output
		nameMatches := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`).FindAllStringSubmatch(output, -1)
		for _, match := range nameMatches {
			if len(match) > 1 {
				containerName := match[1]
				if matches := re.FindStringSubmatch(containerName); len(matches) > 1 {
					if slotNum, err := strconv.Atoi(matches[1]); err == nil {
						sessions[slotNum] = containerName
					}
				}
			}
		}
	} else {
		for _, c := range containers {
			if matches := re.FindStringSubmatch(c.Name); len(matches) > 1 {
				if slotNum, err := strconv.Atoi(matches[1]); err == nil {
					sessions[slotNum] = c.Name
				}
			}
		}
	}

	return sessions, nil
}
