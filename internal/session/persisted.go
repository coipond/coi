package session

import (
	"context"
	"fmt"

	"github.com/coipond/coi/internal/container"
)

// ContainerMarkedPersistent reports whether the container's
// user.coi.persistent key is "true". `coi persist` sets it while a session
// runs, so session ends and later launches read it instead of trusting the
// persistence decided at launch. false when Incus cannot answer.
func ContainerMarkedPersistent(name string) bool {
	v, err := container.ConfigGetUncached(context.Background(), name, PersistentConfigKey)
	return err == nil && v == "true"
}

// AllocateSlotPreferPersisted is AllocateSlot that first returns the lowest
// slot whose container for the identity is stopped and marked persistent
// (see ContainerMarkedPersistent), with persisted=true, so a launch restarts
// a container kept by `coi persist` instead of forking a fresh slot. It
// lists instances once; the key is read only for stopped containers.
func AllocateSlotPreferPersisted(workspacePath, sessionName string, maxSlots int) (slot int, persisted bool, err error) {
	if maxSlots == 0 {
		maxSlots = MaxSlots
	}
	instances, err := listSlotInstances()
	if err != nil {
		return 0, false, err
	}
	re := slotNameRegexp(workspacePath, sessionName)
	used := make(map[int]bool)
	stopped := make(map[int]bool)
	for _, c := range instances {
		if n, ok := slotOf(re, c.Name); ok {
			used[n] = true
			if container.StatusIsStopped(c.Status) {
				stopped[n] = true
			}
		}
	}
	for n := 1; n <= maxSlots; n++ {
		if stopped[n] && ContainerMarkedPersistent(ContainerName(workspacePath, sessionName, n)) {
			return n, true, nil
		}
	}
	for n := 1; n <= maxSlots; n++ {
		if !used[n] {
			return n, false, nil
		}
	}
	return 0, false, fmt.Errorf("all %d slots are in use", maxSlots)
}
