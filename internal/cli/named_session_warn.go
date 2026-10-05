package cli

import (
	"fmt"
	"os"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/session"
)

// warnNamedSessionFork tells the user when a launch of a NAMED session lands
// on a fresh slot while the name already has containers on other slots — for
// a path-keyed workspace that is ordinary parallel-session behavior, but for
// a named session it FORKS the identity into a container with none of the
// session's state. The message distinguishes a merely-existing (stopped)
// container from an actively running one so the suggested remedy is real.
func warnNamedSessionFork(workspacePath, sessionName string, allocatedSlot int) {
	if sessionName == "" {
		return
	}
	others, err := session.ListWorkspaceSessions(workspacePath, sessionName)
	if err != nil {
		return
	}
	delete(others, allocatedSlot)
	if len(others) == 0 {
		return
	}
	for slot, name := range others {
		state := "a stopped"
		remedy := fmt.Sprintf("reuse it with --slot %d or --resume", slot)
		if running, err := container.ContainerRunning(name); err == nil && running {
			state = "a RUNNING"
			remedy = fmt.Sprintf("attach to it (coi attach --slot %d) or stop it first", slot)
		}
		fmt.Fprintf(os.Stderr,
			"Warning: named session %q already has %s container on slot %d; this launch creates a NEW container (slot %d) with none of that session's state — %s.\n",
			sessionName, state, slot, allocatedSlot, remedy)
	}
}
