package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// gitIdentityEnvMarkerKey records (comma-separated) which environment.* keys coi
// set for the locked git identity on the previous setup, so a later run can unset
// them when the lock is turned off or the identity changes. Kept SEPARATE from
// toolEnvMarkerKey so the two reconcilers never unset each other's keys (no
// tool's GetContainerEnv emits GIT_*).
const gitIdentityEnvMarkerKey = "user.coi.git_env_keys"

// ApplyGitIdentityContainerEnv is Layer 1 of the identity lock: it pins
// GIT_AUTHOR_*/GIT_COMMITTER_* as container-level `environment.*` config, which
// Incus injects into EVERY exec — coi's own `bash -c` tool launch (a non-login,
// non-interactive shell that sources no profile), and a third-party
// `coi container exec` alike. GIT_* env beats `user.*` config (including
// `git -c user.*`), so it defeats the common override without rewriting history.
// It is a default, not enforcement (the agent can re-export its own GIT_*), so
// the post-commit re-stamp hook (Layer 2) backstops it.
//
// Values derive from the resolved GitIdentity (single source). Reconciles via
// gitIdentityEnvMarkerKey exactly like applyToolContainerEnv: unset the keys when
// lock is off / identity incomplete, so a reused container converges. Non-fatal.
//
// NB: like all environment.* config, this only reaches execs started AFTER it is
// set. On a persistent-container reuse whose agent shell is already running, that
// shell's env is a stale snapshot and its git children won't see the new GIT_* —
// there the post-commit re-stamp hook (Layer 2) is the actual enforcer.
func ApplyGitIdentityContainerEnv(ctx context.Context, containerName string, id GitIdentity, lock bool, logger func(string)) {
	prevMarker, _ := container.ConfigGet(ctx, containerName, gitIdentityEnvMarkerKey)
	plan := planGitIdentityEnv(prevMarker, id, lock)

	for _, k := range plan.skipped {
		logger(fmt.Sprintf("Warning: skipping git identity env %s (unsafe value)", k))
	}
	for _, k := range plan.unset {
		_ = container.ConfigUnset(ctx, containerName, "environment."+k)
	}
	for _, k := range plan.setKeys {
		if err := container.ConfigSet(ctx, containerName, "environment."+k, plan.set[k]); err != nil {
			logger(fmt.Sprintf("Warning: failed to set git identity env %s: %v", k, err))
		}
	}
	switch {
	case plan.marker != "":
		if err := container.ConfigSet(ctx, containerName, gitIdentityEnvMarkerKey, plan.marker); err != nil {
			logger(fmt.Sprintf("Warning: failed to record git identity env marker: %v", err))
		}
	case prevMarker != "":
		_ = container.ConfigUnset(ctx, containerName, gitIdentityEnvMarkerKey)
	}
}

// planGitIdentityEnv is the pure decision core (unit-tested without Incus): it
// builds the desired GIT_* env — the four keys when the identity is locked and
// complete, none otherwise — and delegates the set/unset/skip/marker
// reconciliation to the shared planContainerEnv.
func planGitIdentityEnv(prevMarker string, id GitIdentity, lock bool) toolEnvPlan {
	var desired map[string]string
	if lock && id.Complete() {
		name := strings.TrimSpace(id.Name)
		email := strings.TrimSpace(id.Email)
		desired = map[string]string{
			"GIT_AUTHOR_NAME":     name,
			"GIT_AUTHOR_EMAIL":    email,
			"GIT_COMMITTER_NAME":  name,
			"GIT_COMMITTER_EMAIL": email,
		}
	}
	return planContainerEnv(prevMarker, desired)
}
