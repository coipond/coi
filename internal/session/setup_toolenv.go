package session

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/tool"
)

// toolEnvMarkerKey records (comma-separated) which environment.* keys coi set
// from the tool's resolved env on the previous setup, so a later run can unset
// the ones a profile/tool switch no longer wants. user.* keys are free-form
// instance metadata Incus stores but never interprets.
const toolEnvMarkerKey = "user.coi.tool_env_keys"

// applyToolContainerEnv persists the tool's resolved GetContainerEnv as
// container-level `environment.*` Incus config. Incus injects those into EVERY
// exec — coi's own tool launch and an external `coi container exec` alike — so
// the profile's tool config (Claude model/effort, opencode's XDG dirs, ...)
// reaches the tool no matter who launches it (#744).
//
// Unlike the in-container settings.json injection (setupCLIConfig), which is
// gated on fresh creation, this runs for reused/persistent containers too, so a
// per-workflow model change on a long-lived container actually takes effect. It
// reconciles stale keys via toolEnvMarkerKey: env a previous profile set but the
// current one doesn't is unset, so nothing leaks across switches. Failures are
// non-fatal (logged) — a missing env var degrades to the tool's default, which
// must never block a session from coming up.
func applyToolContainerEnv(ctx context.Context, containerName, workspacePath string, t tool.Tool, logger func(string)) {
	twce, ok := t.(tool.ToolWithContainerEnv)
	if !ok {
		return
	}
	prevMarker, _ := container.ConfigGet(ctx, containerName, toolEnvMarkerKey)
	plan := planContainerEnv(prevMarker, twce.GetContainerEnv(workspacePath))

	for _, k := range plan.skipped {
		logger(fmt.Sprintf("Warning: skipping tool env %s (unsafe value)", k))
	}
	for _, k := range plan.unset {
		_ = container.ConfigUnsetIfSet(ctx, containerName, "environment."+k)
	}
	for _, k := range plan.setKeys {
		if _, err := container.ConfigSetIfChanged(ctx, containerName, "environment."+k, plan.set[k]); err != nil {
			logger(fmt.Sprintf("Warning: failed to set container env %s: %v", k, err))
		}
	}
	switch {
	case plan.marker != "":
		if _, err := container.ConfigSetIfChanged(ctx, containerName, toolEnvMarkerKey, plan.marker); err != nil {
			logger(fmt.Sprintf("Warning: failed to record tool env marker: %v", err))
		}
	case prevMarker != "":
		_ = container.ConfigUnset(ctx, containerName, toolEnvMarkerKey)
	}
}

// toolEnvPlan is the reconciled set of container-env changes for one setup.
type toolEnvPlan struct {
	set     map[string]string // env key -> value to set
	setKeys []string          // keys of set, sorted (deterministic apply order)
	unset   []string          // previously-set keys no longer desired, sorted
	skipped []string          // desired keys dropped for an unsafe value, sorted
	marker  string            // comma-joined applied keys for toolEnvMarkerKey
}

// planContainerEnv is the pure decision core shared by applyToolContainerEnv and
// ApplyGitIdentityContainerEnv: given the previous marker (keys coi set last time)
// and a desired env map, it decides which environment.* keys to set, which stale
// ones to unset, which to skip as unsafe, and the new marker value. Kept free of
// Incus calls so the reconciliation is unit-tested.
func planContainerEnv(prevMarker string, desired map[string]string) toolEnvPlan {
	plan := toolEnvPlan{set: map[string]string{}}

	for k, v := range desired {
		// Values come from profile config ([tool.*], which is project-mergeable),
		// so reject anything that could break the config line or smuggle newlines
		// into the container environment. Keys are fixed by the tool, not user
		// input, so only values need guarding.
		if validContainerEnvValue(v) {
			plan.set[k] = v
			plan.setKeys = append(plan.setKeys, k)
		} else {
			plan.skipped = append(plan.skipped, k)
		}
	}
	sort.Strings(plan.setKeys)
	sort.Strings(plan.skipped)

	// Unset keys we set last time that we are no longer setting (profile/tool
	// switch, or a value gone unsafe/empty).
	for _, k := range splitCSV(prevMarker) {
		if _, keep := plan.set[k]; !keep {
			plan.unset = append(plan.unset, k)
		}
	}
	sort.Strings(plan.unset)

	plan.marker = strings.Join(plan.setKeys, ",")
	return plan
}

// validContainerEnvValue rejects values that can't be safely carried as an
// Incus environment.* value: control characters that would corrupt the config
// or inject extra environment lines.
func validContainerEnvValue(v string) bool {
	return !strings.ContainsAny(v, "\n\r\x00")
}

// splitCSV splits a comma-separated marker value into non-empty, trimmed keys.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
