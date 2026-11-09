package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/limits"
)

// LimitsApplyOptions maps the [limits] config to the limits applier's options.
func LimitsApplyOptions(containerName, project string, cfg *config.LimitsConfig) limits.ApplyOptions {
	opts := limits.ApplyOptions{ContainerName: containerName, Project: project}
	if cfg == nil {
		return opts
	}
	opts.CPU = limits.CPULimits{
		Count:     cfg.CPU.Count,
		Allowance: cfg.CPU.Allowance,
		Priority:  cfg.CPU.Priority,
	}
	opts.Memory = limits.MemoryLimits{
		Limit:   cfg.Memory.Limit,
		Enforce: cfg.Memory.Enforce,
		Swap:    cfg.Memory.Swap,
	}
	opts.Disk = limits.DiskLimits{
		Read:     cfg.Disk.Read,
		Write:    cfg.Disk.Write,
		Max:      cfg.Disk.Max,
		Size:     cfg.Disk.Size,
		Priority: cfg.Disk.Priority,
	}
	opts.Runtime = limits.RuntimeLimits{
		MaxProcesses: config.IntVal(cfg.Runtime.MaxProcesses),
	}
	return opts
}

// ReconcileLimits brings a STOPPED persistent container's resource limits to
// the current config before it starts again, so a limit lowered, removed or
// raised since creation applies on this start (on create they are applied
// once, by limits.ApplyResourceLimits).
func ReconcileLimits(containerName, project string, cfg *config.LimitsConfig, logger func(string)) error {
	changed, err := limits.ReconcileResourceLimits(context.Background(), LimitsApplyOptions(containerName, project, cfg))
	if err != nil {
		return fmt.Errorf("failed to apply resource limits: %w", err)
	}
	if len(changed) > 0 {
		logger("Applied resource limit changes from the current config: " + strings.Join(changed, ", "))
	}
	return nil
}

// warnLimitsDrift compares a RUNNING container's resource limits with the
// current config and logs which differ. A running container is not changed:
// another session may use it. The next stopped->start applies them.
func warnLimitsDrift(containerName, project string, cfg *config.LimitsConfig, logger func(string)) {
	current, err := container.NewManager(containerName).InstanceLimits()
	if err != nil {
		return // best-effort, like warnHardeningMismatch
	}
	drift := limits.LimitDrift(current, limits.DesiredLimits(LimitsApplyOptions(containerName, project, cfg)))
	if len(drift) > 0 {
		logger("Warning: this running container has different resource limits than the current config (" + strings.Join(drift, ", ") + "); restart it (coi shutdown, then relaunch) to apply them")
	}
}
