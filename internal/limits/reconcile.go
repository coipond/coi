package limits

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// DesiredLimits returns the value coi sets for each container.LimitKeys key
// under opts, keyed the same way; "" means the key must be unset.
func DesiredLimits(opts ApplyOptions) map[string]string {
	nonZero := func(n int) string {
		if n == 0 {
			return ""
		}
		return fmt.Sprintf("%d", n)
	}
	swap := ""
	if opts.Memory.Swap != "" {
		swap = NormalizeBoolString(opts.Memory.Swap)
	}
	processes := ""
	if opts.Runtime.MaxProcesses > 0 {
		processes = fmt.Sprintf("%d", opts.Runtime.MaxProcesses)
	}
	return map[string]string{
		"limits.cpu":                opts.CPU.Count,
		"limits.cpu.allowance":      opts.CPU.Allowance,
		"limits.cpu.priority":       nonZero(opts.CPU.Priority),
		"limits.memory":             opts.Memory.Limit,
		"limits.memory.enforce":     opts.Memory.Enforce,
		"limits.memory.swap":        swap,
		"limits.processes":          processes,
		"root.limits.read":          opts.Disk.Read,
		"root.limits.write":         opts.Disk.Write,
		"root.limits.max":           opts.Disk.Max,
		"root.limits.disk.priority": nonZero(opts.Disk.Priority),
		"root.size":                 opts.Disk.Size,
	}
}

// LimitDrift returns the container.LimitKeys whose current value differs
// from the desired one, in container.LimitKeys order.
func LimitDrift(current, desired map[string]string) []string {
	var drift []string
	for _, k := range container.LimitKeys {
		if current[k] != desired[k] {
			drift = append(drift, k)
		}
	}
	return drift
}

// ReconcileResourceLimits brings the limits in a container's own config to
// opts: a changed key is set, a key emptied in opts is removed. Keys coi does
// not manage are left alone. Meant for a stopped container that is about to
// start again. Returns the keys it changed.
func ReconcileResourceLimits(ctx context.Context, opts ApplyOptions) ([]string, error) {
	if validationErrors := ValidateAll(opts.CPU, opts.Memory, opts.Disk, opts.Runtime); validationErrors != nil {
		return nil, fmt.Errorf("validation failed: %s", FormatValidationErrors(validationErrors))
	}
	current, err := container.NewManager(opts.ContainerName).InstanceLimits()
	if err != nil {
		return nil, err
	}
	desired := DesiredLimits(opts)
	drift := LimitDrift(current, desired)

	rootReady := false
	for _, k := range drift {
		v := desired[k]
		dk, isRoot := strings.CutPrefix(k, "root.")
		switch {
		case !isRoot && v != "":
			err = container.ConfigSet(ctx, opts.ContainerName, k, v)
		case !isRoot:
			err = container.ConfigUnset(ctx, opts.ContainerName, k)
		case v == "":
			// Only an instance-level root device can hold the key.
			if out, uerr := container.DeviceUnset(ctx, opts.ContainerName, "root", dk); uerr != nil {
				err = fmt.Errorf("incus config device unset %s failed: %w (output: %s)", dk, uerr, out)
			}
		default:
			if !rootReady {
				if err = prepareRootDevice(ctx, opts.ContainerName, desired["root.size"] != current["root.size"] && desired["root.size"] != ""); err != nil {
					break
				}
				rootReady = true
			}
			if out, serr := container.DeviceSet(ctx, opts.ContainerName, "root", dk+"="+v); serr != nil {
				err = fmt.Errorf("incus config device set %s=%s failed: %w (output: %s)", dk, v, serr, out)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("failed to reconcile %s: %w", k, err)
		}
	}
	return drift, nil
}

// prepareRootDevice makes the root disk settable as on create: a size quota
// needs a quota-capable pool, and the device must be instance-level.
func prepareRootDevice(ctx context.Context, containerName string, checkQuota bool) error {
	if checkQuota {
		if err := ensureSizeQuotaSupported(ctx, containerName); err != nil {
			return err
		}
	}
	if err := ensureInstanceRootDevice(ctx, containerName); err != nil {
		return fmt.Errorf("failed to ensure instance-level root device: %w", err)
	}
	return nil
}
