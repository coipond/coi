// Package limits validates container resource limits (CPU, memory, disk,
// runtime) and applies them to Incus containers.
package limits

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// ApplyOptions contains options for applying limits
type ApplyOptions struct {
	ContainerName string
	CPU           CPULimits
	Memory        MemoryLimits
	Disk          DiskLimits
	Runtime       RuntimeLimits
	// Project is informational. The actual Incus project used by the container
	// helpers is container.IncusProject (set globally via container.Configure).
	// Both are always sourced from cfg.Incus.Project so they remain in sync.
	Project string
}

// ApplyResourceLimits applies all resource limits to a container
func ApplyResourceLimits(opts ApplyOptions) error {
	return ApplyResourceLimitsContext(context.Background(), opts)
}

// ApplyResourceLimitsContext applies all resource limits to a container with context support
func ApplyResourceLimitsContext(ctx context.Context, opts ApplyOptions) error {
	// Validate all limits first
	validationErrors := ValidateAll(opts.CPU, opts.Memory, opts.Disk, opts.Runtime)
	if validationErrors != nil {
		return fmt.Errorf("validation failed: %s", FormatValidationErrors(validationErrors))
	}

	if pairs := instanceLimitPairs(opts); len(pairs) > 0 {
		if err := container.ConfigSetPairs(ctx, opts.ContainerName, pairs...); err != nil {
			return fmt.Errorf("failed to apply CPU/memory/process limits: %w", err)
		}
	}

	if err := applyDiskLimits(ctx, opts.ContainerName, opts.Disk); err != nil {
		return fmt.Errorf("failed to apply disk limits: %w", err)
	}

	return nil
}

// instanceLimitPairs returns the instance-level limit keys opts sets, as
// `key=value` pairs, so they apply in one `incus config set`.
func instanceLimitPairs(opts ApplyOptions) []string {
	desired := DesiredLimits(opts)
	var pairs []string
	for _, k := range container.LimitKeys {
		if v := desired[k]; v != "" && !strings.HasPrefix(k, "root.") {
			pairs = append(pairs, k+"="+v)
		}
	}
	return pairs
}

// rootDiskLimitPairs returns the root disk device keys disk sets, as
// `key=value` pairs, so they apply in one `incus config device set`.
func rootDiskLimitPairs(disk DiskLimits) []string {
	desired := DesiredLimits(ApplyOptions{Disk: disk})
	var pairs []string
	for _, k := range container.LimitKeys {
		if dk, isRoot := strings.CutPrefix(k, "root."); isRoot && desired[k] != "" {
			pairs = append(pairs, dk+"="+desired[k])
		}
	}
	return pairs
}

// applyDiskLimits applies disk I/O limits to the root device of a container.
// Disk I/O limits in Incus are device-level config on the root disk, not
// container-level config keys, so we use `incus config device set`.
// When the container's root disk device comes from an Incus profile (not from
// the instance config), Incus refuses to modify it via `config device set`.
// We work around this by ensuring an instance-level root device exists first.
func applyDiskLimits(ctx context.Context, containerName string, disk DiskLimits) error {
	if disk.Read == "" && disk.Write == "" && disk.Max == "" && disk.Size == "" && disk.Priority == 0 {
		return nil
	}

	// A rootfs size quota can only be enforced on a quota-capable pool, so reject
	// it up front on an unsupported (e.g. dir) pool rather than leaving the user
	// with an unbounded rootfs they believe is capped (#728).
	if disk.Size != "" {
		if err := ensureSizeQuotaSupported(ctx, containerName); err != nil {
			return err
		}
	}

	// Ensure root device is at the instance level before setting disk limits.
	if err := ensureInstanceRootDevice(ctx, containerName); err != nil {
		return fmt.Errorf("failed to ensure instance-level root device: %w", err)
	}

	pairs := rootDiskLimitPairs(disk)
	if out, err := container.DeviceSet(ctx, containerName, "root", pairs...); err != nil {
		return fmt.Errorf("incus config device set %s failed: %w (output: %s)", strings.Join(pairs, " "), err, out)
	}

	return nil
}

// quotaCapablePoolDrivers are the Incus storage drivers that enforce a root
// disk `size=` quota. On any other driver (notably `dir`) Incus accepts the
// key but never enforces it, so coi rejects the config instead.
var quotaCapablePoolDrivers = map[string]bool{
	"btrfs": true,
	"zfs":   true,
	"lvm":   true,
	"ceph":  true,
}

// PoolDriverEnforcesQuota reports whether an Incus storage-pool driver can
// enforce a root disk `size=` quota. Pure, so it is unit-testable. (#728)
func PoolDriverEnforcesQuota(driver string) bool {
	return quotaCapablePoolDrivers[driver]
}

// ensureSizeQuotaSupported returns an error when the container's root disk lives
// on a storage pool whose driver cannot enforce a size quota (e.g. dir). This is
// a hard failure by design: a silently-ignored quota is worse than none (#728).
func ensureSizeQuotaSupported(ctx context.Context, containerName string) error {
	pool, err := getRootDevicePool(ctx, containerName)
	if err != nil {
		return fmt.Errorf("cannot verify storage pool for disk size quota: %w", err)
	}
	pools, err := container.ListStoragePools()
	if err != nil {
		return fmt.Errorf("cannot list storage pools for disk size quota: %w", err)
	}
	for _, p := range pools {
		if p.Name == pool {
			if PoolDriverEnforcesQuota(p.Driver) {
				return nil
			}
			return fmt.Errorf("[limits.disk] size requires a quota-capable storage pool, but pool %q uses the %q driver which cannot enforce a rootfs quota; use a btrfs/zfs/lvm pool (see 'incus storage create') or remove [limits.disk] size", pool, p.Driver)
		}
	}
	return fmt.Errorf("[limits.disk] size is set but storage pool %q was not found; cannot verify it can enforce a rootfs quota", pool)
}

// ensureInstanceRootDevice ensures the root disk device is defined at the instance
// level rather than only in an Incus profile. Without this, `incus config device set`
// fails with "Device from profile(s) cannot be modified for individual instance."
func ensureInstanceRootDevice(ctx context.Context, containerName string) error {
	pool, err := getRootDevicePool(ctx, containerName)
	if err != nil {
		return err
	}

	// DeviceAdd already handles the "already exists" case internally.
	if _, err := container.DeviceAdd(ctx, containerName, "root", "disk", "path=/", "pool="+pool); err != nil {
		return fmt.Errorf("failed to add instance-level root device: %w", err)
	}
	return nil
}

// getRootDevicePool returns the storage pool name used by the root disk device
// by querying the expanded container config (which includes profile-inherited devices).
// Falls back to "default" if the pool cannot be determined.
func getRootDevicePool(ctx context.Context, containerName string) (string, error) {
	output, err := container.ConfigShow(ctx, containerName, true)
	if err != nil {
		return "default", fmt.Errorf("failed to get expanded container config: %w", err)
	}

	lines := strings.Split(output, "\n")
	inDevices, inRoot := false, false
	for _, line := range lines {
		if line == "devices:" {
			inDevices = true
			continue
		}
		if inDevices && strings.TrimSpace(line) == "root:" {
			inRoot = true
			continue
		}
		if inRoot {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "pool:") {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
			if len(line) > 0 && !strings.HasPrefix(line, "    ") {
				inRoot = false
			}
		}
		if inDevices && len(line) > 0 && !strings.HasPrefix(line, " ") {
			inDevices = false
		}
	}

	return "default", nil
}
