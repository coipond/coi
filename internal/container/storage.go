package container

import (
	"encoding/json"
	"fmt"
)

// StoragePool is a minimal projection of an Incus storage pool entry.
// Only the fields Coi cares about are decoded — Incus's full schema is
// significantly larger and changes between releases.
type StoragePool struct {
	Name   string            `json:"name"`
	Driver string            `json:"driver"`
	Config map[string]string `json:"config"`
	UsedBy []string          `json:"used_by"`
}

// ListStoragePools returns all storage pools known to the local Incus daemon.
// The call goes through the same incus wrapper as every other Incus
// invocation in this package so it inherits the project flag.
func ListStoragePools() ([]StoragePool, error) {
	out, err := IncusOutputRaw("storage", "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to list storage pools: %w", err)
	}

	var pools []StoragePool
	if err := json.Unmarshal([]byte(out), &pools); err != nil {
		return nil, fmt.Errorf("failed to parse storage pool list: %w", err)
	}
	return pools, nil
}

// ValidateStoragePool returns nil if the named pool is empty (caller will use
// the Incus default pool) or exists on the daemon. Otherwise it returns an
// actionable error with copy-pasteable `incus storage create` examples.
//
// The error message is environment-agnostic on purpose: under Colima/Lima the
// user runs the same command inside the VM, so a single fix works everywhere.
func ValidateStoragePool(pool string) error {
	if pool == "" {
		return nil
	}

	pools, err := ListStoragePools()
	if err != nil {
		return err
	}
	for _, p := range pools {
		if p.Name == pool {
			return nil
		}
	}

	return fmt.Errorf(`storage pool %q does not exist.

Create it with one of:

    # Directory-backed (works everywhere)
    incus storage create %s dir

    # ZFS-backed (recommended for snapshots and clones)
    incus storage create %s zfs source=tank/coi

    # btrfs-backed
    incus storage create %s btrfs

See: https://linuxcontainers.org/incus/docs/main/howto/storage_pools/`,
		pool, pool, pool, pool)
}
