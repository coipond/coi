//go:build integration

package session

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/container"
)

// secondStoragePoolForTest returns a storage pool other than "default" so the
// test can prove StoragePool actually changes which pool the container lands
// on (as opposed to a bug that silently keeps using the default pool either
// way). Skips if none is configured locally.
func secondStoragePoolForTest(t *testing.T) string {
	t.Helper()
	pools, err := container.ListStoragePools()
	if err != nil {
		t.Fatalf("failed to list storage pools: %v", err)
	}
	for _, p := range pools {
		if p.Name != "default" {
			return p.Name
		}
	}
	t.Skip("no non-default storage pool configured; create one (e.g. `incus storage create btrfs-pool btrfs`) to run this test")
	return ""
}

// TestSetup_HonorsStoragePool verifies that SetupOptions.StoragePool is
// threaded through Setup() into the actual container launch (issue #726:
// `coi shell` silently ignored [container] storage_pool while `coi
// run`/`coi build` honored it).
func TestSetup_HonorsStoragePool(t *testing.T) {
	skipUnlessContextFileTestable(t)
	pool := secondStoragePoolForTest(t)

	// Match container.CodeUID to the host UID for the duration of this test so
	// Setup()'s raw.idmap decision (host UID != code UID) doesn't kick in —
	// that path is unrelated to storage pool selection and, combined with
	// security.idmap.isolated on this host, hits an unrelated newuidmap/subuid
	// limitation that would otherwise make every session.Setup() call fail
	// here regardless of which pool is requested.
	origUID := container.CodeUID
	container.Configure(container.IncusProject, container.CodeUser, os.Getuid())
	t.Cleanup(func() { container.Configure(container.IncusProject, container.CodeUser, origUID) })

	opts := SetupOptions{
		WorkspacePath: t.TempDir(),
		Image:         "coi-default",
		StoragePool:   pool,
		Logger:        func(msg string) { t.Logf("[setup] %s", msg) },
	}

	result, err := Setup(context.Background(), opts)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	t.Cleanup(func() {
		_ = result.Manager.Stop(true)
		_ = result.Manager.Delete(true)
	})

	// The "root" disk device is only settable on the instance when it
	// overrides the profile's pool (as -s does on the CLI); when a container
	// lands on the profile's pool instead, "config device get" errors since
	// there is no instance-level override to read. `incus list -c b` reports
	// the effective pool either way.
	out, err := container.IncusOutput("list", "^"+result.ContainerName+"$", "--format=csv", "--columns=nb")
	if err != nil {
		t.Fatalf("failed to read container's storage pool: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(out), ",", 2)
	if len(fields) != 2 {
		t.Fatalf("unexpected `incus list` output: %q", out)
	}
	if got := fields[1]; got != pool {
		t.Errorf("container launched on storage pool %q, want %q", got, pool)
	}
}
