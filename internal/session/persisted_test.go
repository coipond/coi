package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// TestAllocateSlotPreferPersisted lists slots 1 (stopped, key false),
// 2 (status2, key true) and 3 (running) for the workspace.
func TestAllocateSlotPreferPersisted(t *testing.T) {
	t.Setenv("COI_CONTAINER_PREFIX", "")
	workspace := "/home/u/persisted"
	tests := []struct {
		name          string
		status2       string
		want          int
		wantPersisted bool
	}{
		{name: "stopped marked container is reused", status2: "STOPPED", want: 2, wantPersisted: true},
		{name: "running marked container is not reused", status2: "RUNNING", want: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := fakeLimitsIncus(t, ContainerName(workspace, "", 2), "")
			orig := listSlotInstances
			t.Cleanup(func() { listSlotInstances = orig })
			listSlotInstances = func() ([]container.ContainerStatus, error) {
				return []container.ContainerStatus{
					{Name: ContainerName(workspace, "", 1), Status: "STOPPED", Key: "false"},
					{Name: ContainerName(workspace, "", 2), Status: tt.status2, Key: "true"},
					{Name: ContainerName(workspace, "", 3), Status: "RUNNING"},
				}, nil
			}

			got, persisted, err := AllocateSlotPreferPersisted(workspace, "", MaxSlots)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || persisted != tt.wantPersisted {
				t.Errorf("AllocateSlotPreferPersisted() = %d, %v; want %d, %v", got, persisted, tt.want, tt.wantPersisted)
			}
			// The key comes from the listing: no incus call per container.
			if calls, _ := os.ReadFile(logPath); len(calls) != 0 {
				t.Errorf("want no incus calls besides the listing, got:\n%s", calls)
			}
		})
	}
}

func TestContainerMarkedPersistent(t *testing.T) {
	for _, tt := range []struct {
		key  string
		want bool
	}{{"true", true}, {"false", false}, {"", false}} {
		logPath := fakeLimitsIncus(t, "coi-marked-1", "")
		keys := filepath.Join(filepath.Dir(logPath), "keys")
		if err := os.MkdirAll(keys, 0o755); err != nil {
			t.Fatal(err)
		}
		if tt.key != "" {
			if err := os.WriteFile(filepath.Join(keys, PersistentConfigKey), []byte(tt.key), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := ContainerMarkedPersistent("coi-marked-1"); got != tt.want {
			t.Errorf("key %q: ContainerMarkedPersistent() = %v, want %v", tt.key, got, tt.want)
		}
	}
	fakeUnreachableIncus(t)
	if ContainerMarkedPersistent("coi-marked-1") {
		t.Error("unreachable incus: want false")
	}
}
