package session

import (
	"context"
	"reflect"
	"testing"
)

func TestContainerInitArgs_RecordsWorkspace(t *testing.T) {
	got := containerInitArgs("coi-default", "coi-abc-1", &SetupOptions{StoragePool: "fast", WorkspacePath: "/home/u/my proj"})
	want := []string{"init", "coi-default", "coi-abc-1", "-s", "fast", "-c", "user.coi.managed=true", "-c", "user.coi.workspace=/home/u/my proj"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("init args = %q, want %q", got, want)
	}
}

func TestPhaseCreateContainer_ReuseSetsWorkspaceKey(t *testing.T) {
	for _, tc := range []struct {
		name, container, configYAML string
		explicit                    bool
		want                        []string
	}{
		{"key missing", "pcc-missing", "config: {}\ndevices: {}\n", false, []string{"config set pcc-missing user.coi.workspace=/home/u/proj"}},
		{"workspace moved", "pcc-moved", "config:\n  user.coi.workspace: /old\ndevices: {}\n", false, []string{"config set pcc-moved user.coi.workspace=/home/u/proj"}},
		{"key current", "pcc-current", "config:\n  user.coi.workspace: /home/u/proj\ndevices: {}\n", false, nil},
		// --container enters the container as it is: its own workspace stays.
		{"explicit --container", "pcc-explicit", "config:\n  user.coi.workspace: /home/u/orig\ndevices: {}\n", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := fakeLimitsIncus(t, tc.container, tc.configYAML)
			opts := SetupOptions{WorkspacePath: "/home/u/proj", Logger: func(string) {}}
			if tc.explicit {
				opts.ContainerName = tc.container
			}
			st := &setupState{
				opts:       opts,
				result:     &SetupResult{ContainerName: tc.container},
				skipLaunch: true,
			}
			if _, err := st.phaseCreateContainer(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := limitWrites(t, logPath); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("writes = %q, want %q", got, tc.want)
			}
		})
	}
}
