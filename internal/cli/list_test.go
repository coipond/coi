package cli

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestResolveStatusFilter(t *testing.T) {
	tests := []struct {
		name      string
		statusSet bool
		status    string
		running   bool
		stopped   bool
		want      string
		wantErr   bool
	}{
		{name: "no filter", want: ""},
		{name: "running shorthand", running: true, want: "running"},
		{name: "stopped shorthand", stopped: true, want: "stopped"},
		{name: "status running", statusSet: true, status: "running", want: "running"},
		{name: "status stopped", statusSet: true, status: "stopped", want: "stopped"},
		{name: "status frozen", statusSet: true, status: "frozen", want: "frozen"},
		{name: "status error", statusSet: true, status: "error", want: "error"},
		{name: "status stopping", statusSet: true, status: "stopping", want: "stopping"},
		{name: "status is case-insensitive", statusSet: true, status: "RUNNING", want: "running"},
		{name: "status mixed case", statusSet: true, status: "Frozen", want: "frozen"},
		{name: "invalid status", statusSet: true, status: "paused", wantErr: true},
		{name: "explicitly empty status", statusSet: true, status: "", wantErr: true},
		{name: "running and stopped conflict", running: true, stopped: true, wantErr: true},
		{name: "running and status conflict", running: true, statusSet: true, status: "running", wantErr: true},
		{name: "running and empty status conflict", running: true, statusSet: true, status: "", wantErr: true},
		{name: "stopped and status conflict", stopped: true, statusSet: true, status: "frozen", wantErr: true},
		{name: "all three conflict", running: true, stopped: true, statusSet: true, status: "running", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveStatusFilter(tt.statusSet, tt.status, tt.running, tt.stopped)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveStatusFilter(%v, %q, %v, %v) expected error, got %q",
						tt.statusSet, tt.status, tt.running, tt.stopped, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveStatusFilter(%v, %q, %v, %v) unexpected error: %v",
					tt.statusSet, tt.status, tt.running, tt.stopped, err)
			}
			if got != tt.want {
				t.Errorf("resolveStatusFilter(%v, %q, %v, %v) = %q, want %q",
					tt.statusSet, tt.status, tt.running, tt.stopped, got, tt.want)
			}
		})
	}
}

func TestResolveStatusFilterAcceptsEveryValidValue(t *testing.T) {
	for _, status := range validStatusFilters {
		got, err := resolveStatusFilter(true, status, false, false)
		if err != nil {
			t.Errorf("resolveStatusFilter rejected valid status %q: %v", status, err)
		}
		if got != status {
			t.Errorf("resolveStatusFilter(%q) = %q, want %q", status, got, status)
		}
	}
}

func TestFilterContainersByStatus(t *testing.T) {
	newContainers := func() []ContainerInfo {
		return []ContainerInfo{
			{Name: "coi-aaa-1", Status: "Running"},
			{Name: "coi-bbb-1", Status: "Stopped"},
			{Name: "coi-ccc-1", Status: "Running"},
			{Name: "coi-ddd-1", Status: "Frozen"},
			{Name: "coi-eee-1", Status: "Error"},
		}
	}

	tests := []struct {
		name   string
		status string
		want   []string
	}{
		{name: "running only", status: "running", want: []string{"coi-aaa-1", "coi-ccc-1"}},
		{name: "stopped only", status: "stopped", want: []string{"coi-bbb-1"}},
		{name: "frozen only", status: "frozen", want: []string{"coi-ddd-1"}},
		{name: "error only", status: "error", want: []string{"coi-eee-1"}},
		{name: "case-insensitive match", status: "RUNNING", want: []string{"coi-aaa-1", "coi-ccc-1"}},
		{name: "no matches", status: "starting", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterContainersByStatus(newContainers(), tt.status)
			if len(got) != len(tt.want) {
				t.Fatalf("filterContainersByStatus(%q) returned %d containers, want %d: %+v",
					tt.status, len(got), len(tt.want), got)
			}
			for i, c := range got {
				if c.Name != tt.want[i] {
					t.Errorf("filterContainersByStatus(%q)[%d] = %q, want %q",
						tt.status, i, c.Name, tt.want[i])
				}
			}
		})
	}

	t.Run("empty input stays empty", func(t *testing.T) {
		if got := filterContainersByStatus(nil, "running"); len(got) != 0 {
			t.Errorf("expected empty result for nil input, got %+v", got)
		}
	})

	t.Run("original slice is not mutated", func(t *testing.T) {
		containers := newContainers()
		want := newContainers()
		filterContainersByStatus(containers, "running")
		for i := range want {
			if !reflect.DeepEqual(containers[i], want[i]) {
				t.Errorf("input[%d] was mutated: got %+v, want %+v", i, containers[i], want[i])
			}
		}
	})
}

// extractPublishedPorts must render coi-port-* proxy devices from the incus
// list JSON: pool devices as the bare identity number, named entries as
// name:host->container (listen address prefixed when not loopback), sorted by
// host port, ignoring non-port devices entirely.
func TestExtractPublishedPorts(t *testing.T) {
	c := map[string]interface{}{
		"expanded_devices": map[string]interface{}{
			"root":     map[string]interface{}{"type": "disk", "pool": "default"},
			"socket-0": map[string]interface{}{"type": "proxy", "listen": "unix:/run/x.sock", "connect": "unix:/tmp/x.sock"},
			"coi-port-pool-1": map[string]interface{}{
				"type": "proxy", "listen": "tcp:127.0.0.1:23410", "connect": "tcp:127.0.0.1:23410",
			},
			"coi-port-web": map[string]interface{}{
				"type": "proxy", "listen": "tcp:127.0.0.1:23412", "connect": "tcp:127.0.0.1:3000",
			},
			"coi-port-lan": map[string]interface{}{
				"type": "proxy", "listen": "tcp:0.0.0.0:8080", "connect": "tcp:127.0.0.1:8080",
			},
			"coi-port-v6": map[string]interface{}{
				"type": "proxy", "listen": "tcp:[::1]:9090", "connect": "tcp:127.0.0.1:3001",
			},
		},
	}

	got := extractPublishedPorts(c)
	want := []string{"lan:0.0.0.0:8080->8080", "v6:::1:9090->3001", "23410", "web:23412->3000"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("port[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// No devices → nothing rendered
	if got := extractPublishedPorts(map[string]interface{}{}); len(got) != 0 {
		t.Errorf("expected no ports without expanded_devices, got %v", got)
	}
}

// The containers section heading follows the status filter (#592): unfiltered
// output keeps the historical "Active Containers:", a filter names the state
// instead of claiming e.g. stopped containers are active.
func TestContainersHeading(t *testing.T) {
	cases := map[string]string{
		"":         "Active Containers:",
		"running":  "Running Containers:",
		"stopped":  "Stopped Containers:",
		"frozen":   "Frozen Containers:",
		"error":    "Error Containers:",
		"starting": "Starting Containers:",
	}
	for filter, want := range cases {
		if got := containersHeading(filter); got != want {
			t.Errorf("containersHeading(%q) = %q, want %q", filter, got, want)
		}
	}
}

func TestListOutput_StateReason(t *testing.T) {
	containers := []ContainerInfo{
		{Name: "coi-aaaaaaaa-1", Status: "Frozen", StateReason: "monitor:Reverse shell detected", StateReasonAt: "2026-11-28T03:00:00Z"},
		{Name: "coi-bbbbbbbb-1", Status: "Running"},
	}

	out := captureOutput(t, &os.Stdout, func() {
		if err := outputJSON(containers, nil, nil, nil); err != nil {
			t.Error(err)
		}
	})
	var got struct {
		Active []map[string]any `json:"active_containers"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got.Active) != 2 || got.Active[0]["state_reason"] != "monitor:Reverse shell detected" ||
		got.Active[0]["state_reason_at"] != "2026-11-28T03:00:00Z" ||
		got.Active[1]["state_reason"] != "" || got.Active[1]["state_reason_at"] != "" {
		t.Errorf("json = %s; want the reason on the frozen container, empty on the other", out)
	}

	text := captureOutput(t, &os.Stdout, func() {
		if err := outputText(containers, nil, nil, nil, ""); err != nil {
			t.Error(err)
		}
	})
	if strings.Count(text, "Reason:") != 1 || !strings.Contains(text, "    Reason: monitor:Reverse shell detected (2026-11-28T03:00:00Z)\n") {
		t.Errorf("text = %q; want one Reason line for the frozen container", text)
	}
}
