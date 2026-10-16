package container

import "testing"

func TestParseInstanceStateCSV(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   InstanceState
	}{
		{"missing", "", InstanceState{}},
		{"stopped", "coi-a-1,STOPPED,", InstanceState{Exists: true}},
		{"running without lease", "coi-a-1,RUNNING,", InstanceState{Exists: true, Running: true}},
		{"running", "coi-a-1,RUNNING,10.47.62.5 (eth0)", InstanceState{Exists: true, Running: true, IPv4: "10.47.62.5"}},
		{
			"several interfaces",
			"coi-a-1,RUNNING,\"172.17.0.1 (docker0)\n10.47.62.5 (eth0)\"",
			InstanceState{Exists: true, Running: true, IPv4: "10.47.62.5"},
		},
		{"no eth0", "coi-a-1,RUNNING,172.17.0.1 (docker0)", InstanceState{Exists: true, Running: true}},
		{"other name only", "coi-a-10,RUNNING,10.47.62.6 (eth0)", InstanceState{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInstanceStateCSV(tt.output, "coi-a-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}
