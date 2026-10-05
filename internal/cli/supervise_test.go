package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
)

func TestNeedsSupervisor(t *testing.T) {
	on, off := true, false
	cases := []struct {
		name       string
		monitoring *bool
		maxDur     string
		want       bool
	}{
		{"nothing to supervise", &off, "", false},
		{"monitoring enabled", &on, "", true},
		{"runtime limit only", &off, "15s", true},
		{"zero runtime limit", &off, "0", false},
		{"invalid runtime limit", &off, "soon", false},
	}
	for _, tc := range cases {
		cfg := &config.Config{Monitoring: config.MonitoringConfig{Enabled: tc.monitoring}}
		got := needsSupervisor(cfg, config.RuntimeLimits{MaxDuration: tc.maxDur})
		if got != tc.want {
			t.Errorf("%s: needsSupervisor = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A second supervisor for the same container must not start while the first
// holds the lock, and the lock frees up once the first lets go.
func TestLockSupervisor_IsExclusive(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "run", "c.supervisor.lock")

	first, err := lockSupervisor(lockPath)
	if err != nil || first == nil {
		t.Fatalf("first lock: got (%v, %v), want a held lock", first, err)
	}
	second, err := lockSupervisor(lockPath)
	if err != nil || second != nil {
		t.Fatalf("second lock while held: got (%v, %v), want (nil, nil)", second, err)
	}
	_ = first.Close()

	third, err := lockSupervisor(lockPath)
	if err != nil || third == nil {
		t.Fatalf("lock after release: got (%v, %v), want a held lock", third, err)
	}
	_ = third.Close()
}

// The state written for the supervisor carries only the sections it needs;
// tool, credential and environment settings (which can hold tokens) must not
// be part of it.
func TestSupervisorState_HasNoSecretBearingSections(t *testing.T) {
	data, err := json.Marshal(supervisorState{ContainerName: "c"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"tool", "defaults", "credentials", "environment", "ssh", "prompts"} {
		for k := range fields {
			if strings.EqualFold(k, banned) {
				t.Errorf("supervisor state must not include %q", k)
			}
		}
	}
}

// A frozen (auto-paused) container is still supervised; only a deleted or
// stopped one ends the supervisor.
func TestContainerGoneFromStatus(t *testing.T) {
	cases := map[string]bool{
		"":          true,
		"\n":        true,
		"STOPPED\n": true,
		"RUNNING\n": false,
		"FROZEN\n":  false,
		"STARTING":  false,
	}
	for out, want := range cases {
		if got, _ := containerGoneFromStatus(out); got != want {
			t.Errorf("containerGoneFromStatus(%q) = %v, want %v", out, got, want)
		}
	}
}

func TestSupervisorNotice(t *testing.T) {
	const log = "/home/u/.coi/logs/coi-x-1.stderr.log"
	tests := []struct {
		name       string
		monitoring bool
		maxDur     string
		already    bool
		logPath    string
		want       string
	}{
		{
			"monitoring only", true, "", false, log,
			"[supervisor] Running security monitoring until the container stops (log: " + log + ")",
		},
		{
			"runtime limit only", false, "2h", false, log,
			"[supervisor] Running the 2h max_duration limit until the container stops (log: " + log + ")",
		},
		{
			"both", true, "30m", false, log,
			"[supervisor] Running security monitoring and the 30m max_duration limit until the container stops (log: " + log + ")",
		},
		{
			"re-attach to a running supervisor", true, "", true, log,
			"[supervisor] Already running for this container (security monitoring) (log: " + log + ")",
		},
		{
			"no log path", true, "", false, "",
			"[supervisor] Running security monitoring until the container stops",
		},
		{
			"unparseable limit is not claimed", true, "soon", false, "",
			"[supervisor] Running security monitoring until the container stops",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := supervisorNotice(tt.monitoring, tt.maxDur, tt.already, tt.logPath)
			if got != tt.want {
				t.Errorf("supervisorNotice() =\n  %q\nwant\n  %q", got, tt.want)
			}
			// Runtime-limit diagnostics must stay off the terminal (#372).
			if strings.Contains(got, "[limits]") || strings.Contains(got, "Runtime limit reached") {
				t.Errorf("notice uses a terminal-forbidden runtime-limit marker: %q", got)
			}
		})
	}
}
