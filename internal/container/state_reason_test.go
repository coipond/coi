package container

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// stateReasonCalls returns the logged incus calls without the project prefix.
func stateReasonCalls(t *testing.T, logPath string) []string {
	t.Helper()
	b, _ := os.ReadFile(logPath)
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			out = append(out, strings.TrimPrefix(line, "--project default "))
		}
	}
	return out
}

func TestSetStateReason_OneCall(t *testing.T) {
	invalidateConfigCache()
	logPath := fakeIncusScript(t, "exit 0")
	before := time.Now().UTC().Truncate(time.Second)

	if err := SetStateReason(context.Background(), "c1", MonitorStateReason("Reverse shell detected")); err != nil {
		t.Fatal(err)
	}

	calls := stateReasonCalls(t, logPath)
	if len(calls) != 1 {
		t.Fatalf("calls = %q, want one config set", calls)
	}
	prefix := "config set c1 user.coi.state_reason=monitor:Reverse shell detected user.coi.state_reason_at="
	at, ok := strings.CutPrefix(calls[0], prefix)
	if !ok {
		t.Fatalf("call = %q, want prefix %q", calls[0], prefix)
	}
	ts, err := time.Parse(time.RFC3339, at)
	if err != nil || ts.Location() != time.UTC || ts.Before(before) {
		t.Errorf("state_reason_at = %q (%v), want UTC RFC 3339 not before %s", at, err, before)
	}
}

func TestSetStateReason_ReturnsIncusError(t *testing.T) {
	invalidateConfigCache()
	fakeIncusScript(t, "echo 'Error: boom' >&2; exit 1")
	err := SetStateReason(context.Background(), "c1", StateReasonUser)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want Incus's message", err)
	}
}

func TestClearStateReason(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		want         []string
	}{
		{"none set", "config: {}\ndevices: {}\n", nil},
		{
			"both set", "config:\n  user.coi.state_reason: user\n  user.coi.state_reason_at: \"2026-11-28T03:00:00Z\"\ndevices: {}\n",
			[]string{"config unset c1 user.coi.state_reason", "config unset c1 user.coi.state_reason_at"},
		},
		{
			"only time set", "config:\n  user.coi.state_reason_at: \"2026-11-28T03:00:00Z\"\ndevices: {}\n",
			[]string{"config unset c1 user.coi.state_reason_at"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalidateConfigCache()
			cfg := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(cfg, []byte(tc.config), 0o644); err != nil {
				t.Fatal(err)
			}
			logPath := fakeIncusScript(t, `case "$*" in *"config show "*) cat `+cfg+` ;; esac`)

			if err := ClearStateReason(context.Background(), "c1"); err != nil {
				t.Fatal(err)
			}

			var writes []string
			for _, c := range stateReasonCalls(t, logPath) {
				if !strings.HasPrefix(c, "config show ") {
					writes = append(writes, c)
				}
			}
			if !reflect.DeepEqual(writes, tc.want) {
				t.Errorf("writes = %q, want %q", writes, tc.want)
			}
		})
	}
}
