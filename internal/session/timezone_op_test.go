package session

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runTimezoneOp runs timezoneOp's command in bash with /etc and
// /usr/share/zoneinfo redirected into a temp root.
func runTimezoneOp(t *testing.T, root, tz string) string {
	t.Helper()
	cmd := timezoneOp(tz).cmd
	cmd = strings.ReplaceAll(cmd, "/usr/share/zoneinfo/", root+"/zoneinfo/")
	cmd = strings.ReplaceAll(cmd, "/etc/", root+"/etc/")
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("timezone op must never fail its batch: %v\n%s", err, out)
	}
	return string(out)
}

// The op sets the zone once, then is a no-op (no write, no marker) while the
// zone matches — the reused-container case — and switches when it changes.
func TestTimezoneOp_SetsOnceThenNoop(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc", "zoneinfo/Europe"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if out := runTimezoneOp(t, root, "Europe/Warsaw"); !strings.Contains(out, timezoneSetMarker) {
		t.Fatalf("first run must set the zone, got %q", out)
	}
	if link, _ := os.Readlink(filepath.Join(root, "etc", "localtime")); link != root+"/zoneinfo/Europe/Warsaw" {
		t.Errorf("localtime -> %q", link)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "timezone")); strings.TrimSpace(string(b)) != "Europe/Warsaw" {
		t.Errorf("/etc/timezone = %q", b)
	}

	if out := runTimezoneOp(t, root, "Europe/Warsaw"); strings.Contains(out, timezoneSetMarker) {
		t.Errorf("matching zone must be a no-op, got %q", out)
	}

	if out := runTimezoneOp(t, root, ""); !strings.Contains(out, timezoneSetMarker) {
		t.Errorf("empty zone must reset to UTC, got %q", out)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc", "timezone")); strings.TrimSpace(string(b)) != "UTC" {
		t.Errorf("/etc/timezone after reset = %q", b)
	}
}

// A failure is reported via the marker, not by failing the shared batch.
func TestTimezoneOp_FailureDoesNotFailBatch(t *testing.T) {
	root := t.TempDir() // no etc/ dir: the write fails
	if out := runTimezoneOp(t, root, "UTC"); !strings.Contains(out, timezoneFailedMarker) {
		t.Errorf("want the failure marker, got %q", out)
	}
}

func TestReportTimezone(t *testing.T) {
	var logs []string
	logf := func(m string) { logs = append(logs, m) }
	reportTimezone("", "Europe/Warsaw", logf)
	if len(logs) != 0 {
		t.Errorf("no-op must log nothing, got %v", logs)
	}
	reportTimezone("x\n"+timezoneSetMarker+"\n", "", logf)
	reportTimezone(timezoneFailedMarker, "Europe/Warsaw", logf)
	if len(logs) != 2 || logs[0] != "Set container timezone to UTC" || !strings.Contains(logs[1], "Warning") {
		t.Errorf("logs = %v", logs)
	}
}

// The timezone phase makes no incus call of its own: it queues its op for
// the context-files exec.
func TestPhaseConfigureTimezone_Deferred(t *testing.T) {
	st := &setupState{opts: SetupOptions{Timezone: "Europe/Warsaw"}, result: &SetupResult{}}
	if _, err := st.phaseConfigureTimezone(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.result.Timezone != "Europe/Warsaw" {
		t.Errorf("result.Timezone = %q", st.result.Timezone)
	}
	if len(st.pendingGuestOps) != 1 || !strings.Contains(st.pendingGuestOps[0].cmd, "Europe/Warsaw") {
		t.Errorf("want one queued timezone op, got %+v", st.pendingGuestOps)
	}
}
