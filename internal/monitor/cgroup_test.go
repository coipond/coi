package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitPIDFromCgroupProcs_SingleProc(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1234\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, err := initPIDFromCgroupProcs(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 1234 {
		t.Errorf("want 1234 got %d", pid)
	}
}

func TestInitPIDFromCgroupProcs_ReturnsMinimum(t *testing.T) {
	// Simulate a systemd container: PID 1 is in init.scope, other processes
	// are in sub-cgroups with higher PIDs.
	dir := t.TempDir()

	// Root cgroup.procs is empty (systemd moves all procs to sub-cgroups).
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	initScope := filepath.Join(dir, "init.scope")
	if err := os.MkdirAll(initScope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(initScope, "cgroup.procs"), []byte("500\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	svcSlice := filepath.Join(dir, "system.slice", "ssh.service")
	if err := os.MkdirAll(svcSlice, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcSlice, "cgroup.procs"), []byte("800\n900\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pid, err := initPIDFromCgroupProcs(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 500 {
		t.Errorf("want 500 (minimum) got %d", pid)
	}
}

func TestInitPIDFromCgroupProcs_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := initPIDFromCgroupProcs(dir)
	if err == nil {
		t.Error("expected error for empty cgroup.procs, got nil")
	}
}

func TestInitPIDFromCgroupProcs_NonexistentPath(t *testing.T) {
	_, err := initPIDFromCgroupProcs("/nonexistent/cgroup/path")
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}

func TestParseInitPIDFromIncusInfo_Valid(t *testing.T) {
	output := `Name: mycontainer
Status: Running
Type: container
Architecture: x86_64
PID: 42317
Created: 2026/06/01 12:00 UTC`
	pid, err := parseInitPIDFromIncusInfo(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 42317 {
		t.Errorf("want 42317 got %d", pid)
	}
}

func TestParseInitPIDFromIncusInfo_CaseInsensitive(t *testing.T) {
	output := "Pid: 99\n"
	pid, err := parseInitPIDFromIncusInfo(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != 99 {
		t.Errorf("want 99 got %d", pid)
	}
}

func TestParseInitPIDFromIncusInfo_Missing(t *testing.T) {
	output := "Name: mycontainer\nStatus: Stopped\n"
	_, err := parseInitPIDFromIncusInfo(output)
	if err == nil {
		t.Error("expected error when PID line absent, got nil")
	}
}

// wellKnownCgroupPaths must probe the container's payload cgroup before its
// monitor cgroup: on a monitor/payload-split layout the monitor holds only the
// host-side forkstart process, so preferring it would make GetCgroupPath
// under-report resources and GetContainerInitPID return the monitor's PID. Each
// payload candidate must appear at a lower index than every monitor candidate.
func TestWellKnownCgroupPaths_PayloadBeforeMonitor(t *testing.T) {
	paths := wellKnownCgroupPaths("coi-abc-1")

	indexOf := func(substr string) int {
		for i, p := range paths {
			if strings.Contains(p, substr) {
				return i
			}
		}
		return -1
	}

	payloadIdx := indexOf(".payload")
	monitorIdx := indexOf(".monitor/")
	if payloadIdx == -1 {
		t.Fatalf("expected a .payload candidate in %v", paths)
	}
	if monitorIdx == -1 {
		t.Fatalf("expected a .monitor candidate in %v", paths)
	}
	if payloadIdx >= monitorIdx {
		t.Errorf("payload cgroup (idx %d) must be probed before monitor cgroup (idx %d): %v",
			payloadIdx, monitorIdx, paths)
	}
	// Every candidate must be under the container's own name (no cross-container match).
	for _, p := range paths {
		if !strings.HasSuffix(p, "/coi-abc-1") && !strings.HasSuffix(p, ".payload.coi-abc-1") {
			t.Errorf("candidate %q is not scoped to the container name", p)
		}
	}
}

// stripSystemdScopeSuffix must strip the init.scope (or any systemd
// scope/service) leaf that GetCgroupPath's incus-info fallback returns, so
// resource stats read the container root whose v2 counters aggregate the whole
// tree — not init.scope, which only accounts for systemd PID 1. It strips a
// single leaf (the ≤1-level contract), so a deeper path yields its parent, not
// the container root; a path whose leaf is neither .scope nor .service is
// returned unchanged.
func TestStripSystemdScopeSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"init.scope stripped", "/sys/fs/cgroup/incus.payload/coi-abc-1/init.scope", "/sys/fs/cgroup/incus.payload/coi-abc-1"},
		{"single leaf only (deeper path not fully resolved)", "/sys/fs/cgroup/lxc.payload/coi-abc-1/system.slice/foo.service", "/sys/fs/cgroup/lxc.payload/coi-abc-1/system.slice"},
		{"already root unchanged", "/sys/fs/cgroup/incus.payload/coi-abc-1", "/sys/fs/cgroup/incus.payload/coi-abc-1"},
		{"monitor root unchanged", "/sys/fs/cgroup/incus.monitor/coi-abc-1", "/sys/fs/cgroup/incus.monitor/coi-abc-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripSystemdScopeSuffix(tc.in); got != tc.want {
				t.Errorf("stripSystemdScopeSuffix(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Incus 7.5 on cgroup2 names the payload cgroup lxc.payload.<name> (a dot, not
// a directory). It must be probed, and before the slash forms, or every lookup
// on such a host falls back to one incus info per container.
func TestWellKnownCgroupPaths_DotPayloadFirst(t *testing.T) {
	paths := wellKnownCgroupPaths("coi-abc-1")
	if want := "/sys/fs/cgroup/lxc.payload.coi-abc-1"; len(paths) == 0 || paths[0] != want {
		t.Fatalf("first candidate: want %q (all: %v)", want, paths)
	}
}
