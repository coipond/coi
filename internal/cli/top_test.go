package cli

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mensfeld/coi/internal/monitor"
	"github.com/spf13/cobra"
)

func TestParseProcJiffies(t *testing.T) {
	tests := []struct {
		name string
		stat string
		want float64
		ok   bool
	}{
		{
			// Fields after comm: state ppid pgrp sid tty tpgid flags minflt
			// cminflt majflt cmajflt utime stime ...
			// -> utime=index11=100, stime=index12=50 => 150.
			name: "simple",
			stat: "1234 (bash) S 1 1234 1234 0 -1 4194560 100 200 0 0 100 50 0 0 20 0 1 0 999 0 0",
			want: 150,
			ok:   true,
		},
		{
			// comm containing spaces AND a closing paren must not break parsing.
			name: "tricky comm",
			stat: "42 (Web Content (ok)) R 1 42 42 0 -1 0 0 0 0 0 7 3 0 0 20 0 1 0 5 0 0",
			want: 10,
			ok:   true,
		},
		{name: "no paren", stat: "garbage without paren", want: 0, ok: false},
		{name: "too few fields", stat: "1 (x) S 1 2 3", want: 0, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseProcJiffies(tt.stat)
			if ok != tt.ok || got != tt.want {
				t.Errorf("parseProcJiffies(%q) = %v,%v; want %v,%v", tt.stat, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRate(t *testing.T) {
	tests := []struct {
		v0, v1, secs, want float64
	}{
		{0, 10, 2, 5},    // 10 over 2s -> 5/s
		{100, 100, 2, 0}, // no change
		{50, 10, 2, 0},   // counter reset -> clamped to 0
		{0, 5, 0, 0},     // zero interval -> 0
	}
	for _, tt := range tests {
		if got := rate(tt.v0, tt.v1, tt.secs); got != tt.want {
			t.Errorf("rate(%v,%v,%v) = %v; want %v", tt.v0, tt.v1, tt.secs, got, tt.want)
		}
	}
}

func TestNetBytes(t *testing.T) {
	e := incusTopEntry{}
	e.State = &struct {
		Network map[string]struct {
			Counters struct {
				BytesReceived int64 `json:"bytes_received"`
				BytesSent     int64 `json:"bytes_sent"`
			} `json:"counters"`
		} `json:"network"`
	}{
		Network: map[string]struct {
			Counters struct {
				BytesReceived int64 `json:"bytes_received"`
				BytesSent     int64 `json:"bytes_sent"`
			} `json:"counters"`
		}{},
	}
	set := func(iface string, rx, tx int64) {
		var c struct {
			Counters struct {
				BytesReceived int64 `json:"bytes_received"`
				BytesSent     int64 `json:"bytes_sent"`
			} `json:"counters"`
		}
		c.Counters.BytesReceived = rx
		c.Counters.BytesSent = tx
		e.State.Network[iface] = c
	}
	set("eth0", 1000, 2000)
	set("eth1", 500, 100)
	set("lo", 9999, 9999) // must be excluded

	rx, tx := e.netBytes()
	if rx != 1500 || tx != 2100 {
		t.Errorf("netBytes() = %d,%d; want 1500,2100 (loopback excluded)", rx, tx)
	}

	// Nil state (stopped/no state) is safe.
	if rx, tx := (incusTopEntry{}).netBytes(); rx != 0 || tx != 0 {
		t.Errorf("netBytes() on nil state = %d,%d; want 0,0", rx, tx)
	}
}

func TestSortContainerRows(t *testing.T) {
	rows := []containerTopRow{
		{Name: "c-low", CPUPercent: 5, MemMB: 900, DiskReadMBs: 1, NetRxMBs: 9},
		{Name: "c-high", CPUPercent: 200, MemMB: 100, DiskReadMBs: 0, NetRxMBs: 0},
		{Name: "c-mid", CPUPercent: 50, MemMB: 500, DiskWriteMBs: 8, NetTxMBs: 4},
	}

	sortContainerRows(rows, "cpu")
	if rows[0].Name != "c-high" || rows[2].Name != "c-low" {
		t.Errorf("cpu sort order wrong: %v", names(rows))
	}

	sortContainerRows(rows, "mem")
	if rows[0].Name != "c-low" {
		t.Errorf("mem sort: expected c-low first, got %v", names(rows))
	}

	sortContainerRows(rows, "disk")
	if rows[0].Name != "c-mid" {
		t.Errorf("disk sort: expected c-mid first, got %v", names(rows))
	}

	sortContainerRows(rows, "net")
	if rows[0].Name != "c-low" {
		t.Errorf("net sort: expected c-low first (rx 9), got %v", names(rows))
	}
}

func names(rows []containerTopRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Name
	}
	return out
}

func TestSortProcRows(t *testing.T) {
	rows := []procTopRow{
		{PID: 3, CPUPercent: 10, MemMB: 5},
		{PID: 1, CPUPercent: 90, MemMB: 1},
		{PID: 2, CPUPercent: 10, MemMB: 50},
	}
	sortProcRows(rows, "cpu")
	if rows[0].PID != 1 {
		t.Errorf("cpu sort: expected PID 1 first, got %d", rows[0].PID)
	}
	// Tie on CPU (PIDs 3 and 2 both 10%) breaks by PID ascending.
	if rows[1].PID != 2 || rows[2].PID != 3 {
		t.Errorf("cpu tie-break wrong: %d then %d", rows[1].PID, rows[2].PID)
	}

	sortProcRows(rows, "mem")
	if rows[0].PID != 2 {
		t.Errorf("mem sort: expected PID 2 first (50MB), got %d", rows[0].PID)
	}
}

func TestSampleContainerRows_CPUAndFilter(t *testing.T) {
	origList, origRes := topListEntries, topCollectResources
	defer func() { topListEntries, topCollectResources = origList, origRes }()

	entry := func(name, status string) incusTopEntry {
		return incusTopEntry{Name: name, Status: status, Config: map[string]string{}}
	}
	topListEntries = func() ([]incusTopEntry, error) {
		return []incusTopEntry{
			entry("coi-run-1", "Running"),
			entry("coi-stopped-1", "Stopped"), // must be filtered out
		}, nil
	}
	// t0 cpu=1.00s, t1 cpu=1.01s: a 0.01s delta over a 10ms interval => 100% CPU.
	// A tiny interval keeps the assertion while avoiding a real multi-second
	// sleep in the unit test.
	call := 0
	topCollectResources = func(_ context.Context, name string) (monitor.ResourceStats, error) {
		call++
		if call == 1 {
			return monitor.ResourceStats{CPUTimeSeconds: 1.00, MemoryMB: 128}, nil
		}
		return monitor.ResourceStats{CPUTimeSeconds: 1.01, MemoryMB: 256}, nil
	}

	rows, err := sampleContainerRows(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("sampleContainerRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 running container row, got %d: %v", len(rows), names(rows))
	}
	r := rows[0]
	if r.Name != "coi-run-1" {
		t.Errorf("expected coi-run-1, got %s", r.Name)
	}
	if r.CPUPercent < 99.9 || r.CPUPercent > 100.1 {
		t.Errorf("CPUPercent = %.2f; want ~100", r.CPUPercent)
	}
	if r.MemMB != 256 {
		t.Errorf("MemMB = %.0f; want 256 (second sample)", r.MemMB)
	}
}

func TestSampleContainerRows_MissingBaselineStaysZero(t *testing.T) {
	// A container whose t0 sample fails but t1 succeeds must NOT report the
	// cumulative counter as a single-interval delta (#707): CPU%/disk stay 0.
	origList, origRes := topListEntries, topCollectResources
	defer func() { topListEntries, topCollectResources = origList, origRes }()

	topListEntries = func() ([]incusTopEntry, error) {
		return []incusTopEntry{{Name: "coi-run-1", Status: "Running", Config: map[string]string{}}}, nil
	}
	call := 0
	topCollectResources = func(_ context.Context, _ string) (monitor.ResourceStats, error) {
		call++
		if call == 1 {
			// t0 read fails -> no baseline recorded.
			return monitor.ResourceStats{}, errors.New("cgroup not ready")
		}
		// t1: a container that has accumulated 9000 CPU-seconds and 500MB of I/O
		// over its lifetime. Without the baseline guard this would render as a
		// wildly inflated rate.
		return monitor.ResourceStats{CPUTimeSeconds: 9000, MemoryMB: 256, IOReadMB: 500}, nil
	}

	rows, err := sampleContainerRows(context.Background(), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("sampleContainerRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.CPUPercent != 0 {
		t.Errorf("CPUPercent = %.2f; want 0 when t0 baseline is missing", r.CPUPercent)
	}
	if r.DiskReadMBs != 0 {
		t.Errorf("DiskReadMBs = %.2f; want 0 when t0 baseline is missing", r.DiskReadMBs)
	}
	if r.MemMB != 256 {
		t.Errorf("MemMB = %.0f; want 256 (instantaneous, no baseline needed)", r.MemMB)
	}
}

func TestSampleContainerRows_NoneRunning(t *testing.T) {
	origList := topListEntries
	defer func() { topListEntries = origList }()
	topListEntries = func() ([]incusTopEntry, error) {
		return []incusTopEntry{{Name: "coi-x", Status: "Stopped"}}, nil
	}
	rows, err := sampleContainerRows(context.Background(), time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rows != nil {
		t.Errorf("expected nil rows when nothing is running, got %v", names(rows))
	}
}

func TestSampleProcessRows_Self(t *testing.T) {
	// Fake the container-process discovery to return THIS test process, so the
	// real /proc jiffies/RSS reads have a live PID to work against.
	orig := topCollectProcesses
	defer func() { topCollectProcesses = orig }()
	self := os.Getpid()
	topCollectProcesses = func(_ context.Context, _ string) (monitor.ProcessStats, error) {
		return monitor.ProcessStats{
			Available:  true,
			TotalCount: 1,
			Processes:  []monitor.Process{{PID: self, User: "1000", Command: "top.test"}},
		}, nil
	}

	rows, err := sampleProcessRows(context.Background(), []string{"coi-x"}, 10*time.Millisecond, true)
	if err != nil {
		t.Fatalf("sampleProcessRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].PID != self {
		t.Errorf("PID = %d; want self %d", rows[0].PID, self)
	}
	if rows[0].MemMB <= 0 {
		t.Errorf("MemMB = %v; want > 0 (live RSS)", rows[0].MemMB)
	}
	if rows[0].Container != "coi-x" {
		t.Errorf("Container = %q; want coi-x", rows[0].Container)
	}
}

func TestSampleProcessRows_StrictPropagatesError(t *testing.T) {
	orig := topCollectProcesses
	defer func() { topCollectProcesses = orig }()
	topCollectProcesses = func(_ context.Context, _ string) (monitor.ProcessStats, error) {
		return monitor.ProcessStats{}, errors.New("cgroup gone")
	}
	// strict=true (a single named container) surfaces the error...
	if _, err := sampleProcessRows(context.Background(), []string{"coi-x"}, time.Millisecond, true); err == nil {
		t.Error("strict sampleProcessRows should return the collection error")
	}
	// ...best-effort (strict=false) skips it and returns an empty (non-nil) slice.
	rows, err := sampleProcessRows(context.Background(), []string{"coi-x"}, time.Millisecond, false)
	if err != nil {
		t.Fatalf("best-effort sampleProcessRows: %v", err)
	}
	if rows == nil {
		t.Error("rows should be non-nil (marshals to [] not null) even when all containers fail")
	}
}

func TestRunTopWatch_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: one render pass runs, then the loop exits.

	calls := 0
	err := runTopWatch(ctx, func() error { calls++; return nil }, 1)
	if err != nil {
		t.Fatalf("runTopWatch returned %v; want nil on cancel", err)
	}
	if calls != 1 {
		t.Errorf("render called %d times; want exactly 1 before cancel", calls)
	}
}

func TestRunTop_JSONWithWatchRejected(t *testing.T) {
	// Save/restore the flag globals the command binds to.
	oi, os_, op, oj, ow := topInterval, topSort, topProcs, topJSON, topWatch
	defer func() { topInterval, topSort, topProcs, topJSON, topWatch = oi, os_, op, oj, ow }()
	topInterval, topSort, topProcs, topJSON, topWatch = 2, "cpu", false, true, 2

	err := runTop(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("expected error for --json with --watch")
	}
	var ec *ExitCodeError
	if !errors.As(err, &ec) || ec.Code != 2 {
		t.Errorf("expected ExitCodeError code 2, got %v", err)
	}
}

func TestValidateSortKey(t *testing.T) {
	// Canonical keys (any case) pass; unknown keys are rejected with exit 2.
	for _, k := range []string{"cpu", "CPU", "mem", "disk", "net"} {
		if err := validateSortKey(k, containerSortKeys); err != nil {
			t.Errorf("validateSortKey(%q, container) = %v; want nil", k, err)
		}
	}
	if err := validateSortKey("disk", procSortKeys); err == nil {
		t.Error("validateSortKey(disk, proc) = nil; want error (disk is container-only)")
	}
	err := validateSortKey("ram", containerSortKeys)
	if err == nil {
		t.Fatal("validateSortKey(ram) = nil; want error")
	}
	var ec *ExitCodeError
	if !errors.As(err, &ec) || ec.Code != 2 {
		t.Errorf("expected ExitCodeError code 2, got %v", err)
	}
}

func TestCollapseHome(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cases := map[string]string{
		"/home/tester":          "~",
		"/home/tester/work/api": "~/work/api",
		"/opt/other":            "/opt/other",
		"":                      "",
	}
	for in, want := range cases {
		if got := collapseHome(in); got != want {
			t.Errorf("collapseHome(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestFormatMem(t *testing.T) {
	// 256 MB, no limit.
	if got := formatMem(256, 0); got != "256.0 MB" {
		t.Errorf("formatMem(256,0) = %q; want 256.0 MB", got)
	}
	// With a limit, both sides shown.
	if got := formatMem(256, 1024); got != "256.0 MB/1.0 GB" {
		t.Errorf("formatMem(256,1024) = %q; want 256.0 MB/1.0 GB", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 60); got != "short" {
		t.Errorf("truncate kept-short = %q", got)
	}
	long := "0123456789"
	if got := truncate(long, 5); got != "0123…" {
		t.Errorf("truncate(%q,5) = %q; want 0123…", long, got)
	}
}
