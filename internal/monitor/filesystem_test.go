package monitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// counterDelta must clamp a backwards-going cumulative counter to 0 instead of
// underflowing. A cgroup io counter reads lower than the prior sample when
// CollectResourceStats' io-error branch returns IOReadMB=0; unguarded unsigned
// subtraction would wrap to ~2^64 bytes and spuriously trip large-read
// detection, freezing a healthy container.
func TestCounterDelta(t *testing.T) {
	cases := []struct {
		name              string
		current, previous uint64
		want              uint64
	}{
		{"normal increase", 100, 40, 60},
		{"no change", 100, 100, 0},
		{"backwards (transient io-error zero)", 0, 50 * 1024 * 1024, 0},
		{"backwards (counter reset)", 10, 1_000_000, 0},
		{"from zero baseline", 60, 0, 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := counterDelta(tc.current, tc.previous); got != tc.want {
				t.Errorf("counterDelta(%d, %d) = %d, want %d", tc.current, tc.previous, got, tc.want)
			}
		})
	}
}

func TestParseDfBMOutput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantUsed    float64
		wantTotal   float64
		wantPercent float64
	}{
		{
			name:        "typical tmpfs",
			input:       "Filesystem     1M-blocks  Used Available Use% Mounted on\ntmpfs              2048M  100M     1948M   5% /tmp\n",
			wantUsed:    100,
			wantTotal:   2048,
			wantPercent: 5,
		},
		{
			name:        "full tmpfs",
			input:       "Filesystem     1M-blocks  Used Available Use% Mounted on\ntmpfs               512M  512M        0M 100% /tmp\n",
			wantUsed:    512,
			wantTotal:   512,
			wantPercent: 100,
		},
		{
			name:        "empty output",
			input:       "",
			wantUsed:    0,
			wantTotal:   0,
			wantPercent: 0,
		},
		{
			name:        "header only",
			input:       "Filesystem     1M-blocks  Used Available Use% Mounted on\n",
			wantUsed:    0,
			wantTotal:   0,
			wantPercent: 0,
		},
		{
			name:        "large tmpfs",
			input:       "Filesystem     1M-blocks    Used Available Use% Mounted on\ntmpfs             16384M  8192M     8192M  50% /tmp\n",
			wantUsed:    8192,
			wantTotal:   16384,
			wantPercent: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			used, total, pct := parseDfBMOutput(tt.input)
			if used != tt.wantUsed {
				t.Errorf("used: got %v want %v", used, tt.wantUsed)
			}
			if total != tt.wantTotal {
				t.Errorf("total: got %v want %v", total, tt.wantTotal)
			}
			if pct != tt.wantPercent {
				t.Errorf("percent: got %v want %v", pct, tt.wantPercent)
			}
		})
	}
}

// fakeDfIncus puts an `incus` script on PATH that runs body.
func fakeDfIncus(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestCollectDiskSpaceViaIncusExec(t *testing.T) {
	fakeDfIncus(t, `printf 'Filesystem 1M-blocks Used Available Use%% Mounted on\ntmpfs 64M 58M 6M 91%% /tmp\n'`)

	used, total, pct, err := collectDiskSpaceViaIncusExec(t.Context(), "c1")
	if err != nil {
		t.Fatalf("collectDiskSpaceViaIncusExec: %v", err)
	}
	if used != 58 || total != 64 || pct != 91 {
		t.Errorf("got used=%v total=%v pct=%v, want 58/64/91", used, total, pct)
	}
}

// A df that prints nothing parseable must fail, not report an empty /tmp.
func TestCollectDiskSpaceViaIncusExecUnparseable(t *testing.T) {
	fakeDfIncus(t, `echo garbage`)

	if _, _, _, err := collectDiskSpaceViaIncusExec(t.Context(), "c1"); err == nil {
		t.Fatal("want an error for unparseable df output")
	}
}

// A hung incus exec must not block the poll: the collector waits for every
// source, so one stuck df would stop all detection for the container.
func TestCollectDiskSpaceViaIncusExecTimesOut(t *testing.T) {
	fakeDfIncus(t, `exec sleep 30`)
	old := diskSpaceExecTimeout
	diskSpaceExecTimeout = 200 * time.Millisecond
	t.Cleanup(func() { diskSpaceExecTimeout = old })

	start := time.Now()
	_, _, _, err := collectDiskSpaceViaIncusExec(t.Context(), "c1")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("df fallback took %v, want it bounded by the timeout", elapsed)
	}
}

func TestDiskSpaceTransition(t *testing.T) {
	fm := NewFilesystemMonitor()
	boom := errors.New("boom")

	steps := []struct {
		in   error
		want error
	}{
		{nil, nil},
		{boom, boom},
		{boom, nil},
		{nil, nil},
		{boom, boom},
	}
	for i, s := range steps {
		if got := fm.diskSpaceTransition(s.in); !errors.Is(got, s.want) || (got == nil) != (s.want == nil) {
			t.Errorf("step %d: diskSpaceTransition(%v) = %v, want %v", i, s.in, got, s.want)
		}
	}
}

// A failing disk-space read is a snapshot error on the first failing poll
// only, and a recovered read reports again on the next failure.
func TestCollectorReportsDiskSpaceFailureOnce(t *testing.T) {
	fakeDfIncus(t, `exit 1`)
	oldStats, oldDisk := filesystemResourceStats, collectDiskSpace
	t.Cleanup(func() { filesystemResourceStats, collectDiskSpace = oldStats, oldDisk })
	filesystemResourceStats = func(context.Context, string) (ResourceStats, error) {
		return ResourceStats{}, nil
	}
	diskErr := errors.New("df failed")
	collectDiskSpace = func(context.Context, string) (float64, float64, float64, error) {
		if diskErr != nil {
			return 0, 0, 0, diskErr
		}
		return 10, 64, 15.6, nil
	}

	c := NewCollector("c1", "", "/workspace", nil)
	diskErrors := func() []string {
		t.Helper()
		snapshot, err := c.Collect(t.Context())
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		var got []string
		for _, e := range snapshot.Errors {
			if strings.HasPrefix(e, "disk space: ") {
				got = append(got, e)
			}
		}
		return got
	}

	if got := diskErrors(); len(got) != 1 || got[0] != "disk space: df failed" {
		t.Fatalf("first failing poll: got %q, want one disk space error", got)
	}
	if got := diskErrors(); len(got) != 0 {
		t.Fatalf("second failing poll: got %q, want none", got)
	}
	diskErr = nil
	if got := diskErrors(); len(got) != 0 {
		t.Fatalf("recovered poll: got %q, want none", got)
	}
	diskErr = errors.New("df failed again")
	if got := diskErrors(); len(got) != 1 {
		t.Fatalf("failing again: got %q, want one disk space error", got)
	}
}
