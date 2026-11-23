package monitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
	fm := NewFilesystemMonitor("")
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

func TestCollectorReportsDiskSpaceFailureOnce(t *testing.T) {
	fakeDfIncus(t, `exit 1`)
	oldStats, oldDisk := filesystemIOStats, collectDiskSpace
	t.Cleanup(func() { filesystemIOStats, collectDiskSpace = oldStats, oldDisk })
	filesystemIOStats = func(context.Context, string, string) (ioStats, error) {
		return ioStats{}, nil
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

func TestReadIOStatsDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "io.stat")
	stat := "252:1 rbytes=1000 wbytes=2000 rios=1 wios=1\n" +
		"259:0 rbytes=10 wbytes=20 rios=1 wios=1\n"
	if err := os.WriteFile(path, []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		device      string
		read, write float64
	}{
		{"", 1010, 2020},
		{"252:1", 1000, 2000},
		{"8:0", 0, 0},
	}
	for _, tt := range tests {
		got, err := readIOStats(path, tt.device)
		if err != nil {
			t.Fatalf("readIOStats(%q): %v", tt.device, err)
		}
		if got.read != tt.read || got.write != tt.write {
			t.Errorf("readIOStats(%q) = %+v, want read=%v write=%v", tt.device, got, tt.read, tt.write)
		}
	}
}

// fakeSysDevBlock points sysDevBlock at a fake sysfs with the given disks and
// partitions (partition "major:minor" -> its disk's).
func fakeSysDevBlock(t *testing.T, disks []string, partitions map[string]string) {
	t.Helper()
	root := t.TempDir()
	byDev := filepath.Join(root, "dev", "block")
	if err := os.MkdirAll(byDev, 0o755); err != nil {
		t.Fatal(err)
	}
	add := func(dev, dir string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dev"), []byte(dev+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, filepath.Join(byDev, dev)); err != nil {
			t.Fatal(err)
		}
	}
	diskDir := func(dev string) string {
		return filepath.Join(root, "devices", strings.ReplaceAll(dev, ":", "-"))
	}
	for _, dev := range disks {
		add(dev, diskDir(dev))
	}
	for dev, disk := range partitions {
		dir := filepath.Join(diskDir(disk), strings.ReplaceAll(dev, ":", "-"))
		add(dev, dir)
		if err := os.WriteFile(filepath.Join(dir, "partition"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := sysDevBlock
	t.Cleanup(func() { sysDevBlock = old })
	sysDevBlock = byDev
}

func TestIODevice(t *testing.T) {
	fakeSysDevBlock(t, []string{"252:1", "252:2", "259:0", "8:0"},
		map[string]string{"259:3": "259:0", "259:4": "259:0", "8:1": "8:0"})
	dev := unix.Mkdev
	tests := []struct {
		name          string
		workspace, fs uint64
		want          string
	}{
		{"own disk", dev(252, 1), dev(252, 2), "252:1"},
		{"partition: its disk", dev(259, 3), dev(8, 1), "259:0"},
		{"shares rootfs device", dev(252, 1), dev(252, 1), ""},
		{"partitions of one disk", dev(259, 3), dev(259, 4), ""},
		{"partition and its disk", dev(259, 3), dev(259, 0), ""},
		{"workspace has no block device", dev(0, 70), dev(252, 1), ""},
		{"rootfs has no block device (zfs, btrfs)", dev(252, 1), dev(0, 70), ""},
		{"unknown workspace device", dev(7, 9), dev(252, 1), ""},
		{"unknown rootfs device", dev(252, 1), dev(7, 9), ""},
	}
	for _, tt := range tests {
		if got := ioDevice(tt.workspace, tt.fs); got != tt.want {
			t.Errorf("%s: ioDevice = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestCollectContainerRootDevice(t *testing.T) {
	fakeDfIncus(t, `case "$*" in *"exec c1 -- stat -c %d /"*) echo 64513 ;; *) exit 1 ;; esac`)

	got, err := collectContainerRootDevice(t.Context(), "c1")
	if err != nil {
		t.Fatalf("collectContainerRootDevice: %v", err)
	}
	if got != unix.Mkdev(252, 1) {
		t.Errorf("collectContainerRootDevice = %d, want %d", got, unix.Mkdev(252, 1))
	}
}

func TestWorkspaceIODeviceFallsBackToContainer(t *testing.T) {
	old := containerRootDevice
	t.Cleanup(func() { containerRootDevice = old })
	containerRootDevice = func(context.Context, string) (uint64, error) {
		return 0, errors.New("exec failed")
	}

	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if got := workspaceIODevice(t.Context(), "c1", path); got != "" {
			t.Errorf("workspaceIODevice(%q) = %q, want whole container", path, got)
		}
	}
}

func TestFilesystemMonitorCountsWorkspaceDevice(t *testing.T) {
	oldStats, oldDisk, oldRoot := filesystemIOStats, collectDiskSpace, containerRootDevice
	t.Cleanup(func() { filesystemIOStats, collectDiskSpace, containerRootDevice = oldStats, oldDisk, oldRoot })
	collectDiskSpace = func(context.Context, string) (float64, float64, float64, error) {
		return 0, 0, 0, nil
	}
	// The package dir, not t.TempDir(): /tmp is often tmpfs or zfs.
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(workspace, &st); err != nil {
		t.Fatal(err)
	}
	if unix.Major(st.Dev) == 0 {
		t.Skip("package dir has no block device")
	}
	want := fmt.Sprintf("%d:%d", unix.Major(st.Dev), unix.Minor(st.Dev))
	rootDev := unix.Mkdev(unix.Major(st.Dev)+1, 0)
	fakeSysDevBlock(t, []string{want, fmt.Sprintf("%d:0", unix.Major(rootDev))}, nil)
	containerRootDevice = func(context.Context, string) (uint64, error) {
		return rootDev, nil
	}
	var devices []string
	written := 0.0
	filesystemIOStats = func(_ context.Context, _ string, device string) (ioStats, error) {
		devices = append(devices, device)
		written += 100 * 1024 * 1024
		return ioStats{write: written}, nil
	}

	fm := NewFilesystemMonitor(workspace)
	if _, err := fm.Collect(t.Context(), "c1"); err != nil {
		t.Fatal(err)
	}
	stats, err := fm.Collect(t.Context(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 || devices[0] != want || devices[1] != want {
		t.Errorf("io.stat devices read = %q, want %q twice", devices, want)
	}
	if stats.WorkspaceDevice != want || stats.TotalWriteMB != 100 {
		t.Errorf("stats = %+v, want device %q and 100 MB written", stats, want)
	}
}
