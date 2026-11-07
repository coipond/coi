package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSizeBytes(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"256MiB", 256 << 20, true},
		{"2GiB", 2 << 30, true},
		{"1024MiB", 1024 << 20, true},
		{"512KiB", 512 << 10, true},
		{"1TiB", 1 << 40, true},
		{"256M", 256 << 20, true},        // bare binary suffix
		{"2G", 2 << 30, true},            // bare binary suffix
		{"1000MB", 1000 * 1e6, true},     // SI (decimal)
		{"1GB", 1e9, true},               // SI
		{"1073741824", 1073741824, true}, // plain bytes
		{"1073741824B", 1073741824, true},
		{" 256MiB ", 256 << 20, true}, // surrounding space
		{"256mib", 256 << 20, true},   // case-insensitive
		{"", 0, false},
		{"abc", 0, false},
		{"12x", 0, false},
	}
	for _, tt := range tests {
		got, err := parseSizeBytes(tt.in)
		if tt.ok {
			if err != nil {
				t.Errorf("parseSizeBytes(%q) unexpected error: %v", tt.in, err)
				continue
			}
			if got != tt.want {
				t.Errorf("parseSizeBytes(%q) = %d, want %d", tt.in, got, tt.want)
			}
		} else if err == nil {
			t.Errorf("parseSizeBytes(%q) = %d, want error", tt.in, got)
		}
	}
}

func TestBuildTmpMountUnit(t *testing.T) {
	got := buildTmpMountUnit(256 << 20)
	for _, want := range []string{
		"[Mount]",
		"What=tmpfs",
		"Where=/tmp",
		"Type=tmpfs",
		"size=268435456", // 256 MiB in bytes
		"mode=1777",
		"WantedBy=local-fs.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("tmp.mount unit missing %q; got:\n%s", want, got)
		}
	}
}

// The tmp.mount script reloads systemd only when the unit changes.
func TestTmpfsSizeScript_SkipsUnchangedUnit(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "tmp.mount")
	logPath := filepath.Join(dir, "systemctl.log")
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho \"$*\" >> "+logPath+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(size int64) []string {
		t.Helper()
		_ = os.Remove(logPath)
		cmd := exec.Command("sh", "-c", tmpfsSizeScript(unit, size))
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		b, _ := os.ReadFile(logPath)
		return strings.Fields(strings.TrimSpace(string(b)))
	}

	if got := run(1 << 30); len(got) == 0 {
		t.Fatal("first install did not run systemctl")
	}
	if b, _ := os.ReadFile(unit); string(b) != buildTmpMountUnit(1<<30) {
		t.Errorf("unit = %q", b)
	}
	if got := run(1 << 30); len(got) != 0 {
		t.Errorf("unchanged unit ran systemctl %q", got)
	}
	if _, err := os.Stat(unit + ".coi-new"); !os.IsNotExist(err) {
		t.Errorf("temp unit left behind: %v", err)
	}
	if got := run(2 << 30); len(got) == 0 {
		t.Error("changed size did not run systemctl")
	}
	if b, _ := os.ReadFile(unit); string(b) != buildTmpMountUnit(2<<30) {
		t.Errorf("unit after resize = %q", b)
	}
}
