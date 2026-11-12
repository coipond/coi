package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// runTmpfsScript runs script with a fake systemctl that logs its calls and
// reports tmp.mount as active unless inactive is set, and a fake umount.
func runTmpfsScript(t *testing.T, dir, script string, inactive bool) (calls []string, out string) {
	t.Helper()
	logPath := filepath.Join(dir, "systemctl.log")
	_ = os.Remove(logPath)
	isActive := "0"
	if inactive {
		isActive = "3"
	}
	fake := "#!/bin/sh\necho \"$*\" >> " + logPath + "\n[ \"$1\" = is-active ] && exit " + isActive + "\nexit 0\n"
	for _, name := range []string{"systemctl", "umount"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(fake), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	log, _ := os.ReadFile(logPath)
	if s := strings.TrimSpace(string(log)); s != "" {
		calls = strings.Split(s, "\n")
	}
	return calls, strings.TrimSpace(string(b))
}

func TestTmpfsSizeScript(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "tmp.mount")
	reload := []string{"daemon-reload", "enable tmp.mount", "reload-or-restart tmp.mount"}

	if got, _ := runTmpfsScript(t, dir, tmpfsSizeScript(unit, 1<<30), false); !reflect.DeepEqual(got, reload) {
		t.Errorf("first install: systemctl %q, want %q", got, reload)
	}
	if b, _ := os.ReadFile(unit); string(b) != buildTmpMountUnit(1<<30) {
		t.Errorf("unit = %q", b)
	}
	if got, _ := runTmpfsScript(t, dir, tmpfsSizeScript(unit, 1<<30), false); !reflect.DeepEqual(got, []string{"is-active -q tmp.mount"}) {
		t.Errorf("unchanged, active: systemctl %q, want only is-active", got)
	}
	if _, err := os.Stat(unit + ".coi-new"); !os.IsNotExist(err) {
		t.Errorf("temp unit left behind: %v", err)
	}
	if got, _ := runTmpfsScript(t, dir, tmpfsSizeScript(unit, 1<<30), true); !reflect.DeepEqual(got, []string{"is-active -q tmp.mount", "start tmp.mount"}) {
		t.Errorf("unchanged, inactive: systemctl %q, want is-active + start", got)
	}
	// A restart with a new size: boot mounted the old unit, so it must be
	// remounted, not only started.
	if got, _ := runTmpfsScript(t, dir, tmpfsSizeScript(unit, 2<<30), false); !reflect.DeepEqual(got, reload) {
		t.Errorf("changed size: systemctl %q, want %q", got, reload)
	}
	if b, _ := os.ReadFile(unit); string(b) != buildTmpMountUnit(2<<30) {
		t.Errorf("unit after resize = %q", b)
	}
}

// The remove script swaps only coi's own unit for a mask and unmounts /tmp.
func TestTmpfsRemoveScript(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "tmp.mount")

	if got, out := runTmpfsScript(t, dir, tmpfsRemoveScript(unit), false); len(got) != 0 || out != "" {
		t.Errorf("no unit: systemctl %q, output %q, want nothing", got, out)
	}

	other := "[Unit]\nDescription=Temporary Directory /tmp\n"
	if err := os.WriteFile(unit, []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, out := runTmpfsScript(t, dir, tmpfsRemoveScript(unit), false); len(got) != 0 || out != "" {
		t.Errorf("foreign unit: systemctl %q, output %q, want nothing", got, out)
	}
	if b, _ := os.ReadFile(unit); string(b) != other {
		t.Errorf("foreign unit changed: %q", b)
	}

	if err := os.WriteFile(unit, []byte(buildTmpMountUnit(1<<30)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, out := runTmpfsScript(t, dir, tmpfsRemoveScript(unit), false)
	if want := []string{"disable tmp.mount", "daemon-reload", "stop tmp.mount"}; !reflect.DeepEqual(got, want) || out != "removed" {
		t.Errorf("coi unit: systemctl %q, output %q, want %q and removed", got, out, want)
	}
	if dst, err := os.Readlink(unit); err != nil || dst != "/dev/null" {
		t.Errorf("coi unit not masked: %q, %v", dst, err)
	}
}
