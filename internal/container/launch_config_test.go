package container

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeIncusFailing puts an `incus` on PATH that logs each call without the
// leading `--project <p>` and exits 1 on calls containing failOn ("" = none).
func fakeIncusFailing(t *testing.T, failOn string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls")
	script := `#!/bin/sh
shift 2
echo "$*" >> ` + logPath + `
case "$*" in
  *"` + failOn + `"*) [ -n "` + failOn + `" ] && { echo "Error: refused" >&2; exit 1; } ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	invalidateConfigCache()
	t.Cleanup(invalidateConfigCache)
	return logPath
}

func TestInitConfigArgs(t *testing.T) {
	got := InitConfigArgs(DefaultHardeningPolicy())
	want := []string{
		"-c", "security.nesting=true",
		"-c", "security.syscalls.intercept.mknod=true",
		"-c", "security.syscalls.intercept.setxattr=true",
		"-c", "linux.sysctl.net.ipv4.ip_unprivileged_port_start=0",
		"-c", "security.guestapi=false",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("default policy: got %q, want %q", got, want)
	}

	got = InitConfigArgs(HardeningPolicy{})
	want = []string{"-c", "security.guestapi=false"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("docker off: got %q, want %q", got, want)
	}

	got = InitConfigArgs(HardeningPolicy{ReduceKernelSurface: true})
	if len(got) != 4 || got[1] != "security.syscalls.deny="+kernelSurfaceDenyValue(HardeningPolicy{ReduceKernelSurface: true}) || got[3] != "security.guestapi=false" {
		t.Errorf("reduce kernel surface: got %q", got)
	}
}

// The kernel-surface policy and the guest API go in the `incus init` call;
// no `config set` runs before preStart.
func TestInitAndConfigureContainer_SettingsAtInit(t *testing.T) {
	logPath := fakeIncusFailing(t, "")
	if err := initAndConfigureContainer("img", "c1", "pool1", true, nil, HardeningPolicy{}, nil); err != nil {
		t.Fatal(err)
	}
	got := calls(t, logPath)
	if len(got) == 0 || got[0] != "init img c1 --ephemeral -s pool1 -c user.coi.managed=true -c security.guestapi=false" {
		t.Fatalf("first call = %q", got)
	}
	for _, c := range got[1:] {
		if strings.HasPrefix(c, "config set") || strings.HasPrefix(c, "init") {
			t.Errorf("unexpected write after init: %q", c)
		}
	}
}

func TestEnableNICSecurity_OneCall(t *testing.T) {
	logPath := fakeIncusFailing(t, "")
	if err := EnableNICSecurity("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"config device override c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true"}
	if got := calls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// An already overridden NIC: the keys are set on the instance device in one call.
func TestEnableNICSecurity_AlreadyOverridden(t *testing.T) {
	logPath := fakeIncusFailing(t, "override c1 eth0 security")
	if err := EnableNICSecurity("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"config device override c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true",
		"config device override c1 eth0",
		"config device set c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true",
	}
	if got := calls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestEnableNICSecurity_SetFails(t *testing.T) {
	fakeIncusFailing(t, "eth0 security")
	if err := EnableNICSecurity("c1"); err == nil {
		t.Error("want an error when the keys cannot be set")
	}
}

func TestDisableIPv6AtBoot_OneCall(t *testing.T) {
	logPath := fakeIncusFailing(t, "")
	if err := DisableIPv6AtBoot("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"config set c1 linux.sysctl.net.ipv6.conf.all.disable_ipv6=1 linux.sysctl.net.ipv6.conf.default.disable_ipv6=1"}
	if got := calls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}
