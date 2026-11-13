package container

import (
	"reflect"
	"testing"
)

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

func TestEnableNICSecurity_OneCall(t *testing.T) {
	logPath := fakeIncusScript(t, "exit 0")
	if err := EnableNICSecurity("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"config device override c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true"}
	if got := incusCalls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// An already overridden NIC: the keys are set on the instance device in one call.
func TestEnableNICSecurity_AlreadyOverridden(t *testing.T) {
	logPath := fakeIncusScript(t, `case "$*" in
  *"override c1 eth0 security"*) echo "Error: refused" >&2; exit 1 ;;
esac
exit 0`)
	if err := EnableNICSecurity("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"config device override c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true",
		"config device override c1 eth0",
		"config device set c1 eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true",
	}
	if got := incusCalls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

func TestEnableNICSecurity_SetFails(t *testing.T) {
	fakeIncusScript(t, `case "$*" in
  *"eth0 security"*) echo "Error: refused" >&2; exit 1 ;;
esac
exit 0`)
	if err := EnableNICSecurity("c1"); err == nil {
		t.Error("want an error when the keys cannot be set")
	}
}

func TestDisableIPv6AtBoot_OneCall(t *testing.T) {
	logPath := fakeIncusScript(t, "exit 0")
	if err := DisableIPv6AtBoot("c1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"config set c1 linux.sysctl.net.ipv6.conf.all.disable_ipv6=1 linux.sysctl.net.ipv6.conf.default.disable_ipv6=1"}
	if got := incusCalls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}
