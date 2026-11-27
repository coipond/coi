package container

import (
	"reflect"
	"strings"
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

// nicConfigScript answers `config show --expanded <name>` with an eth0 carrying
// extra, then with after once a `config device override` ran.
func nicConfigScript(name, before, after string) string {
	return `case "$*" in
  *"config device override"*) touch "$(dirname "$0")/written"; exit 0 ;;
  *"config show --expanded ` + name + `") if [ -f "$(dirname "$0")/written" ]; then
      printf 'config: {}\ndevices:\n  eth0:\n    type: nic\n` + after + `'
    else
      printf 'config: {}\ndevices:\n  eth0:\n    type: nic\n` + before + `'
    fi ;;
esac
exit 0`
}

const nicKeysOn = `    security.ipv4_filtering: "true"\n    security.mac_filtering: "true"\n    security.port_isolation: "true"\n`

func TestReconcileNICSecurity_Missing(t *testing.T) {
	logPath := fakeIncusScript(t, nicConfigScript("nic-missing", "", nicKeysOn))
	changed, err := ReconcileNICSecurity("nic-missing")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v, want true, nil", changed, err)
	}
	want := []string{
		"config show --expanded nic-missing",
		"config device override nic-missing eth0 security.ipv4_filtering=true security.mac_filtering=true security.port_isolation=true",
		"config show --expanded nic-missing",
	}
	if got := incusCalls(t, logPath); !reflect.DeepEqual(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// A container that already carries the keys (here one via a truthy spelling)
// gets no write.
func TestReconcileNICSecurity_AlreadySet(t *testing.T) {
	on := `    security.ipv4_filtering: "true"\n    security.mac_filtering: "yes"\n    security.port_isolation: "true"\n`
	logPath := fakeIncusScript(t, nicConfigScript("nic-set", on, on))
	changed, err := ReconcileNICSecurity("nic-set")
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v, want false, nil", changed, err)
	}
	if got := incusCalls(t, logPath); !reflect.DeepEqual(got, []string{"config show --expanded nic-set"}) {
		t.Errorf("calls = %q, want only the read", got)
	}
}

// One key missing is enough to write.
func TestReconcileNICSecurity_OneKeyMissing(t *testing.T) {
	partial := `    security.ipv4_filtering: "true"\n    security.mac_filtering: "true"\n`
	fakeIncusScript(t, nicConfigScript("nic-partial", partial, nicKeysOn))
	if changed, err := ReconcileNICSecurity("nic-partial"); err != nil || !changed {
		t.Fatalf("changed=%v err=%v, want true, nil", changed, err)
	}
}

func TestReconcileNICSecurity_SetFails(t *testing.T) {
	fakeIncusScript(t, `case "$*" in
  *"eth0 security"*) echo "Error: refused" >&2; exit 1 ;;
  *"config show --expanded nic-fail") printf 'config: {}\ndevices:\n  eth0:\n    type: nic\n' ;;
esac
exit 0`)
	if _, err := ReconcileNICSecurity("nic-fail"); err == nil {
		t.Fatal("want an error when the keys cannot be set")
	}
}

// Keys written but not in effect (e.g. a NIC type that ignores them) fail.
func TestReconcileNICSecurity_NotInEffectAfterWrite(t *testing.T) {
	fakeIncusScript(t, nicConfigScript("nic-noeffect", "", ""))
	_, err := ReconcileNICSecurity("nic-noeffect")
	if err == nil || !strings.Contains(err.Error(), "security.ipv4_filtering") {
		t.Fatalf("want an error naming the missing keys, got %v", err)
	}
}

func TestReconcileNICSecurity_NoEth0(t *testing.T) {
	logPath := fakeIncusScript(t, `case "$*" in
  *"config show --expanded nic-none") printf 'config: {}\ndevices:\n  root:\n    type: disk\n' ;;
esac
exit 0`)
	if _, err := ReconcileNICSecurity("nic-none"); err == nil {
		t.Fatal("want an error for a container without eth0")
	}
	if got := incusCalls(t, logPath); len(got) != 1 {
		t.Errorf("calls = %q, want only the read", got)
	}
}
