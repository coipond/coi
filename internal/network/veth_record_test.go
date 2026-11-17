package network

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A recorded veth is listed until forgotten; recording a new one drops the
// records of interfaces that are gone.
func TestHostVethRecords(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("no /sys/class/net/lo")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got, err := RecordedHostVeths(); err != nil || got != nil {
		t.Fatalf("no records: got %v, %v", got, err)
	}

	recordHostVeth("vethgone")
	recordHostVeth("lo")
	recordHostVeth("../x")
	if got, err := RecordedHostVeths(); err != nil || !reflect.DeepEqual(got, []string{"lo"}) {
		t.Fatalf("RecordedHostVeths() = %v, %v, want [lo]", got, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".coi", "x")); err == nil {
		t.Error("recorded a name outside the records dir")
	}

	if err := ForgetHostVeth("lo"); err != nil {
		t.Fatal(err)
	}
	if err := ForgetHostVeth("lo"); err != nil {
		t.Errorf("forgetting a missing record: %v", err)
	}
	if got, _ := RecordedHostVeths(); len(got) != 0 {
		t.Errorf("after forget: %v", got)
	}
}

func TestGetContainerVethName_RecordsVeth(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("no /sys/class/net/lo")
	}
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in *volatile.eth0.host_name*) echo lo ;; *) exit 1 ;; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete("c-rec")

	if _, err := GetContainerVethName("c-rec"); err != nil {
		t.Fatal(err)
	}
	if got, _ := RecordedHostVeths(); !reflect.DeepEqual(got, []string{"lo"}) {
		t.Errorf("RecordedHostVeths() = %v, want [lo]", got)
	}
}

// An instance-state lookup (the IP poll, open mode's only network lookup)
// records the veth too.
func TestGetContainerIP_RecordsVeth(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("no /sys/class/net/lo")
	}
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		"  'query /1.0/instances/c-ip?recursion=1&project=default') echo '{\"state\":{\"network\":{\"eth0\":{\"host_name\":\"lo\",\"addresses\":[{\"family\":\"inet\",\"address\":\"10.0.0.5\"}]}}}}' ;;\n" +
		"  *) exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete("c-ip")
	t.Cleanup(func() { instanceNetCache.Delete("c-ip") })

	if ip, err := GetContainerIPWithRetries("c-ip", 1); err != nil || ip != "10.0.0.5" {
		t.Fatalf("got %q, %v", ip, err)
	}
	if got, _ := RecordedHostVeths(); !reflect.DeepEqual(got, []string{"lo"}) {
		t.Errorf("RecordedHostVeths() = %v, want [lo]", got)
	}
}
