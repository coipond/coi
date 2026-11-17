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

// Every veth lookup for a coi container records the veth it finds.
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
