package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The veth comes from the cheap volatile.eth0.host_name key when that
// interface exists on the host — no full-state `incus list` (which can block
// for seconds right after a start).
func TestGetContainerVethName_UsesVolatileKey(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("no /sys/class/net/lo")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + calls + "\n" +
		"case \"$*\" in *volatile.eth0.host_name*) echo lo ;; *) echo 'unexpected' >&2; exit 1 ;; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete("c1")

	veth, err := GetContainerVethName("c1")
	if err != nil || veth != "lo" {
		t.Fatalf("got %q, %v", veth, err)
	}
	b, _ := os.ReadFile(calls)
	if strings.Contains(string(b), "--format=json") {
		t.Errorf("must not fall back to the full-state query:\n%s", b)
	}
}

// A key naming an interface that doesn't exist (stale) falls back to the
// state query.
func TestGetContainerVethName_StaleKeyFallsBack(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *volatile.eth0.host_name*) echo vethgone123 ;;\n" +
		"  *--format=json*) echo '[{\"name\":\"c2\",\"state\":{\"network\":{\"eth0\":{\"host_name\":\"vethreal\",\"addresses\":[]}}}}]' ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete("c2")
	if veth, err := GetContainerVethName("c2"); err != nil || veth != "vethreal" {
		t.Errorf("got %q, %v; want the state query's answer", veth, err)
	}
}
