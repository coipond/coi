package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The veth comes from the cheap volatile.eth0.host_name key when that
// interface exists on the host — no instance query (which can block for
// seconds right after a start).
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
	if strings.Contains(string(b), "query ") {
		t.Errorf("must not fall back to the instance query:\n%s", b)
	}
}

// A key naming an interface that doesn't exist (stale) falls back to the
// instance query.
func TestGetContainerVethName_StaleKeyFallsBack(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in\n" +
		"  *volatile.eth0.host_name*) echo vethgone123 ;;\n" +
		"  'query /1.0/instances/c2?recursion=1&project=default') echo '{\"state\":{\"network\":{\"eth0\":{\"host_name\":\"vethreal\",\"addresses\":[]}}}}' ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete("c2")
	if veth, err := GetContainerVethName("c2"); err != nil || veth != "vethreal" {
		t.Errorf("got %q, %v; want the instance query's answer", veth, err)
	}
}

// gatewayFakeIncus puts a fake `incus` on PATH: the container's eth0 is on
// network, and `network show` prints each network's ipv4.address.
func gatewayFakeIncus(t *testing.T, containerName, network string) string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + calls + "\ncase \"$*\" in\n" +
		"  'query /1.0/instances/" + containerName + "?recursion=1&project=default') echo '{\"name\":\"" + containerName + "\",\"expanded_devices\":{\"eth0\":{\"type\":\"nic\",\"network\":\"" + network + "\"}},\"state\":{\"network\":{}}}' ;;\n" +
		"  *'network show incusbr0'*) printf 'config:\\n  ipv4.address: 10.10.0.1/24\\n' ;;\n" +
		"  *'network show coinet1'*) printf 'config:\\n  ipv4.address: 10.20.0.1/24\\n' ;;\n" +
		"  *) echo 'unexpected' >&2; exit 1 ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Delete(containerName)
	gatewayMu.Lock()
	prevGateways := gatewayByNetwork
	gatewayByNetwork = map[string]string{}
	gatewayMu.Unlock()
	t.Cleanup(func() {
		gatewayMu.Lock()
		gatewayByNetwork = prevGateways
		gatewayMu.Unlock()
	})
	return calls
}

// The gateway comes from the network the container's eth0 is attached to,
// never from the default profile.
func TestGetContainerGatewayIP_ContainerNetwork(t *testing.T) {
	for _, c := range []struct{ network, want string }{
		{"incusbr0", "10.10.0.1"},
		{"coinet1", "10.20.0.1"},
	} {
		t.Run(c.network, func(t *testing.T) {
			calls := gatewayFakeIncus(t, "gw1", c.network)
			gw, err := getContainerGatewayIP("gw1")
			if err != nil || gw != c.want {
				t.Fatalf("got %q, %v; want %q", gw, err, c.want)
			}
			b, _ := os.ReadFile(calls)
			if strings.Contains(string(b), "profile") {
				t.Errorf("must not read the default profile:\n%s", b)
			}
		})
	}
}

// A container whose eth0 names no network fails closed.
func TestGetContainerGatewayIP_NoNetwork(t *testing.T) {
	gatewayFakeIncus(t, "gw2", "")
	if gw, err := getContainerGatewayIP("gw2"); err == nil {
		t.Errorf("got %q, want an error", gw)
	}
}
