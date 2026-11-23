package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/logger"
)

// fakeRecordEnv gives the test its own HOME and an incus on PATH that logs its
// calls and answers nothing. It returns the incus log.
func fakeRecordEnv(t *testing.T) (logPath string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return fakeIncus(t)
}

// readRecord renders containerName's runtime host ports record as
// "<ip>:<ports> ..." ("" when there is none).
func readRecord(t *testing.T, containerName string) string {
	t.Helper()
	entries, err := defaultCacheManager().LoadHostPorts(containerName)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, fmt.Sprintf("%s:%v", e.IP, e.Ports))
	}
	return strings.Join(out, " ")
}

// seedRecord writes a runtime host ports record left by an earlier session.
func seedRecord(t *testing.T, containerName string) {
	t.Helper()
	if err := defaultCacheManager().SaveHostPorts(containerName, []config.HostEntry{{IP: "203.0.113.10", Ports: []int{8080}}}); err != nil {
		t.Fatal(err)
	}
}

// A second `coi hosts add --ports` keeps the first entry's ports.
func TestRecordRuntimeHostPorts_Merges(t *testing.T) {
	c := "coi-rhp-merge"
	fakeRecordEnv(t)
	if err := recordRuntimeHostPorts(c, config.HostEntry{IP: "192.168.1.50", Ports: []int{8080}}); err != nil {
		t.Fatal(err)
	}
	if err := recordRuntimeHostPorts(c, config.HostEntry{IP: "192.168.1.60", Ports: []int{1234, 443}}); err != nil {
		t.Fatal(err)
	}
	if got, want := readRecord(t, c), "192.168.1.50:[8080] 192.168.1.60:[1234 443]"; got != want {
		t.Errorf("record = %q, want %q", got, want)
	}
}

// Clearing removes the record, also when there is none, without an incus call.
func TestClearRuntimeHostPorts(t *testing.T) {
	c := "coi-rhp-clear"
	logPath := fakeRecordEnv(t)
	if err := ClearRuntimeHostPorts(c); err != nil {
		t.Errorf("clear without a record: %v", err)
	}
	seedRecord(t, c)
	if err := ClearRuntimeHostPorts(c); err != nil {
		t.Fatal(err)
	}
	if got := readRecord(t, c); got != "" {
		t.Errorf("record after clear = %q, want none", got)
	}
	// Every session setup runs this: it must not cost an incus call.
	if calls, _ := os.ReadFile(logPath); len(calls) != 0 {
		t.Errorf("clear called incus:\n%s", calls)
	}
}

// Session setup drops a record left by an earlier session, also when the
// config has no [[network.hosts]] (the firewall it described is gone).
func TestSetupForContainer_ClearsRuntimeHostPorts(t *testing.T) {
	c := "coi-rhp-setup"
	fakeRecordEnv(t)
	seedRecord(t, c)
	useSudo := false
	cfg := &config.NetworkConfig{Mode: config.NetworkModeOpen, UseSudo: &useSudo}
	_ = NewManager(cfg, logger.NewDiscard()).SetupForContainer(context.Background(), c)
	if got := readRecord(t, c); got != "" {
		t.Errorf("record after setup = %q, want none", got)
	}
}

// `coi hosts add --ports` records its ports for the monitors.
func TestAddUserHost_RecordsPorts(t *testing.T) {
	if !hostInterfaceExists("lo") {
		t.Skip("no /sys/class/net/lo")
	}
	c := "coi-rhp-add"
	logPath := fakeRecordEnv(t)
	sudoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sudoDir, "sudo"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", sudoDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	instanceNetCache.Store(c, instanceNet{ip: "10.47.0.5", veth: "lo", at: time.Now()})
	t.Cleanup(func() { instanceNetCache.Delete(c) })

	entry := config.HostEntry{IP: "192.168.1.50", Hostnames: []string{"svc.lan"}, Ports: []int{8080}}
	if err := AddUserHost(c, config.NetworkModeRestricted, false, entry, nil); err != nil {
		log, _ := os.ReadFile(logPath)
		t.Fatalf("AddUserHost: %v\nincus calls:\n%s", err, log)
	}
	if got := readRecord(t, c); got != "192.168.1.50:[8080]" {
		t.Errorf("record = %q, want 192.168.1.50:[8080]", got)
	}

	// Without ports there is nothing to record.
	if err := ClearRuntimeHostPorts(c); err != nil {
		t.Fatal(err)
	}
	entry = config.HostEntry{IP: "192.168.1.60", Hostnames: []string{"other.lan"}}
	if err := AddUserHost(c, config.NetworkModeRestricted, false, entry, []int{443}); err != nil {
		t.Fatal(err)
	}
	if got := readRecord(t, c); got != "" {
		t.Errorf("record = %q, want none", got)
	}
}

// Without $HOME the record, the IP cache and the monitor all use the /tmp
// fallback, and setup does not fail.
func TestRuntimeHostPorts_HomeUnset(t *testing.T) {
	t.Setenv("HOME", "")
	fakeIncus(t)
	c := "coi-rhp-nohome-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() {
		_ = defaultCacheManager().DeleteHostPorts(c)
		_ = defaultCacheManager().Delete(c)
	})

	useSudo := false
	m := NewManager(&config.NetworkConfig{Mode: config.NetworkModeOpen, UseSudo: &useSudo}, logger.NewDiscard())
	if err := m.SetupForContainer(context.Background(), c); err != nil {
		t.Fatalf("setup without $HOME: %v", err)
	}
	if !strings.HasPrefix(m.cacheManager.cacheDir, "/tmp/") {
		t.Errorf("IP cache dir %q, want the /tmp fallback", m.cacheManager.cacheDir)
	}

	if err := recordRuntimeHostPorts(c, config.HostEntry{IP: "192.168.1.50", Ports: []int{8080}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.cacheManager.LoadHostPorts(c); err != nil || len(got) != 1 {
		t.Errorf("record in the IP cache dir = %v, %v", got, err)
	}
	if got, err := readRuntimeHostPorts(c); err != nil || len(got) != 1 {
		t.Errorf("monitor's record read = %v, %v", got, err)
	}
	if err := ClearRuntimeHostPorts(c); err != nil {
		t.Errorf("clear without $HOME: %v", err)
	}

	cache := &IPCache{Domains: map[string][]string{"proxy.example.com": {"203.0.113.31"}}}
	if err := m.cacheManager.Save(c, cache); err != nil {
		t.Fatal(err)
	}
	if got, err := loadNameAddresses(c); err != nil || len(got["proxy.example.com"]) != 1 {
		t.Errorf("name addresses = %v, %v, want the firewall's IP cache", got, err)
	}
}
