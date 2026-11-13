package session

import (
	"os"
	"path/filepath"
	"testing"
)

// hardeningPolicyFrom passes the raw flags through; the docker-vs-hardening
// precedence is resolved by HardeningPolicy.DockerEnabled, not here. So the
// mapping is a straight copy, and DockerEnabled applies "reduce wins".
func TestHardeningPolicyFrom(t *testing.T) {
	tests := []struct {
		docker, reduce  bool
		wantDockerAfter bool // DockerEnabled() result
	}{
		{true, false, true},
		{false, false, false},
		{true, true, false},
		{false, true, false},
	}
	for _, tt := range tests {
		opts := &SetupOptions{Security: SecurityOptions{Docker: tt.docker, ReduceKernelSurface: tt.reduce}}
		got := hardeningPolicyFrom(opts)
		if got.Docker != tt.docker || got.ReduceKernelSurface != tt.reduce {
			t.Errorf("docker=%v reduce=%v: got %+v, want raw flags copied", tt.docker, tt.reduce, got)
		}
		if got.DockerEnabled() != tt.wantDockerAfter {
			t.Errorf("docker=%v reduce=%v: DockerEnabled()=%v, want %v", tt.docker, tt.reduce, got.DockerEnabled(), tt.wantDockerAfter)
		}
	}
}

// A fresh coi shell container gets the kernel-surface policy and the disabled
// guest API in its `incus init` call. The fake `incus` fails the init, so the
// create stops right after it.
func TestCreateAndStartContainer_SettingsAtInit(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\nshift 2\necho \"$*\" >> " + logPath + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "incus"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result := &SetupResult{ContainerName: "c1"}
	opts := &SetupOptions{StoragePool: "pool1", Logger: func(string) {}}
	opts.Security.Docker = true
	if err := createAndStartContainer(result, opts, "img", "c1"); err == nil {
		t.Fatal("want the failed init to fail the create")
	}
	b, _ := os.ReadFile(logPath)
	want := "init img c1 -s pool1 -c user.coi.managed=true" +
		" -c user.coi.persistent=false" +
		" -c security.nesting=true" +
		" -c security.syscalls.intercept.mknod=true" +
		" -c security.syscalls.intercept.setxattr=true" +
		" -c linux.sysctl.net.ipv4.ip_unprivileged_port_start=0" +
		" -c security.guestapi=false\n"
	if string(b) != want {
		t.Errorf("calls = %q, want %q", b, want)
	}
}
