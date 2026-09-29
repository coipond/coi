package cli

import (
	"path/filepath"
	"testing"

	"github.com/mensfeld/coi/internal/config"
)

func TestParseSocketConfig_ExpandsAbsAndCarriesFields(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cfg := &config.Config{
		Sockets: []config.SocketEntry{
			{Host: "~/agent.sock", Container: "/run/agent.sock", Env: "MY_SOCK", Untrusted: true, SourcePath: "/ws/.coi/config.toml"},
			{Host: "/abs/host.sock", Container: "/run/host.sock"},
		},
	}

	sc, err := ParseSocketConfig(cfg)
	if err != nil {
		t.Fatalf("ParseSocketConfig: %v", err)
	}
	if len(sc.Sockets) != 2 {
		t.Fatalf("expected 2 sockets, got %d", len(sc.Sockets))
	}

	s0 := sc.Sockets[0]
	if s0.HostPath != "/home/tester/agent.sock" {
		t.Errorf("~ not expanded: HostPath=%q", s0.HostPath)
	}
	if s0.ContainerPath != "/run/agent.sock" || s0.EnvVar != "MY_SOCK" {
		t.Errorf("unexpected container/env: %+v", s0)
	}
	if !s0.Untrusted || s0.SourcePath != "/ws/.coi/config.toml" {
		t.Errorf("trust metadata not carried: %+v", s0)
	}
	if s0.DeviceName != "socket-0" || sc.Sockets[1].DeviceName != "socket-1" {
		t.Errorf("device names not unique/sequential: %q, %q", s0.DeviceName, sc.Sockets[1].DeviceName)
	}
}

func TestParseSocketConfig_RejectsRelativeContainerPath(t *testing.T) {
	cfg := &config.Config{
		Sockets: []config.SocketEntry{{Host: "/abs/host.sock", Container: "relative/path.sock"}},
	}
	if _, err := ParseSocketConfig(cfg); err == nil {
		t.Fatal("expected error for relative container path")
	}
}

func TestParseSocketConfig_AbsResolvesHost(t *testing.T) {
	cfg := &config.Config{
		Sockets: []config.SocketEntry{{Host: "rel/host.sock", Container: "/run/host.sock"}},
	}
	sc, err := ParseSocketConfig(cfg)
	if err != nil {
		t.Fatalf("ParseSocketConfig: %v", err)
	}
	if !filepath.IsAbs(sc.Sockets[0].HostPath) {
		t.Errorf("host path should be absolutized, got %q", sc.Sockets[0].HostPath)
	}
}

func TestParseSocketConfig_Empty(t *testing.T) {
	sc, err := ParseSocketConfig(&config.Config{})
	if err != nil {
		t.Fatalf("ParseSocketConfig: %v", err)
	}
	if len(sc.Sockets) != 0 {
		t.Fatalf("expected no sockets, got %d", len(sc.Sockets))
	}
}
