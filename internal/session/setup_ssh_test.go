package session

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mensfeld/coi/internal/container"
)

// fakeForwarder implements the narrow socketForwarder interface for unit tests.
// It records proxy-device operations and reports a configurable set of
// in-container socket paths as "present" so waitForContainerSocket succeeds.
type fakeForwarder struct {
	added        []addedDevice
	removed      []string
	presentAfter int // number of AddProxyDevice calls before a socket "appears"
	addCalls     int
}

type addedDevice struct {
	name, connect, listen string
	uid, gid              int
}

func (f *fakeForwarder) MountDisk(_, _, _ string, _, _ bool) error { return nil }
func (f *fakeForwarder) SetTmpfsSize(_ string) error               { return nil }

func (f *fakeForwarder) AddProxyDevice(name, connect, listen string, uid, gid int) error {
	f.addCalls++
	f.added = append(f.added, addedDevice{name, connect, listen, uid, gid})
	return nil
}

func (f *fakeForwarder) AddHostPortDevice(name, listenAddr string, hostPort, containerPort int) error {
	return nil
}

func (f *fakeForwarder) RemoveDevice(name string) error {
	f.removed = append(f.removed, name)
	return nil
}

func (f *fakeForwarder) ListDevices() ([]string, error) { return nil, nil }

func (f *fakeForwarder) Exec(_ ...string) error                                    { return nil }
func (f *fakeForwarder) ExecArgs(_ []string, _ container.ExecCommandOptions) error { return nil }
func (f *fakeForwarder) ExecHostCommand(_ string, _ bool) (string, error)          { return "", nil }

func (f *fakeForwarder) ExecArgsCapture(_ []string, _ container.ExecCommandOptions) (string, error) {
	return "", nil
}

// ExecCommand answers the `test -S <path>` probe: present once enough
// AddProxyDevice calls have happened.
func (f *fakeForwarder) ExecCommand(command string, _ container.ExecCommandOptions) (string, error) {
	if strings.HasPrefix(command, "test -S ") {
		if f.addCalls >= f.presentAfter {
			return "", nil
		}
		return "", fmt.Errorf("not present yet")
	}
	return "", nil
}

func newTestSocket(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatalf("failed to create unix socket: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return p
}

func TestForwardSockets_ForwardsAndReturnsEnv(t *testing.T) {
	host := newTestSocket(t, "broker.sock")
	f := &fakeForwarder{presentAfter: 1}
	entries := []SocketEntry{{
		HostPath:      host,
		ContainerPath: "/run/broker.sock",
		EnvVar:        "BROKER_SOCK",
		DeviceName:    "socket-0",
	}}

	env := forwardSockets(f, entries, func(string) {})

	if got := env["BROKER_SOCK"]; got != "/run/broker.sock" {
		t.Fatalf("env[BROKER_SOCK] = %q, want /run/broker.sock", got)
	}
	if len(f.added) != 1 {
		t.Fatalf("expected 1 proxy device added, got %d", len(f.added))
	}
	a := f.added[0]
	if a.name != "socket-0" || a.connect != "unix:"+host || a.listen != "unix:/run/broker.sock" {
		t.Fatalf("unexpected proxy device args: %+v", a)
	}
	if a.uid != container.CodeUID || a.gid != container.CodeUID {
		t.Fatalf("proxy device uid/gid = %d/%d, want %d", a.uid, a.gid, container.CodeUID)
	}
}

func TestForwardSocket_RetriesWhenSocketLate(t *testing.T) {
	host := newTestSocket(t, "late.sock")
	// Socket only appears after the second AddProxyDevice (the retry path).
	f := &fakeForwarder{presentAfter: 2}
	e := SocketEntry{HostPath: host, ContainerPath: "/run/late.sock", DeviceName: "socket-0"}

	path, ok, err := forwardSocket(f, e, func(string) {})
	if err != nil || !ok || path != "/run/late.sock" {
		t.Fatalf("forwardSocket retry: path=%q ok=%v err=%v", path, ok, err)
	}
	if f.addCalls != 2 {
		t.Fatalf("expected 2 AddProxyDevice calls (initial + retry), got %d", f.addCalls)
	}
}

func TestForwardSocket_SkipsMissingHostSocket(t *testing.T) {
	f := &fakeForwarder{presentAfter: 0}
	e := SocketEntry{HostPath: "/nonexistent/missing.sock", ContainerPath: "/run/x.sock", DeviceName: "socket-0"}

	path, ok, err := forwardSocket(f, e, func(string) {})
	if err != nil || ok || path != "" {
		t.Fatalf("missing host socket should be skipped (ok=false, no error): path=%q ok=%v err=%v", path, ok, err)
	}
	if len(f.added) != 0 {
		t.Fatalf("no proxy device should be added for a missing host socket, got %d", len(f.added))
	}
}

func TestForwardSocket_SkipsNonSocketHostPath(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeForwarder{presentAfter: 0}
	e := SocketEntry{HostPath: regular, ContainerPath: "/run/x.sock", DeviceName: "socket-0"}

	if _, ok, _ := forwardSocket(f, e, func(string) {}); ok {
		t.Fatal("a regular file (not a socket) must not be forwarded")
	}
}

func TestSSHAgentSocketEntry_UsesFixedDeviceAndEnv(t *testing.T) {
	host := newTestSocket(t, "agent.sock")
	t.Setenv("SSH_AUTH_SOCK", host)

	e, ok := sshAgentSocketEntry(func(string) {})
	if !ok {
		t.Fatal("sshAgentSocketEntry should succeed when SSH_AUTH_SOCK is set")
	}
	if e.DeviceName != sshAgentDevice || e.ContainerPath != sshAgentContainerPath || e.EnvVar != "SSH_AUTH_SOCK" {
		t.Fatalf("unexpected SSH agent entry: %+v", e)
	}
}

func TestSSHAgentSocketEntry_SkipsWhenUnset(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, ok := sshAgentSocketEntry(func(string) {}); ok {
		t.Fatal("sshAgentSocketEntry should report ok=false when SSH_AUTH_SOCK is unset")
	}
}
