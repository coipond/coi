package session

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coipond/coi/internal/container"
)

// fakeForwarder implements the narrow socketForwarder interface for unit tests.
// It records proxy-device operations and reports a configurable set of
// in-container socket paths as "present" so waitForContainerSocket succeeds.
type fakeForwarder struct {
	added        []addedDevice
	removed      []string
	presentAfter int // number of AddProxyDevice calls before a socket "appears"
	addCalls     int
	devices      []string // what ListDevices returns
	listErr      error
	listCalls    int
	addsAtList   int // AddProxyDevice calls made before the last ListDevices
	addErr       error
}

type addedDevice struct {
	name, connect, listen string
	uid, gid              int
}

func (f *fakeForwarder) MountDisk(_, _, _ string, _, _ bool) error { return nil }
func (f *fakeForwarder) SetTmpfsSize(_ string) error               { return nil }

func (f *fakeForwarder) AddProxyDevice(name, connect, listen string, uid, gid int) error {
	f.addCalls++
	if f.addErr != nil {
		return f.addErr
	}
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

func (f *fakeForwarder) ListDevices() ([]string, error) {
	f.listCalls++
	f.addsAtList = f.addCalls
	return f.devices, f.listErr
}

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

	env, forwarded := forwardSockets(f, entries, func(string) {})

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
	if len(forwarded) != 1 || forwarded[0].ContainerPath != "/run/broker.sock" || forwarded[0].HostPath != host {
		t.Fatalf("forwarded = %+v, want the one broker entry", forwarded)
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

// fakeForwarderWithDevices also exposes existing device config, like the
// real manager does from the instance config cache.
type fakeForwarderWithDevices struct {
	*fakeForwarder
	devices map[string]map[string]string
}

func (f *fakeForwarderWithDevices) DeviceConfig(name string) (map[string]string, bool) {
	cfg, ok := f.devices[name]
	return cfg, ok
}

func existingSocketDevice(host, listen string) map[string]string {
	uid := fmt.Sprintf("%d", container.CodeUID)
	return map[string]string{
		"type": "proxy", "connect": "unix:" + host, "listen": "unix:" + listen,
		"bind": "container", "uid": uid, "gid": uid, "mode": "0600",
	}
}

// A reused container whose proxy device is already identical keeps it: no
// remove, no re-add.
func TestForwardSocket_KeepsIdenticalDevice(t *testing.T) {
	host := newTestSocket(t, "same.sock")
	f := &fakeForwarderWithDevices{
		fakeForwarder: &fakeForwarder{presentAfter: 0},
		devices:       map[string]map[string]string{"socket-0": existingSocketDevice(host, "/run/same.sock")},
	}
	e := SocketEntry{HostPath: host, ContainerPath: "/run/same.sock", DeviceName: "socket-0"}
	path, ok, err := forwardSocket(f, e, func(string) {})
	if err != nil || !ok || path != "/run/same.sock" {
		t.Fatalf("path=%q ok=%v err=%v", path, ok, err)
	}
	if len(f.removed) != 0 || f.addCalls != 0 {
		t.Errorf("identical device must be kept: removed=%v adds=%d", f.removed, f.addCalls)
	}
}

// A changed host socket path (new login, new SSH_AUTH_SOCK) is re-forwarded.
func TestForwardSocket_ReplacesChangedDevice(t *testing.T) {
	host := newTestSocket(t, "new.sock")
	f := &fakeForwarderWithDevices{
		fakeForwarder: &fakeForwarder{presentAfter: 1},
		devices:       map[string]map[string]string{"socket-0": existingSocketDevice("/tmp/old-agent.sock", "/run/x.sock")},
	}
	e := SocketEntry{HostPath: host, ContainerPath: "/run/x.sock", DeviceName: "socket-0"}
	if _, ok, err := forwardSocket(f, e, func(string) {}); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(f.removed) != 1 || f.addCalls != 1 || f.added[0].connect != "unix:"+host {
		t.Errorf("changed device must be replaced: removed=%v added=%+v", f.removed, f.added)
	}
}

// A reused container keeps the socket devices of earlier sessions: with
// forward_agent off and no [[sockets]], the SSH agent's and every socket-<n>
// device go, and nothing else is touched.
func TestForwardConfiguredSockets_RemovesStaleDevicesWhenNothingForwarded(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", newTestSocket(t, "agent.sock"))
	f := &fakeForwarder{devices: []string{"workspace", "ssh-agent", "socket-0", "socket-12", "socket-x", "coi-port-web", "mount-0"}}
	env, forwarded := forwardConfiguredSockets(f, nil, false, true, func(string) {})
	if len(env) != 0 || len(forwarded) != 0 || f.addCalls != 0 {
		t.Fatalf("nothing should be forwarded: env=%v forwarded=%v adds=%d", env, forwarded, f.addCalls)
	}
	if got := strings.Join(f.removed, ","); got != "socket-0,socket-12,ssh-agent" {
		t.Errorf("removed = %q, want socket-0,socket-12,ssh-agent", got)
	}
}

// Devices this session forwards stay; a [[sockets]] entry removed from
// config (socket-1) and one whose host socket is gone (socket-2) do not.
func TestForwardConfiguredSockets_KeepsOnlyForwardedDevices(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", newTestSocket(t, "agent.sock"))
	host := newTestSocket(t, "a.sock")
	f := &fakeForwarderWithDevices{
		fakeForwarder: &fakeForwarder{devices: []string{"ssh-agent", "socket-0", "socket-1", "socket-2"}},
		devices: map[string]map[string]string{
			"ssh-agent": existingSocketDevice(os.Getenv("SSH_AUTH_SOCK"), sshAgentContainerPath),
			"socket-0":  existingSocketDevice(host, "/run/a.sock"),
		},
	}
	sc := &SocketConfig{Sockets: []SocketEntry{
		{HostPath: host, ContainerPath: "/run/a.sock", DeviceName: "socket-0"},
		{HostPath: filepath.Join(t.TempDir(), "gone.sock"), ContainerPath: "/run/gone.sock", DeviceName: "socket-2"},
	}}
	env, forwarded := forwardConfiguredSockets(f, sc, true, true, func(string) {})
	if env["SSH_AUTH_SOCK"] != sshAgentContainerPath || len(forwarded) != 2 {
		t.Fatalf("env=%v forwarded=%+v", env, forwarded)
	}
	if got := strings.Join(f.removed, ","); got != "socket-1,socket-2" {
		t.Errorf("removed = %q, want socket-1,socket-2", got)
	}
	// One list, before any device write, so it shares forwardSocket's
	// cached config read.
	if f.listCalls != 1 || f.addsAtList != 0 {
		t.Errorf("devices listed %d times, after %d adds; want once, before forwarding", f.listCalls, f.addsAtList)
	}
}

// The list comes before the device writes even when one is added.
func TestForwardConfiguredSockets_ListsBeforeAdding(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", newTestSocket(t, "agent.sock"))
	f := &fakeForwarder{devices: []string{"socket-0"}}
	forwardConfiguredSockets(f, nil, true, true, func(string) {})
	if f.addCalls != 1 || f.listCalls != 1 || f.addsAtList != 0 {
		t.Errorf("adds=%d lists=%d addsAtList=%d; want the list once, before the add", f.addCalls, f.listCalls, f.addsAtList)
	}
	if strings.Join(f.removed, ",") != "socket-0,ssh-agent" {
		t.Errorf("removed = %v, want the stale socket-0, then the agent's re-add", f.removed)
	}
}

// A container created by this session can't hold devices of an earlier
// one: no list, no removal.
func TestForwardConfiguredSockets_FreshContainerSkipsList(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	f := &fakeForwarder{devices: []string{"ssh-agent"}}
	forwardConfiguredSockets(f, nil, false, false, func(string) {})
	if f.listCalls != 0 || len(f.removed) != 0 {
		t.Errorf("lists=%d removed=%v, want neither", f.listCalls, f.removed)
	}
}

// A device list that can't be read is logged; forwarding still works.
func TestForwardConfiguredSockets_ListErrorIsLogged(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	f := &fakeForwarder{listErr: fmt.Errorf("incus down")}
	var logs []string
	forwardConfiguredSockets(f, nil, false, true, func(s string) { logs = append(logs, s) })
	if len(f.removed) != 0 {
		t.Errorf("removed = %v", f.removed)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "could not list devices to remove stale socket forwards: incus down") {
		t.Errorf("logs = %v", logs)
	}
}

// forwardSocket removes the old device before a failed add: it is not
// removed (and warned about) a second time.
func TestForwardConfiguredSockets_FailedAddRemovesOnce(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	host := newTestSocket(t, "a.sock")
	f := &fakeForwarder{devices: []string{"socket-0"}, addErr: fmt.Errorf("add failed")}
	sc := &SocketConfig{Sockets: []SocketEntry{{HostPath: host, ContainerPath: "/run/a.sock", DeviceName: "socket-0"}}}
	var logs []string
	_, forwarded := forwardConfiguredSockets(f, sc, false, true, func(s string) { logs = append(logs, s) })
	if len(forwarded) != 0 || strings.Join(f.removed, ",") != "socket-0" {
		t.Errorf("forwarded=%v removed=%v, want none forwarded and socket-0 removed once", forwarded, f.removed)
	}
	if strings.Contains(strings.Join(logs, "\n"), "could not remove stale socket device") {
		t.Errorf("logs = %v", logs)
	}
}

// fakeSocketManager is a container.ContainerManager whose socket-forwarding
// methods go to a fakeForwarder; any other call panics.
type fakeSocketManager struct {
	container.ContainerManager
	f *fakeForwarder
}

func (m *fakeSocketManager) ListDevices() ([]string, error) { return m.f.ListDevices() }
func (m *fakeSocketManager) RemoveDevice(name string) error { return m.f.RemoveDevice(name) }
func (m *fakeSocketManager) AddProxyDevice(name, connect, listen string, uid, gid int) error {
	return m.f.AddProxyDevice(name, connect, listen, uid, gid)
}

func (m *fakeSocketManager) ExecCommand(command string, opts container.ExecCommandOptions) (string, error) {
	return m.f.ExecCommand(command, opts)
}

// coi shell removes a stale device only from a container it did not create
// (skipLaunch), and doesn't list the devices of one it did.
func TestPhaseForwardSockets_ReusedOnly(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, skipLaunch := range []bool{true, false} {
		f := &fakeForwarder{devices: []string{"ssh-agent"}}
		st := &setupState{
			opts:       SetupOptions{Logger: func(string) {}},
			result:     &SetupResult{Manager: &fakeSocketManager{f: f}},
			skipLaunch: skipLaunch,
		}
		if _, err := st.phaseForwardSockets(t.Context()); err != nil {
			t.Fatal(err)
		}
		if skipLaunch && (f.listCalls != 1 || strings.Join(f.removed, ",") != "ssh-agent") {
			t.Errorf("reused: lists=%d removed=%v, want the stale ssh-agent removed", f.listCalls, f.removed)
		}
		if !skipLaunch && (f.listCalls != 0 || len(f.removed) != 0) {
			t.Errorf("new container: lists=%d removed=%v, want neither", f.listCalls, f.removed)
		}
	}
}
