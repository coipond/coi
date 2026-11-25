package cli

import (
	"strings"
	"testing"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
)

// fakeSocketDeviceManager records the device calls of socket forwarding;
// any other call panics.
type fakeSocketDeviceManager struct {
	container.ContainerManager
	devices   []string
	listCalls int
	removed   []string
}

func (f *fakeSocketDeviceManager) ListDevices() ([]string, error) {
	f.listCalls++
	return f.devices, nil
}

func (f *fakeSocketDeviceManager) RemoveDevice(name string) error {
	f.removed = append(f.removed, name)
	return nil
}

// coi run removes a stale socket device only from a persistent container
// that existed before the run, and doesn't list the devices of a new one.
func TestApplyForwardSockets_ReusedOnly(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	a := &App{cfg: &config.Config{}}
	for _, reused := range []bool{true, false} {
		mgr := &fakeSocketDeviceManager{devices: []string{"ssh-agent", "workspace"}}
		if env := a.applyForwardSockets(mgr, nil, reused); len(env) != 0 {
			t.Errorf("reused=%v: env = %v", reused, env)
		}
		if reused && (mgr.listCalls != 1 || strings.Join(mgr.removed, ",") != "ssh-agent") {
			t.Errorf("reused: lists=%d removed=%v, want the stale ssh-agent removed", mgr.listCalls, mgr.removed)
		}
		if !reused && (mgr.listCalls != 0 || len(mgr.removed) != 0) {
			t.Errorf("new container: lists=%d removed=%v, want neither", mgr.listCalls, mgr.removed)
		}
	}
}
