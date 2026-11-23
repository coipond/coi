package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coipond/coi/internal/container"
)

// sshAgentDevice / sshAgentContainerPath are the fixed identifiers for the
// built-in SSH agent forward, kept stable so persistent containers re-point the
// same device across sessions.
const (
	sshAgentDevice        = "ssh-agent"
	sshAgentContainerPath = "/tmp/ssh-agent.sock"
)

// SetupSSHAgentForwarding forwards the host SSH agent socket ($SSH_AUTH_SOCK)
// into the container. Returns the container socket path, or "" if skipped (no
// SSH_AUTH_SOCK / invalid socket / could not be created). Kept for callers that
// only want the SSH agent (e.g. ConfigureContainer / coi-pond).
func SetupSSHAgentForwarding(mgr container.ContainerManager, containerName string, logger func(string)) (string, error) {
	entry, ok := sshAgentSocketEntry(logger)
	if !ok {
		return "", nil
	}
	path, forwarded, err := forwardSocket(mgr, entry, logger)
	if err != nil {
		return "", err
	}
	if !forwarded {
		return "", nil
	}
	return path, nil
}

// ForwardConfiguredSockets forwards the host SSH agent (when includeSSHAgent)
// plus every entry in sc into the container, returning a map of env var name ->
// in-container socket path for the entries that were forwarded and declare an
// EnvVar. Per-entry failures are logged, never fatal.
func ForwardConfiguredSockets(mgr container.ContainerManager, sc *SocketConfig, includeSSHAgent bool, logger func(string)) map[string]string {
	env, _ := forwardConfiguredSockets(mgr, sc, includeSSHAgent, true, logger)
	return env
}

// forwardConfiguredSockets is ForwardConfiguredSockets that also returns the
// entries actually forwarded, for the startup grants report. A reused
// persistent container keeps the socket devices of earlier sessions, so every
// one this session does not forward is removed: forward_agent turned off, a
// [[sockets]] entry removed or dropped by the trust gate, a host socket gone.
// A container created by this session (reused false) has none to remove.
func forwardConfiguredSockets(mgr socketForwarder, sc *SocketConfig, includeSSHAgent, reused bool, logger func(string)) (map[string]string, []SocketEntry) {
	var entries []SocketEntry
	if includeSSHAgent {
		if e, ok := sshAgentSocketEntry(logger); ok {
			entries = append(entries, e)
		}
	}
	if sc != nil {
		entries = append(entries, sc.Sockets...)
	}
	// Listed before forwarding: the list shares the config cache entry that
	// forwardSocket reads next, while a list after the device writes would
	// cost another `incus config show`.
	var existing map[string]bool
	if reused {
		existing = existingSocketDevices(mgr, logger)
		requested := make(map[string]bool, len(entries))
		for _, e := range entries {
			requested[e.DeviceName] = true
		}
		for d := range existing {
			if !requested[d] {
				removeSocketDevice(mgr, d, logger)
			}
		}
	}
	if len(entries) == 0 {
		return nil, nil
	}
	env, forwarded := forwardSockets(mgr, entries, logger)
	done := make(map[string]bool, len(forwarded))
	for _, e := range forwarded {
		done[e.DeviceName] = true
	}
	for _, e := range entries {
		if existing[e.DeviceName] && !done[e.DeviceName] {
			removeSocketDevice(mgr, e.DeviceName, logger)
		}
	}
	return env, forwarded
}

// isSocketDevice reports whether a device name is one socket forwarding
// creates: the SSH agent's or a [[sockets]] entry's (socket-<n>).
func isSocketDevice(name string) bool {
	if name == sshAgentDevice {
		return true
	}
	n, ok := strings.CutPrefix(name, "socket-")
	if !ok || n == "" {
		return false
	}
	for _, c := range n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// existingSocketDevices returns the names of the container's socket devices.
func existingSocketDevices(mgr container.ContainerDevices, logger func(string)) map[string]bool {
	devices, err := mgr.ListDevices()
	if err != nil {
		logger(fmt.Sprintf("Warning: could not list devices to remove stale socket forwards: %v", err))
		return nil
	}
	out := map[string]bool{}
	for _, d := range devices {
		if isSocketDevice(d) {
			out[d] = true
		}
	}
	return out
}

// removeSocketDevice removes a socket device this session does not forward.
func removeSocketDevice(mgr container.ContainerDevices, name string, logger func(string)) {
	if err := mgr.RemoveDevice(name); err != nil {
		logger(fmt.Sprintf("Warning: could not remove stale socket device %s: %v", name, err))
	}
}

// sshAgentSocketEntry builds the synthetic socket entry for the host SSH agent,
// reading the live $SSH_AUTH_SOCK. ok is false when there's nothing to forward.
func sshAgentSocketEntry(logger func(string)) (SocketEntry, bool) {
	hostSocket := filepath.Clean(os.Getenv("SSH_AUTH_SOCK"))
	if hostSocket == "." || hostSocket == "" {
		logger("SSH agent forwarding skipped: SSH_AUTH_SOCK not set on host")
		return SocketEntry{}, false
	}
	return SocketEntry{
		HostPath:      hostSocket,
		ContainerPath: sshAgentContainerPath,
		EnvVar:        "SSH_AUTH_SOCK",
		DeviceName:    sshAgentDevice,
	}, true
}

// socketForwarder is the narrow slice of the container API that socket
// forwarding needs: adding/removing proxy devices and probing for the socket
// inside the container. Kept small so it can be faked in unit tests.
type socketForwarder interface {
	container.ContainerDevices
	container.ContainerExecution
}

// forwardSockets forwards each entry into the container and returns a map of
// env var name -> in-container socket path for the entries that were forwarded
// successfully and declare an EnvVar, plus every entry that was forwarded.
// Per-entry failures are logged, not fatal.
func forwardSockets(mgr socketForwarder, entries []SocketEntry, logger func(string)) (map[string]string, []SocketEntry) {
	env := map[string]string{}
	var forwarded []SocketEntry
	for _, e := range entries {
		path, ok, err := forwardSocket(mgr, e, logger)
		if err != nil {
			logger(fmt.Sprintf("Warning: socket forwarding failed for %s: %v", e.HostPath, err))
			continue
		}
		if !ok {
			continue
		}
		e.ContainerPath = path
		forwarded = append(forwarded, e)
		if e.EnvVar != "" {
			env[e.EnvVar] = path
		}
	}
	return env, forwarded
}

// forwardSocket forwards a single host unix socket into the container via an
// Incus proxy device, verifying it appears (with one retry to work around an
// Incus race). Returns the container path and whether it was forwarded. A
// missing/invalid host socket is skipped (ok=false, nil error), matching the
// original SSH-agent behavior.
func forwardSocket(mgr socketForwarder, e SocketEntry, logger func(string)) (string, bool, error) {
	hostSocket := filepath.Clean(e.HostPath)
	if hostSocket == "." || hostSocket == "" {
		logger("Socket forwarding skipped: empty host socket path")
		return "", false, nil
	}
	if fi, err := os.Stat(hostSocket); err != nil {
		logger(fmt.Sprintf("Socket forwarding skipped: %s not accessible: %v", hostSocket, err))
		return "", false, nil
	} else if fi.Mode()&os.ModeSocket == 0 {
		logger(fmt.Sprintf("Socket forwarding skipped: %s is not a Unix domain socket", hostSocket))
		return "", false, nil
	}

	// A reused persistent container usually still has this exact device from
	// the previous session: keep it when it is identical and the socket is
	// there, instead of remove + re-add + poll on every launch.
	if r, ok := mgr.(deviceConfigReader); ok {
		if cfg, found := r.DeviceConfig(e.DeviceName); found && socketDeviceMatches(cfg, hostSocket, e.ContainerPath) {
			if waitForContainerSocket(mgr, e.ContainerPath, time.Second) {
				logger(fmt.Sprintf("Forwarding socket: %s -> %s (device unchanged)", hostSocket, e.ContainerPath))
				return e.ContainerPath, true, nil
			}
		}
	}

	// Remove any existing device of this name (host socket path may have changed
	// between sessions on a reused persistent container).
	_ = mgr.RemoveDevice(e.DeviceName)

	logger(fmt.Sprintf("Forwarding socket: %s -> %s", hostSocket, e.ContainerPath))
	if err := addSocketProxyDevice(mgr, e.DeviceName, hostSocket, e.ContainerPath); err != nil {
		return "", false, fmt.Errorf("failed to add proxy device %q: %w", e.DeviceName, err)
	}

	if waitForContainerSocket(mgr, e.ContainerPath, 5*time.Second) {
		return e.ContainerPath, true, nil
	}

	// Incus proxy devices can lag on freshly-started containers; retry once.
	logger(fmt.Sprintf("Socket %s not yet available, retrying device setup...", e.ContainerPath))
	_ = mgr.RemoveDevice(e.DeviceName)
	if err := addSocketProxyDevice(mgr, e.DeviceName, hostSocket, e.ContainerPath); err != nil {
		return "", false, fmt.Errorf("failed to re-add proxy device %q: %w", e.DeviceName, err)
	}
	if !waitForContainerSocket(mgr, e.ContainerPath, 5*time.Second) {
		logger(fmt.Sprintf("Warning: socket %s did not appear in container after retry", e.ContainerPath))
		return "", false, nil
	}
	return e.ContainerPath, true, nil
}

// deviceConfigReader is implemented by *container.Manager (kept out of the
// fakes' interfaces): one device's config, from the instance config cache.
type deviceConfigReader interface {
	DeviceConfig(name string) (map[string]string, bool)
}

// socketDeviceMatches reports whether an existing device is exactly the proxy
// addSocketProxyDevice would create for hostSocket -> containerSocket. The
// host path is compared exactly: SSH_AUTH_SOCK changes between logins.
func socketDeviceMatches(cfg map[string]string, hostSocket, containerSocket string) bool {
	uid := fmt.Sprintf("%d", container.CodeUID)
	return cfg["type"] == "proxy" &&
		cfg["connect"] == "unix:"+hostSocket &&
		cfg["listen"] == "unix:"+containerSocket &&
		cfg["bind"] == "container" &&
		cfg["uid"] == uid && cfg["gid"] == uid &&
		cfg["mode"] == "0600"
}

// addSocketProxyDevice adds a proxy device forwarding hostSocket -> containerSocket.
func addSocketProxyDevice(mgr container.ContainerDevices, deviceName, hostSocket, containerSocket string) error {
	return mgr.AddProxyDevice(
		deviceName,
		fmt.Sprintf("unix:%s", hostSocket),
		fmt.Sprintf("unix:%s", containerSocket),
		container.CodeUID,
		container.CodeUID,
	)
}

// waitForContainerSocket polls for a Unix socket to appear inside the container.
func waitForContainerSocket(mgr container.ContainerExecution, socketPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	checkCmd := fmt.Sprintf("test -S %s", socketPath)
	for time.Now().Before(deadline) {
		if _, err := mgr.ExecCommand(checkCmd, container.ExecCommandOptions{Capture: true}); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
