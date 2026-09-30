package session

import (
	"fmt"
	"os"
	"path/filepath"
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
	var entries []SocketEntry
	if includeSSHAgent {
		if e, ok := sshAgentSocketEntry(logger); ok {
			entries = append(entries, e)
		}
	}
	if sc != nil {
		entries = append(entries, sc.Sockets...)
	}
	if len(entries) == 0 {
		return nil
	}
	return forwardSockets(mgr, entries, logger)
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
// successfully and declare an EnvVar. Per-entry failures are logged, not fatal.
func forwardSockets(mgr socketForwarder, entries []SocketEntry, logger func(string)) map[string]string {
	env := map[string]string{}
	for _, e := range entries {
		path, ok, err := forwardSocket(mgr, e, logger)
		if err != nil {
			logger(fmt.Sprintf("Warning: socket forwarding failed for %s: %v", e.HostPath, err))
			continue
		}
		if ok && e.EnvVar != "" {
			env[e.EnvVar] = path
		}
	}
	return env
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
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
