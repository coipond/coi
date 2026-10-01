package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/monitor"
	"github.com/coipond/coi/internal/network"
	"github.com/coipond/coi/internal/session"
)

// waitProbeReady waits up to 30s for a just-launched probe container via the
// shared session.WaitForReady chokepoint (silent logger — health probes don't
// narrate). The former hand-rolled loops here retried through transient
// ContainerRunning errors; WaitForReady fails fast on them instead, which for
// a probe is the same verdict (an erroring incus is a failed check) delivered
// sooner.
func waitProbeReady(containerName string) bool {
	return session.WaitForReady(context.Background(), container.NewManager(containerName), 30, func(string) {}) == nil
}

// CheckContainerConnectivity tests internet connectivity from inside a container
// probeLaunch is the launcher the isolation probes use, indirected through a
// package var so a unit test can assert the resolved kernel-surface policy is
// actually threaded to the launch (a live-container E2E can only observe this
// when the environment can boot the seconds-lived probes at all). Production
// value: the real policy-honoring launcher.
var probeLaunch = container.LaunchContainerWithPreStartPolicy

// hostUIDInSubidRange reports whether the current host UID sits in a multi-ID
// subordinate range in /etc/subuid — the condition under which the workspace
// can't be idmapped (#838). Indirected so tests can simulate it without touching
// /etc/subuid.
var hostUIDInSubidRange = session.HostUIDSubordinateRange

// subidSkip returns a WARNING "skipped" result (and true) for a probe that mounts
// and idmaps a temp workspace when the host UID can't be mapped, so the probe
// reports an honest, named skip instead of a cryptic mount/forkmount [FAIL]
// (#838). Returns (_, false) when the UID is mappable, so the caller proceeds.
func subidSkip(name string) (HealthCheck, bool) {
	line, inRange := hostUIDInSubidRange()
	if !inRange {
		return HealthCheck{}, false
	}
	return HealthCheck{
		Name:   name,
		Status: StatusWarning,
		Message: fmt.Sprintf("Skipped — host UID %d is inside /etc/subuid range %s, so the probe "+
			"workspace can't be idmapped; run coi as a uid-%d user to verify. (not a masking failure)",
			os.Getuid(), line, container.CodeUID),
	}, true
}

func CheckContainerConnectivity(imageName string, policy container.HardeningPolicy) HealthCheck {
	// Skip if no image available
	if imageName == "" {
		imageName = "coi-default"
	}

	exists, err := container.ImageExists(imageName)
	if err != nil || !exists {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusWarning,
			Message: "Skipped (image not available)",
		}
	}

	// Create temporary container name
	containerName := fmt.Sprintf("coi-health-check-%d", time.Now().UnixNano())

	// Launch ephemeral container on the Incus default pool — this probe is
	// one-shot and pool routing isn't relevant to what we're checking.
	if err := probeLaunch(imageName, containerName, "", true, nil, policy); err != nil {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Failed to launch test container: %v", err),
		}
	}

	// Ensure cleanup on any exit path
	defer func() {
		// Ephemeral containers auto-delete when stopped, but force cleanup just in case
		_ = container.StopContainer(containerName)
		_ = container.DeleteContainer(containerName)
	}()

	// Wait for container to be ready and have network (up to 30 seconds)
	if !waitProbeReady(containerName) {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusFailed,
			Message: "Test container failed to start within timeout",
		}
	}

	// Wait for DHCP to assign an IP (up to 15 seconds)
	var containerIP string
	for i := 0; i < 15; i++ {
		ip, err := network.GetContainerIP(containerName)
		if err == nil && ip != "" {
			containerIP = ip
			break
		}
		time.Sleep(1 * time.Second)
	}

	if containerIP == "" {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusFailed,
			Message: "Container failed to get IP address (DHCP not working)",
		}
	}

	// Apply firewall rules to allow container traffic
	// (FORWARD chain policy may be DROP with Docker)
	var usedIptablesFallback bool
	var iptablesBridgeName string

	if network.NftAvailable() {
		if err := network.EnsureOpenModeRules(containerIP); err != nil {
			return HealthCheck{
				Name:    "container_connectivity",
				Status:  StatusWarning,
				Message: fmt.Sprintf("Failed to apply firewall rules: %v", err),
			}
		}
	} else if network.NeedsIptablesFallback() {
		bridgeName, err := network.GetIncusBridgeName()
		if err != nil {
			return HealthCheck{
				Name:    "container_connectivity",
				Status:  StatusWarning,
				Message: fmt.Sprintf("iptables fallback: could not get bridge name: %v", err),
			}
		}
		if err := network.EnsureIptablesBridgeRules(bridgeName); err != nil {
			return HealthCheck{
				Name:    "container_connectivity",
				Status:  StatusWarning,
				Message: fmt.Sprintf("iptables fallback: failed to add bridge rules: %v", err),
			}
		}
		usedIptablesFallback = true
		iptablesBridgeName = bridgeName
	}

	// Clean up firewall rules on exit
	defer func() {
		if usedIptablesFallback {
			_ = network.RemoveIptablesBridgeRules(iptablesBridgeName)
		} else if network.NftAvailable() {
			_ = network.RemoveOpenModeRules(containerIP)
		}
	}()

	// Give networking additional time to fully stabilize after DHCP
	time.Sleep(3 * time.Second)

	// Test 1: DNS resolution using getent
	dnsOutput, dnsErr := container.IncusOutput("exec", containerName, "--", "getent", "hosts", "api.anthropic.com")

	// Test 2: HTTP connectivity using curl
	httpOutput, httpErr := container.IncusOutput("exec", containerName, "--", "curl", "-s", "--connect-timeout", "10", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com")

	// Analyze results
	dnsOK := dnsErr == nil && dnsOutput != ""
	// Accept any HTTP response - getting a response means connectivity works
	// Common responses: 200 (OK), 401/403 (auth required), 404 (not found), 405 (method not allowed)
	httpOK := httpErr == nil && httpOutput != "" && httpOutput != "000"

	details := map[string]interface{}{
		"dns_test":  dnsOK,
		"http_test": httpOK,
	}

	if dnsOK {
		parts := strings.Fields(dnsOutput)
		if len(parts) > 0 {
			details["dns_result"] = parts[0] // First IP
		}
	}
	if httpOK {
		details["http_status"] = httpOutput
	}

	if dnsOK && httpOK {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusOK,
			Message: fmt.Sprintf("DNS and HTTP working (status %s)", httpOutput),
			Details: details,
		}
	}

	if !dnsOK && !httpOK {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusFailed,
			Message: "Both DNS and HTTP failed inside container",
			Details: details,
		}
	}

	if !dnsOK {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusWarning,
			Message: "DNS resolution failed inside container",
			Details: details,
		}
	}

	// DNS OK but HTTP failed - provide specific error message
	if httpErr != nil {
		return HealthCheck{
			Name:    "container_connectivity",
			Status:  StatusWarning,
			Message: fmt.Sprintf("HTTP connectivity failed (DNS OK, curl error: %v)", httpErr),
			Details: details,
		}
	}
	return HealthCheck{
		Name:    "container_connectivity",
		Status:  StatusWarning,
		Message: fmt.Sprintf("HTTP connectivity failed (DNS OK, HTTP status: %s)", httpOutput),
		Details: details,
	}
}

// CheckNetworkRestriction tests that restricted network mode properly blocks private networks
func CheckNetworkRestriction(imageName string, policy container.HardeningPolicy) HealthCheck {
	// Skip if firewall not available
	if !network.NftAvailable() {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusWarning,
			Message: "Skipped (nft not available)",
		}
	}

	// Skip if no image available
	if imageName == "" {
		imageName = "coi-default"
	}

	exists, err := container.ImageExists(imageName)
	if err != nil || !exists {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusWarning,
			Message: "Skipped (image not available)",
		}
	}

	// Create temporary container name
	containerName := fmt.Sprintf("coi-restriction-check-%d", time.Now().UnixNano())

	// Launch ephemeral container on the Incus default pool — this probe is
	// one-shot and pool routing isn't relevant to what we're checking.
	if err := probeLaunch(imageName, containerName, "", true, nil, policy); err != nil {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Failed to launch test container: %v", err),
		}
	}

	// Track if we applied firewall rules (for cleanup)
	var nftManager *network.NftManager

	// Ensure cleanup on any exit path
	defer func() {
		// Remove firewall rules first
		if nftManager != nil {
			_ = nftManager.RemoveRules()
		}
		// Then stop/delete container
		_ = container.StopContainer(containerName)
		_ = container.DeleteContainer(containerName)
	}()

	// Wait for container to be ready and have network (up to 30 seconds)
	if !waitProbeReady(containerName) {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: "Test container failed to start within timeout",
		}
	}

	// Wait for DHCP to assign an IP (up to 15 seconds)
	var containerIP string
	for i := 0; i < 15; i++ {
		ip, err := network.GetContainerIP(containerName)
		if err == nil && ip != "" {
			containerIP = ip
			break
		}
		time.Sleep(1 * time.Second)
	}

	if containerIP == "" {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: "Container failed to get IP address",
		}
	}

	// Get gateway IP for firewall rules from the host-side /proc/<pid>/net/route.
	// This avoids running ip route inside the container, where the output could
	// be spoofed by a compromised binary or bind-mount.
	gatewayIP, gwErr := getContainerGatewayIPFromProc(containerName)

	// Apply restricted mode firewall rules
	nftManager = network.NewNftManager(containerIP, gatewayIP)
	boolTrue := true
	restrictedConfig := &config.NetworkConfig{
		Mode:                  config.NetworkModeRestricted,
		BlockPrivateNetworks:  &boolTrue,
		BlockMetadataEndpoint: &boolTrue,
	}

	if err := nftManager.ApplyRestricted(restrictedConfig); err != nil {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Failed to apply firewall rules: %v", err),
		}
	}

	// Test 1: External internet should be accessible
	httpOutput, httpErr := container.IncusOutput("exec", containerName, "--", "curl", "-s", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{http_code}", "https://api.anthropic.com")
	externalOK := httpErr == nil && httpOutput != "" && httpOutput != "000"

	// Test 2: RFC1918 private networks should be blocked
	// Try to reach a private IP - we use the gateway but on a different port that won't respond
	// Actually, let's try to reach 10.0.0.1 which should be blocked
	// Using curl with connect-timeout to test if connection is rejected
	_, privateErr := container.IncusOutput("exec", containerName, "--", "curl", "-s", "--connect-timeout", "2", "-o", "/dev/null", "http://10.0.0.1:80")

	// If private network access is blocked, curl should fail with connection refused/rejected
	// Exit code 7 = connection refused, 28 = timeout (both indicate blocking works)
	privateBlocked := privateErr != nil

	// Also test 192.168.0.1
	_, private2Err := container.IncusOutput("exec", containerName, "--", "curl", "-s", "--connect-timeout", "2", "-o", "/dev/null", "http://192.168.0.1:80")
	private2Blocked := private2Err != nil

	// Test 3: the cloud metadata endpoint (169.254.169.254) is the marquee SSRF
	// target block_metadata_endpoint defends — verify it's actually unreachable.
	_, metadataErr := container.IncusOutput("exec", containerName, "--", "curl", "-s", "--connect-timeout", "2", "-o", "/dev/null", "http://169.254.169.254/")
	metadataBlocked := metadataErr != nil

	details := map[string]interface{}{
		"container_ip":        containerIP,
		"gateway_ip":          gatewayIP,
		"external_access":     externalOK,
		"private_blocked":     privateBlocked,
		"private_10_blocked":  privateBlocked,
		"private_192_blocked": private2Blocked,
		"metadata_blocked":    metadataBlocked,
	}
	if gwErr != nil {
		details["gateway_read_error"] = gwErr.Error()
	}

	if externalOK {
		details["external_status"] = httpOutput
	}

	// Evaluate results
	if externalOK && privateBlocked && private2Blocked && metadataBlocked {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusOK,
			Message: "Restricted mode working (external OK; private networks + metadata endpoint blocked)",
			Details: details,
		}
	}

	if !externalOK {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: "Restricted mode broken: external internet not accessible",
			Details: details,
		}
	}

	if !privateBlocked || !private2Blocked {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: "Restricted mode broken: private networks NOT blocked (firewall rules ineffective)",
			Details: details,
		}
	}

	if !metadataBlocked {
		return HealthCheck{
			Name:    "network_restriction",
			Status:  StatusFailed,
			Message: "Restricted mode broken: cloud metadata endpoint (169.254.169.254) NOT blocked (SSRF exposure)",
			Details: details,
		}
	}

	return HealthCheck{
		Name:    "network_restriction",
		Status:  StatusWarning,
		Message: "Restricted mode partially working",
		Details: details,
	}
}

// CheckSecretMasking proves, at runtime, that workspace secret masking
// (`[security] secret_paths`) actually hides a secret from inside the container.
// It plants a decoy secret plus a non-secret marker in a temp workspace, mounts
// it into an ephemeral container, applies the real masking code path
// (session.SetupSecretMasks), then reads both files from inside: the marker must
// be readable (proves the workspace is mounted/readable — the control), and the
// masked secret must read EMPTY (proves masking works). A leak is StatusFailed.
func CheckSecretMasking(imageName string, policy container.HardeningPolicy) HealthCheck {
	const name = "secret_masking"
	const secretSentinel = "COI_SECRET_SENTINEL_DO_NOT_LEAK"
	const markerSentinel = "COI_MARKER_SENTINEL"

	if imageName == "" {
		imageName = "coi-default"
	}
	// The probe idmaps a temp workspace (shift=true); if the host UID can't be
	// mapped, skip with a named cause instead of a cryptic forkmount [FAIL] (#838).
	if skip, ok := subidSkip(name); ok {
		return skip
	}
	if exists, err := container.ImageExists(imageName); err != nil || !exists {
		return HealthCheck{Name: name, Status: StatusWarning, Message: "Skipped (image not available)"}
	}

	// Temp workspace with a decoy secret + a readable marker (control).
	workspace, err := os.MkdirTemp("", "coi-secret-check-")
	if err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (temp dir: %v)", err)}
	}
	defer os.RemoveAll(workspace)
	if err := os.WriteFile(filepath.Join(workspace, ".env"), []byte(secretSentinel+"\n"), 0o600); err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (write secret: %v)", err)}
	}
	if err := os.WriteFile(filepath.Join(workspace, "marker.txt"), []byte(markerSentinel+"\n"), 0o644); err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (write marker: %v)", err)}
	}

	containerName := fmt.Sprintf("coi-secret-check-%d", time.Now().UnixNano())
	if err := probeLaunch(imageName, containerName, "", true, nil, policy); err != nil {
		return HealthCheck{Name: name, Status: StatusFailed, Message: fmt.Sprintf("Failed to launch test container: %v", err)}
	}
	defer func() {
		_ = container.StopContainer(containerName)
		_ = container.DeleteContainer(containerName)
	}()

	if !waitProbeReady(containerName) {
		return HealthCheck{Name: name, Status: StatusFailed, Message: "Test container failed to start within timeout"}
	}

	mgr := container.NewManager(containerName)
	const containerWorkspace = "/workspace"
	// Deliberately NOT session.ConfigureUIDMapping's decision: shift=false is
	// only half of the non-shift path, the other half being raw.idmap, which
	// takes effect at container START and this probe has already started. Handing the real
	// decision here without the mapping breaks the mask device outright
	// ("Failed to add mount for device inside container"). The workspace is a
	// throwaway MkdirTemp on local storage rather than the user's real one, so
	// shift is the right answer for it regardless of what the user's own
	// workspace filesystem would get (#683).
	const useShift = true
	if err := mgr.MountDisk("workspace", workspace, containerWorkspace, useShift, false); err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (mount workspace: %v)", err)}
	}

	// Apply the REAL masking code path.
	masked, _, maskErr := session.SetupSecretMasks(mgr, workspace, containerWorkspace, []string{".env"}, useShift)
	if maskErr != nil || len(masked) == 0 {
		return HealthCheck{Name: name, Status: StatusFailed, Message: fmt.Sprintf("Failed to apply secret masks: %v", maskErr)}
	}

	markerOut, _ := container.IncusOutput("exec", containerName, "--", "cat", containerWorkspace+"/marker.txt")
	secretOut, _ := container.IncusOutput("exec", containerName, "--", "cat", containerWorkspace+"/.env")

	controlReadable := strings.Contains(markerOut, markerSentinel)
	secretLeaked := strings.Contains(secretOut, secretSentinel)

	details := map[string]interface{}{
		"masked_paths":     masked,
		"control_readable": controlReadable,
		"secret_leaked":    secretLeaked,
	}

	if secretLeaked {
		return HealthCheck{
			Name:    name,
			Status:  StatusFailed,
			Message: "Secret masking INEFFECTIVE: a masked secret_paths file is readable inside the container",
			Details: details,
		}
	}
	if !controlReadable {
		// The masked file read empty, but so did the control marker — can't
		// distinguish working masking from a broken/unreadable mount. Don't claim
		// success on an inconclusive probe.
		return HealthCheck{
			Name:    name,
			Status:  StatusWarning,
			Message: "Could not verify secret masking (probe workspace not readable inside container)",
			Details: details,
		}
	}
	return HealthCheck{
		Name:    name,
		Status:  StatusOK,
		Message: "Secret masking working (masked secret_paths read empty inside the container)",
		Details: details,
	}
}

// CheckHostCredentialIsolation proves Coi's headline guarantee — host
// credentials are not exposed to the container unless explicitly mounted — holds
// at runtime. It plants a decoy in the host home directory, launches a probe
// container with its own (separate) temp workspace, and confirms the decoy is
// NOT readable inside by its host path. If it leaks, the host home has been
// mounted into the container (a containment regression) → StatusFailed.
func CheckHostCredentialIsolation(imageName string, policy container.HardeningPolicy) HealthCheck {
	const name = "host_credential_isolation"
	const sentinel = "COI_HOST_CRED_DECOY_DO_NOT_LEAK"

	if imageName == "" {
		imageName = "coi-default"
	}
	// Same idmap constraint as CheckSecretMasking: skip with a named cause when
	// the host UID can't be mapped, rather than a cryptic mount [FAIL] (#838).
	if skip, ok := subidSkip(name); ok {
		return skip
	}
	if exists, err := container.ImageExists(imageName); err != nil || !exists {
		return HealthCheck{Name: name, Status: StatusWarning, Message: "Skipped (image not available)"}
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (home dir: %v)", err)}
	}
	// Decoy in the host home ROOT (not inside .ssh/.aws — non-invasive); if Coi
	// ever mounted the host home into a container it would surface here.
	decoyPath := filepath.Join(homeDir, fmt.Sprintf(".coi-hostcred-decoy-%d", time.Now().UnixNano()))
	if err := os.WriteFile(decoyPath, []byte(sentinel+"\n"), 0o600); err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (write decoy: %v)", err)}
	}
	defer os.Remove(decoyPath)

	// Separate temp workspace so the probe doesn't mount the host home.
	workspace, err := os.MkdirTemp("", "coi-hostcred-check-")
	if err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (temp dir: %v)", err)}
	}
	defer os.RemoveAll(workspace)

	containerName := fmt.Sprintf("coi-hostcred-check-%d", time.Now().UnixNano())
	if err := probeLaunch(imageName, containerName, "", true, nil, policy); err != nil {
		return HealthCheck{Name: name, Status: StatusFailed, Message: fmt.Sprintf("Failed to launch test container: %v", err)}
	}
	defer func() {
		_ = container.StopContainer(containerName)
		_ = container.DeleteContainer(containerName)
	}()

	if !waitProbeReady(containerName) {
		return HealthCheck{Name: name, Status: StatusFailed, Message: "Test container failed to start within timeout"}
	}

	mgr := container.NewManager(containerName)
	// shift=true deliberately hardcoded for the same reason as the secret-mask
	// probe above: raw.idmap can't take effect on an already-started container,
	// and the workspace is a throwaway temp dir on local storage (#683).
	if err := mgr.MountDisk("workspace", workspace, "/workspace", true, false); err != nil {
		return HealthCheck{Name: name, Status: StatusWarning, Message: fmt.Sprintf("Skipped (mount workspace: %v)", err)}
	}

	// Try to read the host decoy by its absolute host path from inside.
	out, _ := container.IncusOutput("exec", containerName, "--", "cat", decoyPath)
	leaked := strings.Contains(out, sentinel)

	details := map[string]interface{}{
		"host_home":    homeDir,
		"decoy_path":   decoyPath,
		"decoy_leaked": leaked,
	}
	if leaked {
		return HealthCheck{
			Name:    name,
			Status:  StatusFailed,
			Message: "Host home is reachable inside the container — host credentials are NOT isolated",
			Details: details,
		}
	}
	return HealthCheck{
		Name:    name,
		Status:  StatusOK,
		Message: "Host credentials isolated (host home not reachable inside the container)",
		Details: details,
	}
}

// CheckProcessMonitoringCapability checks that host-side process collection works.
// Process monitoring reads /proc on the host filtered by container cgroup membership,
// so this check verifies the host walk succeeds — not that ps runs inside the container.
func CheckProcessMonitoringCapability(imageName string) HealthCheck {
	output, err := container.IncusOutput("list", "--format=json")
	if err != nil {
		return HealthCheck{
			Name:    "process_monitoring",
			Status:  StatusWarning,
			Message: "Unable to list containers",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(output), &containers); err != nil {
		return HealthCheck{
			Name:    "process_monitoring",
			Status:  StatusWarning,
			Message: "Unable to parse container list",
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}

	var testContainer string
	for _, c := range containers {
		if status, ok := c["status"].(string); ok && container.StatusIsRunning(status) {
			if name, ok := c["name"].(string); ok {
				testContainer = name
				break
			}
		}
	}

	if testContainer == "" {
		return HealthCheck{
			Name:    "process_monitoring",
			Status:  StatusWarning,
			Message: "No running containers to verify process monitoring",
			Details: map[string]interface{}{
				"hint": "Start a container with 'coi shell' to enable this check",
			},
		}
	}

	stats, err := monitor.CollectProcessStats(context.Background(), testContainer)
	if err != nil {
		return HealthCheck{
			Name:    "process_monitoring",
			Status:  StatusFailed,
			Message: fmt.Sprintf("Host-side process collection failed: %v", err),
			Details: map[string]interface{}{
				"container": testContainer,
				"hint":      "Ensure cgroup v2 is available and the monitor has read access to /proc",
			},
		}
	}

	return HealthCheck{
		Name:    "process_monitoring",
		Status:  StatusOK,
		Message: "Process monitoring is functional (host-side /proc walk)",
		Details: map[string]interface{}{
			"container":     testContainer,
			"process_count": stats.TotalCount,
		},
	}
}
