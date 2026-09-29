package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mensfeld/coi/internal/bedrock"
	"github.com/mensfeld/coi/internal/container"
	"github.com/mensfeld/coi/internal/logger"
	"github.com/mensfeld/coi/internal/network"
	"github.com/mensfeld/coi/internal/vmhost"
)

// 1. Generate or use existing container name, create the manager and session
// logger, and route the network package's diagnostics to the session log.
func (st *setupState) phaseResolveName(_ context.Context) (Teardown, error) {
	var containerName string
	if st.opts.ContainerName != "" {
		// Use existing container (for testing)
		containerName = st.opts.ContainerName
		st.opts.Logger(fmt.Sprintf("Using existing container: %s", containerName))
	} else {
		// Generate new container name
		containerName = ContainerName(st.opts.WorkspacePath, st.opts.SessionName, st.opts.Slot)
		st.opts.Logger(fmt.Sprintf("Container name: %s", containerName))
	}
	st.result.ContainerName = containerName
	st.result.Manager = container.NewManager(containerName)

	hostHome, _ := os.UserHomeDir() // empty string on failure; logger.New handles it
	st.result.Logger = logger.New(containerName, hostHome)
	if w := st.result.Logger.InitWarning(); w != "" {
		st.opts.Logger(fmt.Sprintf("Warning: %s", w))
	}
	// Route the network package's diagnostics (incl. the background IP-refresh
	// goroutine) to the session log files instead of stderr, which in a coi
	// shell is the user's tmux terminal (issue #372).
	network.SetLogger(st.result.Logger)
	return nil, nil
}

// 1.5 Validate Bedrock setup if running in Colima/Lima.
func (st *setupState) phaseValidateBedrock(_ context.Context) (Teardown, error) {
	if vmhost.Detect().HandlesUIDMapping() && st.opts.CLIConfigPath != "" {
		settingsPath := filepath.Join(st.opts.CLIConfigPath, "settings.json")
		isConfigured, err := bedrock.IsBedrockConfigured(settingsPath)
		if err != nil {
			st.opts.Logger(fmt.Sprintf("Warning: Failed to check Bedrock configuration: %v", err))
		} else if isConfigured {
			st.opts.Logger("Detected AWS Bedrock configuration, validating setup...")

			// Validate Bedrock setup
			validationResult := bedrock.ValidateColimaBedrockSetup()

			// Check if .aws is mounted
			if st.opts.MountConfig != nil {
				var mountPaths []string
				for _, mount := range st.opts.MountConfig.Mounts {
					mountPaths = append(mountPaths, mount.HostPath)
				}
				if mountIssue := bedrock.CheckMountConfiguration(mountPaths); mountIssue != nil {
					validationResult.Issues = append(validationResult.Issues, *mountIssue)
				}
			}

			// If there are errors, fail with helpful message
			if validationResult.HasErrors() {
				return nil, fmt.Errorf("%s", validationResult.FormatError())
			}

			// Log warnings but continue
			if len(validationResult.Issues) > 0 {
				for _, issue := range validationResult.Issues {
					if issue.Severity == "warning" {
						st.opts.Logger(fmt.Sprintf("⚠️  %s", issue.Message))
					}
				}
			}
		}
	}
	return nil, nil
}

// Autofix: make sure the Incus bridge has iptables FORWARD ACCEPT rules before
// any container is started. Without them, containers cannot get IPs via DHCP
// when the FORWARD chain policy is DROP (e.g. when Docker is running).
func (st *setupState) phaseEnsureBridge(_ context.Context) (Teardown, error) {
	if changed, bridgeName, err := network.EnsureBridgeInTrustedZone(); err != nil {
		st.opts.Logger(fmt.Sprintf("Warning: could not ensure bridge forwarding rules: %v", err))
	} else if changed {
		st.opts.Logger(fmt.Sprintf("Added iptables FORWARD rules for %s (was missing — containers could not get IPs)", bridgeName))
	}
	return nil, nil
}

// 2. Determine image and verify it exists. 3. Set the provisional execution
// context (finalized in phaseDetectUser once the container is up).
func (st *setupState) phaseResolveImage(_ context.Context) (Teardown, error) {
	image := st.opts.Image
	if image == "" {
		image = CoiImage
	}
	st.result.Image = image
	st.image = image

	// Check if image exists
	exists, err := container.ImageExists(image)
	if err != nil {
		return nil, fmt.Errorf("failed to check image: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("image '%s' not found - run 'coi build' first", image)
	}

	// Provisional execution context — finalized at phaseDetectUser once the
	// container is up and we can probe it for the `code` user.
	//
	// Historically this was a literal string match against the coi-default
	// alias. That breaks custom images built FROM coi-default (they have
	// the `code` user inherited from the base layer but a different alias,
	// so the match returned false and the session was forced to root). We
	// now defer the final decision until after the container boots and
	// probe it directly.
	st.result.HomeDir = "/home/" + container.CodeUser
	return nil, nil
}
