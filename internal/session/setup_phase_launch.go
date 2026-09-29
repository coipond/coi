package session

import (
	"context"
	"fmt"

	"github.com/mensfeld/coi/internal/container"
)

// 5. Create and configure the container (unless reusing), and set/update alias
// metadata for running-container lookup.
func (st *setupState) phaseCreateContainer(_ context.Context) (Teardown, error) {
	// Always launch as non-ephemeral so we can save session data even if container is stopped
	// (e.g., via 'sudo shutdown 0' from within). Cleanup will delete unless persistent mode is configured.
	if !st.skipLaunch {
		if err := createAndStartContainer(st.result, &st.opts, st.image, st.result.ContainerName); err != nil {
			return nil, err
		}
	}

	// Set/update alias metadata on container (for running-container lookup).
	// This runs for both new and reused containers so alias changes are propagated.
	if st.opts.Alias != "" {
		if err := container.IncusExec("config", "set", st.result.ContainerName,
			fmt.Sprintf("user.coi.alias=%s", st.opts.Alias)); err != nil {
			st.opts.Logger(fmt.Sprintf("Warning: Failed to set alias metadata: %v", err))
		}
	}
	return nil, nil
}

// 6. Wait for the container to become ready.
func (st *setupState) phaseWaitReady(ctx context.Context) (Teardown, error) {
	readyTimeout := st.opts.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = 30
	}
	if err := WaitForReady(ctx, st.result.Manager, readyTimeout, st.opts.Logger); err != nil {
		return nil, AnnotateReadyTimeout(err, st.opts.LimitsConfig)
	}
	return nil, nil
}

// 6.1 Configure the Docker bridge CIDR to prevent IP conflicts.
func (st *setupState) phaseConfigureDockerBridge(_ context.Context) (Teardown, error) {
	// Written whenever Docker is enabled — on reuse too, not only fresh
	// launches: a persistent container created with docker=false and later
	// flipped to docker=true has no daemon.json yet. The write is idempotent.
	// Skipped for an explicit --container attach ("use it as it is").
	if st.opts.ContainerName == "" && hardeningPolicyFrom(&st.opts).DockerEnabled() {
		if err := ConfigureDockerDaemon(st.result.Manager, st.opts.Logger); err != nil {
			st.opts.Logger(fmt.Sprintf("Warning: Failed to configure Docker daemon: %v", err))
		}
	}
	return nil, nil
}

// 6 (cont). Size /tmp to prevent space exhaustion in big builds (POST-start,
// fresh launches only).
func (st *setupState) phaseSizeTmpfs(_ context.Context) (Teardown, error) {
	if !st.skipLaunch {
		ApplyTmpfsSizing(st.result.Manager, st.opts.LimitsConfig, st.opts.Logger)
	}
	return nil, nil
}

// 6.4 Finalize the execution context by probing the container for the `code`
// user; fall back to root when it has none.
func (st *setupState) phaseDetectUser(_ context.Context) (Teardown, error) {
	hasCodeUser, err := DetectCodeUser(st.result.Manager, container.CodeUser)
	if err != nil {
		st.opts.Logger(fmt.Sprintf("Warning: could not probe container for %s user: %v — falling back to root", container.CodeUser, err))
		hasCodeUser = false
	}
	st.hasCodeUser = hasCodeUser
	st.result.RunAsRoot = !hasCodeUser
	if st.result.RunAsRoot {
		st.result.HomeDir = "/root"
	} else {
		st.result.HomeDir = "/home/" + container.CodeUser
	}
	return nil, nil
}

// 6.5 Remap the container user UID/GID if the configured UID differs from the
// image default (1000).
func (st *setupState) phaseRemapUID(_ context.Context) (Teardown, error) {
	if !st.skipLaunch && st.hasCodeUser && container.CodeUID != 1000 {
		if err := remapContainerUser(st.result, st.opts); err != nil {
			return nil, err
		}
	}
	return nil, nil
}
