package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/config"
	"github.com/coipond/coi/internal/limits"
	"github.com/coipond/coi/internal/network"
)

// 6.6 Forward host sockets (SSH agent built-in entry plus configured
// [[sockets]]) to the running container.
func (st *setupState) phaseForwardSockets(_ context.Context) (Teardown, error) {
	st.result.SocketEnv = ForwardConfiguredSockets(st.result.Manager, st.opts.Network.Sockets, st.opts.Network.ForwardSSHAgent, st.opts.Logger)
	st.result.SSHAgentSocketPath = st.result.SocketEnv["SSH_AUTH_SOCK"]
	return nil, nil
}

// 6.6.05 Publish configured [ports] on the host (proxy devices).
func (st *setupState) phasePublishPorts(_ context.Context) (Teardown, error) {
	st.result.PublishedPorts, st.result.PortsEnv = PublishResolvedPorts(st.result.Manager, st.resolvedPorts, st.opts.Logger)
	return nil, nil
}

// 6.6.1 Prevent git from guessing a commit identity from the container user
// (and, under git.readonly, mount the identity read-only).
func (st *setupState) phaseConfigureGit(ctx context.Context) (Teardown, error) {
	if err := configureGitIdentity(ctx, st.result, st.opts); err != nil {
		return nil, err
	}
	return nil, nil
}

// 6.6.2 Claude managed settings: auto-mode prompt suppression and
// includeCoAuthoredBy handling. No-op for other tools.
func (st *setupState) phaseClaudeSettings(_ context.Context) (Teardown, error) {
	if st.opts.Tool != nil && st.opts.Tool.Name() == "claude" {
		SetupClaudeManagedSettings(st.result.Manager,
			shouldSuppressClaudeAutoMode(st.opts.Tool.Name(), st.opts.PermissionMode),
			st.opts.Git.StripAttribution, st.opts.Logger)
	}
	return nil, nil
}

// 6.7 Configure the timezone inside the container (or reset to UTC).
//
// No exec of its own: the (idempotent) command rides along with the context
// files' exec in phaseInjectContext, which every session runs anyway, so a
// reused container whose zone already matches pays nothing for it.
func (st *setupState) phaseConfigureTimezone(_ context.Context) (Teardown, error) {
	// Always set result.Timezone so the TZ env var is applied even if the
	// filesystem configuration fails (some programs only check TZ).
	st.result.Timezone = st.opts.Timezone
	// Empty means UTC: reset explicitly — important for persistent containers
	// that may have had a different timezone applied in a previous session.
	st.pendingGuestOps = append(st.pendingGuestOps, timezoneOp(st.opts.Timezone))
	return nil, nil
}

// Markers timezoneOp prints.
const (
	timezoneSetMarker    = "coi:tz-set"
	timezoneFailedMarker = "coi:tz-failed"
)

// timezoneOp sets the container's zone ("" = UTC). It writes nothing when the
// zone already matches (the usual case on a reused persistent container),
// prints timezoneSetMarker when it changed it, and never fails the batch it
// rides in: a failure prints timezoneFailedMarker instead.
func timezoneOp(tz string) guestOp {
	if tz == "" {
		tz = "UTC"
	}
	return guestCmd(timezoneCmd(tz) + " || echo " + timezoneFailedMarker)
}

// timezoneCmd sets the container's zone, writing nothing when it is already
// set, and prints timezoneSetMarker when it did write.
func timezoneCmd(tz string) string {
	return fmt.Sprintf(
		`{ [ "$(readlink /etc/localtime)" = /usr/share/zoneinfo/%[1]s ] && [ "$(cat /etc/timezone 2>/dev/null)" = %[1]s ]; } || { ln -sf /usr/share/zoneinfo/%[1]s /etc/localtime && echo %[1]s > /etc/timezone && echo %[2]s; }`,
		tz, timezoneSetMarker,
	)
}

// reportTimezone logs what the batched timezoneOp did, from the exec output.
func reportTimezone(out, tz string, logger func(string)) {
	if tz == "" {
		tz = "UTC"
	}
	switch {
	case strings.Contains(out, timezoneFailedMarker):
		logger(fmt.Sprintf("Warning: Failed to set timezone to %s", tz))
	case strings.Contains(out, timezoneSetMarker):
		logger(fmt.Sprintf("Set container timezone to %s", tz))
	}
}

// 7. Start the timeout monitor if max_duration is configured.
func (st *setupState) phaseStartTimeoutMonitor(ctx context.Context) (Teardown, error) {
	if st.opts.LimitsConfig != nil && st.opts.LimitsConfig.Runtime.MaxDuration != "" {
		duration, err := limits.ParseDuration(st.opts.LimitsConfig.Runtime.MaxDuration)
		if err != nil {
			return nil, fmt.Errorf("invalid max_duration: %w", err)
		}
		if duration > 0 {
			st.result.TimeoutMonitor = limits.NewTimeoutMonitor(
				ctx,
				st.result.ContainerName,
				duration,
				config.BoolVal(st.opts.LimitsConfig.Runtime.AutoStop),
				config.BoolVal(st.opts.LimitsConfig.Runtime.StopGraceful),
				st.opts.IncusProject,
				st.result.Logger,
			)
			st.result.TimeoutMonitor.Start()
		}
	}
	return nil, nil
}

// 8. Setup network isolation (after the container is running and has an IP).
func (st *setupState) phaseSetupNetwork(ctx context.Context) (Teardown, error) {
	if st.opts.Network.Config != nil {
		st.result.NetworkManager = network.NewManager(st.opts.Network.Config, st.result.Logger)
		if err := st.result.NetworkManager.SetupForContainer(ctx, st.result.ContainerName); err != nil {
			return nil, fmt.Errorf("failed to setup network isolation: %w", err)
		}
	}
	return nil, nil
}
