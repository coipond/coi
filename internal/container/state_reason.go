package container

import (
	"context"
	"time"
)

// Instance keys recording why coi last stopped or froze a container, and
// when (UTC, RFC 3339). A new start and `coi unfreeze` clear both.
const (
	StateReasonKey   = "user.coi.state_reason"
	StateReasonAtKey = "user.coi.state_reason_at"
)

// StateReason is the value of StateReasonKey.
type StateReason string

// Reasons coi stops or freezes a container for.
const (
	StateReasonMaxDuration StateReason = "max_duration"
	StateReasonUser        StateReason = "user"
)

// MonitorStateReason is the reason for a freeze by the security monitor on
// the threat with the given title.
func MonitorStateReason(threatTitle string) StateReason {
	return StateReason("monitor:" + threatTitle)
}

// SetStateReason records reason and the current time on the container.
// It writes nothing to the terminal, so it is safe from a background
// monitor while a session is attached.
func SetStateReason(ctx context.Context, containerName string, reason StateReason) error {
	return IncusExecQuietContext(ctx, "config", "set", containerName,
		StateReasonKey+"="+string(reason),
		StateReasonAtKey+"="+time.Now().UTC().Format(time.RFC3339))
}

// ClearStateReason removes the state reason keys that are set on the
// container. A container without them costs one (cached) config read.
func ClearStateReason(ctx context.Context, containerName string) error {
	c, ok := loadInstanceConfig(ctx, containerName, false)
	for _, key := range []string{StateReasonKey, StateReasonAtKey} {
		if ok && c.config[key] == "" {
			continue
		}
		if err := IncusExecQuietContext(ctx, "config", "unset", containerName, key); err != nil {
			return err
		}
	}
	return nil
}
