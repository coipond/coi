package container

import (
	"context"
	"time"
)

// Instance keys recording why coi last stopped or froze a container, and
// when (UTC, RFC 3339). A new start and `coi unfreeze` clear both.
const (
	StateReasonConfigKey   = "user.coi.state_reason"
	StateReasonAtConfigKey = "user.coi.state_reason_at"
)

// StateReason is the value of StateReasonConfigKey.
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
		StateReasonConfigKey+"="+string(reason),
		StateReasonAtConfigKey+"="+time.Now().UTC().Format(time.RFC3339))
}

// ClearStateReason removes the state reason keys that are set on the
// container. A container without them costs one (cached) config read.
func ClearStateReason(ctx context.Context, containerName string) error {
	return UnsetStateReasonKeys(ctx, containerName, StateReasonKeysSet(ctx, containerName))
}

// StateReasonKeysSet returns the state reason keys set on the container,
// read from the (cached) config. Both keys when the config cannot be read.
func StateReasonKeysSet(ctx context.Context, containerName string) []string {
	c, ok := loadInstanceConfig(ctx, containerName, false)
	var keys []string
	for _, key := range []string{StateReasonConfigKey, StateReasonAtConfigKey} {
		if !ok || c.config[key] != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

// UnsetStateReasonKeys removes keys (from StateReasonKeysSet) from the
// container.
func UnsetStateReasonKeys(ctx context.Context, containerName string, keys []string) error {
	for _, key := range keys {
		if err := IncusExecQuietContext(ctx, "config", "unset", containerName, key); err != nil {
			return err
		}
	}
	return nil
}
