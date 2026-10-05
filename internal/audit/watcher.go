package audit

import (
	"context"
	"sync"
	"time"
)

// Default heartbeat parameters used by the host-side watcher.
//
// The agent emits a heartbeat every 10 s. The host trips a stale warning at
// 35 s (3 missed heartbeats with a small grace margin) and re-checks every
// 5 s. These constants are exported so callers (cli, tests) can match them.
const (
	DefaultHeartbeatInterval = 10 * time.Second
	DefaultStaleAfter        = 35 * time.Second
	DefaultCheckInterval     = 5 * time.Second
)

// WatcherStatus is a transition emitted by the watcher when it crosses a
// liveness threshold for a given session.
//
// StatusStale fires when last-seen heartbeat exceeds StaleAfter. StatusAlive
// fires the next time a heartbeat lands while the connection is in the stale
// state. StatusFirstSeen fires once per session when the first heartbeat is
// observed.
type WatcherStatus int

// WatcherStatus values.
const (
	StatusFirstSeen WatcherStatus = iota
	StatusStale
	StatusAlive
)

// String returns a short label for the status useful for log lines.
func (s WatcherStatus) String() string {
	switch s {
	case StatusFirstSeen:
		return "first-seen"
	case StatusStale:
		return "stale"
	case StatusAlive:
		return "alive"
	default:
		return "unknown"
	}
}

// HeartbeatWatcher tracks the most recent heartbeat per session and reports
// liveness transitions on a callback. The watcher does not kill the
// underlying connection; it only surfaces the state so the operator can
// decide.
//
// The zero value is not usable; construct via NewHeartbeatWatcher.
type HeartbeatWatcher struct {
	StaleAfter    time.Duration
	CheckInterval time.Duration

	OnTransition func(sessionID string, status WatcherStatus, lastSeen time.Time)

	now func() time.Time

	mu       sync.Mutex
	sessions map[string]*sessionState
}

type sessionState struct {
	lastSeen time.Time
	stale    bool
	seen     bool
}

// NewHeartbeatWatcher returns a watcher with the supplied callback and
// default thresholds. staleAfter and checkInterval default to
// DefaultStaleAfter and DefaultCheckInterval when zero is passed.
func NewHeartbeatWatcher(
	onTransition func(sessionID string, status WatcherStatus, lastSeen time.Time),
	staleAfter, checkInterval time.Duration,
) *HeartbeatWatcher {
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	if checkInterval <= 0 {
		checkInterval = DefaultCheckInterval
	}
	return &HeartbeatWatcher{
		StaleAfter:    staleAfter,
		CheckInterval: checkInterval,
		OnTransition:  onTransition,
		now:           time.Now,
		sessions:      make(map[string]*sessionState),
	}
}

// Observe records a heartbeat for sessionID. Calling this with an empty
// sessionID is a no-op, which keeps the watcher safe to wire in front of
// streams that haven't been decorated yet.
func (w *HeartbeatWatcher) Observe(sessionID string) {
	if sessionID == "" {
		return
	}
	w.mu.Lock()
	st, ok := w.sessions[sessionID]
	if !ok {
		st = &sessionState{}
		w.sessions[sessionID] = st
	}
	st.lastSeen = w.now()
	wasStale := st.stale
	wasSeen := st.seen
	st.stale = false
	st.seen = true
	last := st.lastSeen
	w.mu.Unlock()

	if !wasSeen {
		w.fire(sessionID, StatusFirstSeen, last)
		return
	}
	if wasStale {
		w.fire(sessionID, StatusAlive, last)
	}
}

// Run loops on CheckInterval, marking sessions stale that have not heartbeat
// within StaleAfter. Returns when ctx is cancelled.
func (w *HeartbeatWatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

func (w *HeartbeatWatcher) tick() {
	now := w.now()
	type fireRec struct {
		sessionID string
		status    WatcherStatus
		lastSeen  time.Time
	}
	var fires []fireRec

	w.mu.Lock()
	for id, st := range w.sessions {
		if !st.seen || st.stale {
			continue
		}
		if now.Sub(st.lastSeen) > w.StaleAfter {
			st.stale = true
			fires = append(fires, fireRec{id, StatusStale, st.lastSeen})
		}
	}
	w.mu.Unlock()

	for _, f := range fires {
		w.fire(f.sessionID, f.status, f.lastSeen)
	}
}

func (w *HeartbeatWatcher) fire(sessionID string, status WatcherStatus, lastSeen time.Time) {
	if w.OnTransition == nil {
		return
	}
	w.OnTransition(sessionID, status, lastSeen)
}
