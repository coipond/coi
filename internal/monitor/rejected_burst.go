package monitor

import (
	"fmt"
	"sync"
	"time"
)

// Defaults for [monitoring] rejected_burst_destinations and
// rejected_burst_window_sec.
const (
	DefaultRejectedBurstDestinations = 10
	DefaultRejectedBurstWindowSec    = 60
)

// RejectedBurst rates connection attempts the firewall rejects. One is a
// WARNING: the firewall already stopped it. Attempts to threshold or more
// distinct destinations within window are a HIGH (a scan or a search for a way
// out). Safe for concurrent use.
type RejectedBurst struct {
	threshold int
	window    time.Duration

	mu   sync.Mutex
	seen map[string]time.Time // destination -> last attempt
	// queue holds attempts in arrival order, to prune in O(1) amortized; an
	// entry whose ts is not its destination's last attempt is stale.
	queue []rejectedAttempt
}

// rejectedAttempt is one queued attempt of RejectedBurst.
type rejectedAttempt struct {
	destination string
	ts          time.Time
}

// NewRejectedBurst creates the tracker; a threshold or window <= 0 takes its
// default.
func NewRejectedBurst(threshold int, window time.Duration) *RejectedBurst {
	if threshold <= 0 {
		threshold = DefaultRejectedBurstDestinations
	}
	if window <= 0 {
		window = DefaultRejectedBurstWindowSec * time.Second
	}
	return &RejectedBurst{threshold: threshold, window: window, seen: make(map[string]time.Time)}
}

// Rate records a rejected attempt to destination at ts and returns its
// severity, with the description suffix that says why.
func (b *RejectedBurst) Rate(destination string, ts time.Time) (ThreatLevel, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if last, ok := b.seen[destination]; !ok || ts.After(last) {
		b.seen[destination] = ts
		b.queue = append(b.queue, rejectedAttempt{destination, ts})
	}
	for len(b.queue) > 0 && ts.Sub(b.queue[0].ts) > b.window {
		old := b.queue[0]
		b.queue = b.queue[1:]
		if b.seen[old.destination].Equal(old.ts) {
			delete(b.seen, old.destination)
		}
	}
	if n := len(b.seen); n >= b.threshold {
		return ThreatLevelHigh, fmt.Sprintf(" (rejected by the firewall; %d distinct rejected destinations within %s)", n, b.window)
	}
	return ThreatLevelWarning, " (rejected by the firewall)"
}
