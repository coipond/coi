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
	}
	// Below the threshold, entries older than the window cannot change the
	// answer, so they are pruned only once it is reached.
	if len(b.seen) >= b.threshold {
		for d, last := range b.seen {
			if ts.Sub(last) > b.window {
				delete(b.seen, d)
			}
		}
	}
	if n := len(b.seen); n >= b.threshold {
		return ThreatLevelHigh, fmt.Sprintf(" (rejected by the firewall; %d distinct rejected destinations within %s)", n, b.window)
	}
	return ThreatLevelWarning, " (rejected by the firewall)"
}
