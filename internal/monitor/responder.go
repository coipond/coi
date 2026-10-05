package monitor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coipond/coi/internal/container"
	"github.com/coipond/coi/internal/network"
)

// Responder handles automated responses to threats
type Responder struct {
	containerName      string
	autoPauseOnHigh    bool
	autoKillOnCritical bool
	forensicsOnKill    bool // preserve a forensic copy of the container before the kill deletes it (opt-in, default false)
	auditLog           *AuditLog
	onThreat           func(ThreatEvent)
	onAction           func(action, message string) // Called when container is paused/killed
	onError            func(error)                  // Called for non-fatal cleanup errors (routes to the session log, never the terminal)

	// State tracking to prevent infinite loops
	mu            sync.Mutex
	paused        bool
	killed        bool
	recentThreats map[string]time.Time // threat key -> last alert time
	dedupeWindow  time.Duration
}

// NewResponder creates a new threat responder
func NewResponder(containerName string, autoPauseOnHigh, autoKillOnCritical bool,
	auditLog *AuditLog, onThreat func(ThreatEvent),
) *Responder {
	return &Responder{
		containerName:      containerName,
		autoPauseOnHigh:    autoPauseOnHigh,
		autoKillOnCritical: autoKillOnCritical,
		forensicsOnKill:    false, // opt-in; production sets it via SetForensicsOnKill([monitoring] forensics_on_kill)
		auditLog:           auditLog,
		onThreat:           onThreat,
		recentThreats:      make(map[string]time.Time),
		dedupeWindow:       30 * time.Second, // Don't re-alert for same threat within 30s
	}
}

// SetForensicsOnKill controls whether killContainer preserves a forensic copy
// of the container before deleting it ([monitoring] forensics_on_kill,
// opt-in, default false).
func (r *Responder) SetForensicsOnKill(enabled bool) {
	r.forensicsOnKill = enabled
}

// SetOnAction sets a callback for when critical actions (pause/kill) are taken
func (r *Responder) SetOnAction(callback func(action, message string)) {
	r.onAction = callback
}

// SetOnError sets a callback for non-fatal cleanup errors. The daemons wire this
// to the session logger so the warnings are recorded in
// ~/.coi/logs/<container>.stderr.log instead of being written to the user's
// attached terminal (issue #372 class).
func (r *Responder) SetOnError(callback func(error)) {
	r.onError = callback
}

// reportError routes a non-fatal error to the onError callback when set. It is
// deliberately silent when no callback is set: these are best-effort cleanup
// warnings on the kill path and must never fall back to a terminal sink.
func (r *Responder) reportError(err error) {
	if r.onError != nil {
		r.onError(err)
	}
}

// Handle processes a threat and takes appropriate action
func (r *Responder) Handle(ctx context.Context, threat ThreatEvent) error {
	r.mu.Lock()

	// If already killed, nothing more to do
	if r.killed {
		r.mu.Unlock()
		return nil
	}

	// Deduplicate recent threats - create a key from threat category and title
	threatKey := threat.Category + ":" + threat.Title
	if s := threat.Evidence.String(); s != "" {
		// Include evidence summary in key for more precise deduplication
		threatKey += ":" + s
	}

	now := time.Now()
	if lastSeen, exists := r.recentThreats[threatKey]; exists {
		if now.Sub(lastSeen) < r.dedupeWindow {
			// Already alerted for this threat recently, just log silently
			r.mu.Unlock()
			threat.Action = "deduplicated"
			return r.logThreat(threat)
		}
	}
	r.recentThreats[threatKey] = now

	// Clean up old entries from the map periodically
	if len(r.recentThreats) > 100 {
		for key, ts := range r.recentThreats {
			if now.Sub(ts) > r.dedupeWindow*2 {
				delete(r.recentThreats, key)
			}
		}
	}

	// Check if already paused (for high-level threats that would pause)
	alreadyPaused := r.paused
	r.mu.Unlock()

	// Determine action based on threat level
	switch threat.Level {
	case ThreatLevelInfo:
		threat.Action = "logged"
		return r.logThreat(threat)

	case ThreatLevelWarning:
		threat.Action = "alerted"
		r.alert(threat)
		return r.logThreat(threat)

	case ThreatLevelHigh:
		if r.autoPauseOnHigh {
			if alreadyPaused {
				// Already paused, just log
				threat.Action = "logged (already paused)"
				return r.logThreat(threat)
			}
			threat.Action = "paused"
			r.alert(threat)
			if err := r.logThreat(threat); err != nil {
				return err
			}
			return r.pauseContainer(ctx)
		}
		threat.Action = "alerted"
		r.alert(threat)
		return r.logThreat(threat)

	case ThreatLevelCritical:
		if r.autoKillOnCritical {
			threat.Action = "killed"
			r.alert(threat)
			if err := r.logThreat(threat); err != nil {
				return err
			}
			return r.killContainer(ctx)
		}
		threat.Action = "alerted"
		r.alert(threat)
		return r.logThreat(threat)
	}

	return nil
}

// logThreat writes threat to audit log
func (r *Responder) logThreat(threat ThreatEvent) error {
	if r.auditLog != nil {
		return r.auditLog.WriteThreat(threat)
	}
	return nil
}

// alert notifies via callback
func (r *Responder) alert(threat ThreatEvent) {
	if r.onThreat != nil {
		r.onThreat(threat)
	}
}

// pauseContainer pauses the container
func (r *Responder) pauseContainer(ctx context.Context) error {
	r.mu.Lock()
	if r.paused {
		r.mu.Unlock()
		return nil // Already paused
	}
	r.mu.Unlock()

	// Use IncusOutputWithStderr to capture error messages from Incus
	// (like "already frozen" which goes to stderr)
	output, err := container.IncusOutputWithStderrContext(ctx, "pause", r.containerName)
	if err != nil {
		// Check if error is because container is already paused
		// Incus returns "The container is already frozen" for this case
		// The message may be in err.Error() or in the combined output
		errStr := err.Error() + " " + output
		if strings.Contains(errStr, "already frozen") ||
			strings.Contains(errStr, "already paused") {
			r.mu.Lock()
			r.paused = true
			r.mu.Unlock()
			return nil
		}
		return fmt.Errorf("failed to pause container: %w", err)
	}

	r.mu.Lock()
	r.paused = true
	r.mu.Unlock()

	// Notify about the pause action
	if r.onAction != nil {
		r.onAction("paused", fmt.Sprintf("Container %s PAUSED due to security threat. Unfreeze with: coi unfreeze %s", r.containerName, r.containerName))
	}

	return nil
}

// killContainer stops and deletes the container, first (unless disabled)
// preserving a forensic COPY: the auto-kill fires exactly when the container's
// state is most worth investigating — deleting it with the threat would
// destroy the evidence of HOW the attempt worked, leaving only the audit log
// ("snapshot state for investigation before deactivating", Trail of Bits).
//
// The copy is made WHILE THE CONTAINER IS STILL RUNNING and the original is
// left EPHEMERAL, so the stop below still auto-deletes the original exactly as
// before — the kill's "container gone under its name" contract is unchanged
// and, crucially, is guaranteed by Incus's ephemeral auto-delete even if the
// coi process hosting this daemon is torn down by the very stop (which ends
// the attached session). The copy is a separate, non-ephemeral container that
// survives independently. On the CI/recommended btrfs (or zfs) pool a copy is
// a near-instant COW reflink; it is done before the stop so it never delays
// the security response either way.
func (r *Responder) killContainer(ctx context.Context) error {
	r.mu.Lock()
	if r.killed {
		r.mu.Unlock()
		return nil // Already killed
	}
	r.mu.Unlock()

	// Forensic copy BEFORE the stop, while the container is still running.
	// Best-effort: a failed prune/copy must never block or delay the kill.
	// When enabled, the copy adds a little latency before the delete, so the
	// delete then runs under a DETACHED context (see stopAndDelete).
	forensicName := ""
	detachStop := false
	if r.forensicsOnKill {
		r.pruneForensicCopies(ctx)
		name := forensicCopyName(r.containerName, time.Now())
		if _, err := container.IncusOutputContext(ctx, "copy", r.containerName, name); err != nil {
			r.reportError(fmt.Errorf("failed to create forensic copy (continuing with kill): %w", err))
		} else {
			forensicName = name
			detachStop = true
		}
	}
	forensicNote := ""
	if forensicName != "" {
		forensicNote = fmt.Sprintf(" — forensic copy preserved as %q (inspect with `incus file pull`/`incus start`, dispose with `incus delete`)", forensicName)
	}

	// Notify about the kill action BEFORE killing
	if r.onAction != nil {
		r.onAction("killed", fmt.Sprintf("Container %s KILLED due to critical security threat%s", r.containerName, forensicNote))
	}

	if err := r.stopAndDelete(ctx, detachStop); err != nil {
		return err
	}

	r.mu.Lock()
	r.killed = true
	r.mu.Unlock()
	return nil
}

// stopAndDelete removes the container in ONE atomic `incus delete --force`
// (stop + delete in a single incusd operation), after cleaning up its
// firewall/NFT rules.
//
// It used to stop and then delete in two calls. The stop ends the session,
// and whatever hosts this daemon (the attached `coi shell`, or the background
// session's supervisor, which exits as soon as it sees the container
// Stopped) can be torn down in that gap — losing the delete and leaving a
// killed container behind, Stopped. One incusd operation has no such gap:
// once the request is sent, incusd finishes it even if this process dies.
//
// detached (the forensics path) runs under a fresh timeout-bounded context
// rather than the caller's, because the forensic copy added latency ahead of
// the delete during which the caller context may already be cancelling.
func (r *Responder) stopAndDelete(callerCtx context.Context, detached bool) error {
	ctx := callerCtx
	if detached {
		if callerCtx.Err() != nil {
			return callerCtx.Err() // real shutdown already in progress
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
	}

	// Get container IP BEFORE removing it (needed for cleanup), and clean up
	// first so the rules go even if this process dies right after the delete.
	containerIP, _ := network.GetContainerIPFast(r.containerName)
	r.cleanupContainerRules(containerIP)

	// Tolerate not-found: a race (or the ephemeral auto-delete) already removed it.
	if _, err := container.IncusOutputContext(ctx, "delete", "--force", r.containerName); err != nil && !container.IsNotFoundErr(err) {
		return fmt.Errorf("failed to delete container: %w", err)
	}
	return nil
}

// cleanupContainerRules removes the container's firewall and NFT monitoring
// rules (keyed on the captured IP). Best-effort — warnings only.
func (r *Responder) cleanupContainerRules(containerIP string) {
	if containerIP == "" {
		return
	}
	if err := r.cleanupNftRules(containerIP); err != nil {
		r.reportError(fmt.Errorf("failed to cleanup nft rules: %w", err))
	}
	if err := r.cleanupNFTRules(containerIP); err != nil {
		r.reportError(fmt.Errorf("failed to cleanup NFT monitoring rules: %w", err))
	}
}

// maxForensicCopies caps how many forensic copies may exist per container
// name (oldest pruned first), so repeated incidents on the same slot cannot
// fill the storage pool.
const maxForensicCopies = 3

// forensicCopyName derives the preserved container's name. The unix-seconds suffix
// is fixed-width for the next few centuries, so lexicographic order equals
// chronological order — pruning can sort names directly.
func forensicCopyName(containerName string, now time.Time) string {
	return fmt.Sprintf("%s-forensics-%d", containerName, now.Unix())
}

// forensicCopiesToPrune returns the names to delete so that, together with the
// one copy about to be created, at most maxForensicCopies remain. names may
// contain unrelated containers; only "<containerName>-forensics-" entries are
// considered. Oldest (lexicographically smallest suffix) go first.
func forensicCopiesToPrune(names []string, containerName string) []string {
	prefix := containerName + "-forensics-"
	var copies []string
	for _, n := range names {
		if strings.HasPrefix(n, prefix) {
			copies = append(copies, n)
		}
	}
	sort.Strings(copies)
	// Keep maxForensicCopies-1 existing so the new copy fits under the cap.
	if excess := len(copies) - (maxForensicCopies - 1); excess > 0 {
		return copies[:excess]
	}
	return nil
}

// pruneForensicCopies deletes the oldest preserved containers beyond the cap
// so the one about to be created fits under it. Best-effort: a failed
// list/delete must not stop the evidence preservation or the kill.
func (r *Responder) pruneForensicCopies(ctx context.Context) {
	out, err := container.IncusOutputContext(ctx, "list", "--format", "csv", "-c", "n", r.containerName+"-forensics-")
	if err != nil {
		return
	}
	names := strings.Fields(strings.TrimSpace(out))
	for _, stale := range forensicCopiesToPrune(names, r.containerName) {
		if _, err := container.IncusOutputContext(ctx, "delete", "--force", stale); err != nil {
			r.reportError(fmt.Errorf("failed to prune old forensic container %s: %w", stale, err))
		}
	}
}

// cleanupNftRules removes nft rules for a container IP
func (r *Responder) cleanupNftRules(containerIP string) error {
	fm := network.NewNftManager(containerIP, "")
	return fm.RemoveRules()
}

// cleanupNFTRules removes NFT monitoring rules for a container IP
func (r *Responder) cleanupNFTRules(containerIP string) error {
	return network.CleanupNFTMonitoringRules(containerIP)
}
