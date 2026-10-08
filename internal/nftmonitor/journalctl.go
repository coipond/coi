//go:build linux
// +build linux

package nftmonitor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
)

// Debug controls whether debug output is enabled
// Set COI_NFT_DEBUG=1 to enable
var Debug = os.Getenv("COI_NFT_DEBUG") == "1"

func debugf(format string, args ...interface{}) {
	if !Debug {
		return
	}
	// Route to the session log when set so COI_NFT_DEBUG output during a live
	// session lands in the log file, not the user's attached terminal (issue
	// #372 class). Fall back to stderr only for standalone/CLI use.
	if l := pkgLogger.Load(); l != nil {
		l.Printf("[NFT-DEBUG] "+format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "[NFT-DEBUG] "+format+"\n", args...) // terminal-sink-ok: fallback only when no session logger is set (non-session/CLI use)
}

// JournalReader wraps systemd journal for reading kernel logs.
//
// While StreamLogs runs it owns the sd-journal handle: Close only flags the
// reader closed and StreamLogs closes the handle on its way out. Closing it
// from another goroutine while journal.Wait (which runs unlocked, so Close
// never blocks for its timeout) is inside sd_journal_wait freed the handle
// under it; the C code then closed file descriptors whose numbers the process
// had already reused — e.g. the pidfd of the next `sudo nft` child, whose
// wait then failed with "waitid: bad file descriptor", so the session's
// monitoring rules were never removed.
type JournalReader struct {
	journal   *sdjournal.Journal
	mu        sync.Mutex
	closed    bool
	streaming bool
}

// JournalOpenTimeout is the maximum time to wait for journal to open
const JournalOpenTimeout = 5 * time.Second

// NewJournalReader creates a new journal reader for kernel logs
// Uses a timeout to prevent hanging if journal access is blocked
func NewJournalReader() (*JournalReader, error) {
	type result struct {
		reader *JournalReader
		err    error
	}

	resultChan := make(chan result, 1)

	go func() {
		reader, err := newJournalReaderInternal()
		resultChan <- result{reader, err}
	}()

	select {
	case res := <-resultChan:
		return res.reader, res.err
	case <-time.After(JournalOpenTimeout):
		return nil, fmt.Errorf("timeout opening systemd journal (waited %v) - journal may not be accessible", JournalOpenTimeout)
	}
}

// newJournalReaderInternal does the actual journal opening
func newJournalReaderInternal() (*JournalReader, error) {
	debugf("Opening systemd journal...")
	journal, err := sdjournal.NewJournal()
	if err != nil {
		return nil, fmt.Errorf("failed to open systemd journal: %w", err)
	}
	debugf("Journal opened successfully")

	// Filter to kernel messages only
	// Note: Set COI_NFT_NO_FILTER=1 to disable filtering for debugging
	if os.Getenv("COI_NFT_NO_FILTER") != "1" {
		if err := journal.AddMatch("_TRANSPORT=kernel"); err != nil {
			journal.Close()
			return nil, fmt.Errorf("failed to add kernel filter: %w", err)
		}
		debugf("Added journal filter: _TRANSPORT=kernel")
	} else {
		debugf("WARNING: Journal filter disabled (COI_NFT_NO_FILTER=1)")
	}

	// Start from the end (only read new logs)
	if err := journal.SeekTail(); err != nil {
		journal.Close()
		return nil, fmt.Errorf("failed to seek to end of journal: %w", err)
	}

	// SeekTail positions past the last entry. We need to step back
	// to a valid position, then Next() will read truly new entries.
	n, _ := journal.Previous()
	debugf("After SeekTail+Previous: Previous() returned %d", n)

	debugf("JournalReader initialized, waiting for new kernel log entries")

	return &JournalReader{journal: journal}, nil
}

// StreamLogs streams kernel log messages to the provided channel
func (jr *JournalReader) StreamLogs(ctx context.Context, msgChan chan<- string) error {
	jr.mu.Lock()
	if jr.closed || jr.streaming {
		jr.mu.Unlock()
		return nil
	}
	jr.streaming = true
	jr.mu.Unlock()
	// Close the journal when we're done streaming: we own it until then.
	defer func() {
		jr.mu.Lock()
		defer jr.mu.Unlock()
		jr.streaming = false
		jr.closed = true
		_ = jr.closeLocked()
	}()

	debugf("StreamLogs started, entering main loop")

	for {
		select {
		case <-ctx.Done():
			debugf("Context done, exiting StreamLogs")
			return ctx.Err()
		default:
		}

		// Check if we've been closed
		jr.mu.Lock()
		if jr.closed {
			jr.mu.Unlock()
			debugf("Journal closed, exiting StreamLogs")
			return nil
		}
		journal := jr.journal
		jr.mu.Unlock()

		if journal == nil {
			debugf("Journal is nil, exiting StreamLogs")
			return nil
		}

		// Wait for new journal entries (with timeout)
		// Returns: SD_JOURNAL_NOP (0) = nothing, SD_JOURNAL_APPEND (1) = new entries
		waitResult := journal.Wait(time.Second)
		if waitResult == sdjournal.SD_JOURNAL_APPEND {
			debugf("Journal.Wait returned APPEND - new entries available")
		}

		// Check again after wait
		jr.mu.Lock()
		if jr.closed {
			jr.mu.Unlock()
			return nil
		}
		jr.mu.Unlock()

		// Read all available entries
		entriesRead := 0
		for {
			jr.mu.Lock()
			if jr.closed || jr.journal == nil {
				jr.mu.Unlock()
				return nil
			}
			n, err := jr.journal.Next()
			jr.mu.Unlock()

			if err != nil {
				debugf("journal.Next() error: %v", err)
				return fmt.Errorf("failed to read next journal entry: %w", err)
			}
			if n == 0 {
				if entriesRead == 0 && waitResult == sdjournal.SD_JOURNAL_APPEND {
					debugf("WARNING: Wait() returned APPEND but Next() returned 0 entries")
				}
				break // No more entries
			}
			entriesRead++
			debugf("journal.Next() returned entry %d", entriesRead)

			jr.mu.Lock()
			if jr.closed || jr.journal == nil {
				jr.mu.Unlock()
				return nil
			}

			// Debug: get and log some key fields
			if Debug {
				if transport, err := jr.journal.GetData("_TRANSPORT"); err == nil {
					debugf("  _TRANSPORT: %s", transport)
				}
				if syslogID, err := jr.journal.GetData("SYSLOG_IDENTIFIER"); err == nil {
					debugf("  SYSLOG_IDENTIFIER: %s", syslogID)
				}
			}

			// Get the MESSAGE field (kernel log message)
			// Note: GetData returns "MESSAGE=<content>", we need to strip the prefix
			msg, err := jr.journal.GetData("MESSAGE")
			jr.mu.Unlock()

			if err != nil {
				debugf("GetData(MESSAGE) failed: %v", err)
				continue // Skip entries without MESSAGE
			}

			// Strip the "MESSAGE=" prefix that GetData returns
			msg = strings.TrimPrefix(msg, "MESSAGE=")

			// Show more of the message for debugging
			msgPreview := msg
			if len(msgPreview) > 200 {
				msgPreview = msgPreview[:200] + "..."
			}
			debugf("Got journal message: %s", msgPreview)

			// Send to channel (non-blocking)
			select {
			case msgChan <- msg:
				debugf("Message sent to channel")
			case <-ctx.Done():
				return ctx.Err()
			default:
				debugf("Channel full, skipping message")
				// Channel full, skip this message
			}
		}
	}
}

// Close closes the journal reader (safe to call multiple times). While
// StreamLogs is running it only marks the reader closed; StreamLogs notices
// within one Wait timeout and closes the handle itself.
func (jr *JournalReader) Close() error {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.closed = true
	if jr.streaming {
		return nil
	}
	return jr.closeLocked()
}

// closeLocked closes the sd-journal handle once. Callers hold jr.mu.
func (jr *JournalReader) closeLocked() error {
	if jr.journal == nil {
		return nil
	}
	err := jr.journal.Close()
	jr.journal = nil
	return err
}
