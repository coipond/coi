package audit

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed agent/agent.sh
var agentScript []byte

// WriteAgentScriptTemp writes the embedded agent script to a fresh tempfile
// and returns its path. The file is mode 0700 so non-root users can run it
// after push without a separate chmod call.
func WriteAgentScriptTemp() (string, error) {
	dir, err := os.MkdirTemp("", "coi-audit-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "coi-audit-collector.sh")
	if err := os.WriteFile(path, agentScript, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return path, nil
}

// Collector consumes JSON-line audit events from an in-container agent and
// re-emits them — augmented with sessionId + container — as JSON lines on its
// configured Out writer.
//
// When Watcher is non-nil, every observed heartbeat event is fed to it so the
// caller can detect agent silence (e.g. an attacker inside the sandbox killed
// the collector). The watcher only observes; it does not filter the stream.
type Collector struct {
	SessionID string
	Container string
	Out       io.Writer
	OnError   func(error)
	Watcher   *HeartbeatWatcher
}

// Run reads agent JSON-lines from r until EOF or ctx cancellation, writing
// decorated JSON-lines to c.Out. Parse errors per line are forwarded to
// c.OnError if set; the stream is not aborted by them.
//
// Run honours ctx by closing r at cancellation if r implements io.Closer.
func (c *Collector) Run(ctx context.Context, r io.Reader) error {
	if c.Out == nil {
		c.Out = os.Stdout
	}
	if closer, ok := r.(io.Closer); ok && ctx != nil {
		go func() {
			<-ctx.Done()
			_ = closer.Close()
		}()
	}

	enc := json.NewEncoder(c.Out)
	enc.SetEscapeHTML(false)

	emit := func(ev Event) error {
		if ev.Type == TypeHeartbeat && c.Watcher != nil {
			c.Watcher.Observe(ev.SessionID)
		}
		return enc.Encode(ev)
	}
	return StreamEvents(r, c.SessionID, c.Container, emit, c.OnError)
}

// HostAuditTail tails an existing host-side audit JSONL file (the one written
// by internal/monitor.AuditLog) and emits each entry as an Event of type
// "audit". This is what `coi audit <session>` (without --follow) returns when
// there is no live container — it lets users inspect what was already logged.
func HostAuditTail(path string, follow bool, sessionID, container string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	if err := copyHostAuditLines(f, sessionID, container, out); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	// Tail mode: simple sleep-poll loop over the same fd. We don't pull
	// in a heavy fsnotify dep just for this.
	return tailFollow(f, sessionID, container, out)
}

// copyHostAuditLines writes each record of a host-side audit log to out. Lines
// in the agent's event schema (a recording made with --follow) are re-encoded
// with sessionID/container stamped on, as StreamEvents does. The monitor's own
// records (threat events and snapshots, written by internal/monitor.AuditLog)
// carry no `type` and would be rejected by ParseLine, so a JSON object that is
// not an agent event is passed through verbatim. Anything else is skipped.
func copyHostAuditLines(r io.Reader, sessionID, container string, out io.Writer) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if ev, err := ParseLine(line); err == nil && ev != nil {
			if sessionID != "" {
				ev.SessionID = sessionID
			}
			if container != "" {
				ev.Container = container
			}
			if err := enc.Encode(ev); err != nil {
				return err
			}
			continue
		}
		if json.Valid([]byte(line)) {
			if _, err := io.WriteString(out, line+"\n"); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}
