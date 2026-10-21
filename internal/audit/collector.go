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
// With follow, it returns nil once ctx is done.
func HostAuditTail(ctx context.Context, path string, follow bool, sessionID, container string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	c := newHostAuditCopier(f, sessionID, container, out)
	if err := c.drain(); err != nil {
		return err
	}
	if !follow {
		// A dump prints a final record even when it has no trailing newline.
		return c.flush()
	}
	// Tail mode: simple sleep-poll loop over the same fd. We don't pull
	// in a heavy fsnotify dep just for this. A trailing partial line stays
	// pending in c until the writer finishes it.
	return tailFollow(ctx, c)
}

// copyHostAuditLines writes each record of a host-side audit log to out. Lines
// in the agent's event schema (a recording made with --follow) are re-encoded
// with sessionID/container stamped on, as StreamEvents does. The monitor's own
// records (threat events and snapshots, written by internal/monitor.AuditLog)
// carry no `type` and would be rejected by ParseLine, so a JSON object that is
// not an agent event is passed through verbatim. Anything else is skipped.
func copyHostAuditLines(r io.Reader, sessionID, container string, out io.Writer) error {
	c := newHostAuditCopier(r, sessionID, container, out)
	if err := c.drain(); err != nil {
		return err
	}
	return c.flush()
}

// hostAuditCopier is the incremental form of copyHostAuditLines used by the
// dump and --follow paths. It reads with bufio.Reader rather than
// bufio.Scanner so that (a) a record has no length cap (a monitor snapshot
// lists every process's full command line and can exceed any fixed token
// limit, which would abort the whole dump), and (b) a record the monitor is
// still writing when we hit EOF is held in pending instead of being split
// into two invalid halves and dropped.
type hostAuditCopier struct {
	br        *bufio.Reader
	pending   []byte
	enc       *json.Encoder
	out       io.Writer
	sessionID string
	container string
}

func newHostAuditCopier(r io.Reader, sessionID, container string, out io.Writer) *hostAuditCopier {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return &hostAuditCopier{br: bufio.NewReader(r), enc: enc, out: out, sessionID: sessionID, container: container}
}

// drain emits every complete (newline-terminated) line available now. A
// trailing partial line is kept in pending for the next drain or flush.
func (c *hostAuditCopier) drain() error {
	for {
		chunk, err := c.br.ReadBytes('\n')
		c.pending = append(c.pending, chunk...)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		line := c.pending
		c.pending = nil
		if err := c.emit(line); err != nil {
			return err
		}
	}
}

// flush emits a pending final line that has no trailing newline.
func (c *hostAuditCopier) flush() error {
	line := c.pending
	c.pending = nil
	return c.emit(line)
}

func (c *hostAuditCopier) emit(raw []byte) error {
	line := strings.TrimSpace(string(raw))
	// ParseLine turns non-JSON lines into agent.stderr audit events, as the
	// dump did before monitor records were passed through.
	if ev, err := ParseLine(line); err == nil && ev != nil {
		if c.sessionID != "" {
			ev.SessionID = c.sessionID
		}
		if c.container != "" {
			ev.Container = c.container
		}
		return c.enc.Encode(ev)
	}
	if json.Valid([]byte(line)) {
		_, err := io.WriteString(c.out, line+"\n")
		return err
	}
	return nil
}
