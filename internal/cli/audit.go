package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/mensfeld/coi/internal/audit"
	"github.com/mensfeld/coi/internal/container"
	"github.com/spf13/cobra"
)

var (
	auditFollow bool
	auditFile   string
)

func init() {
	auditCmd.Flags().BoolVarP(&auditFollow, "follow", "f", false, "Stream events live from the container's in-sandbox collector")
	auditCmd.Flags().StringVar(&auditFile, "file", "", "Read from a specific audit JSONL file instead of the host-side default path")
	rootCmd.AddCommand(auditCmd)
}

var auditCmd = &cobra.Command{
	Use:   "audit [container]",
	Short: "Stream threat-event audit records from a sandbox session",
	Long: `Stream threat-event audit records from a sandbox session as JSON lines.

Default mode reads the host-side audit log written by the security monitor
daemon (~/.coi/audit/<container>.jsonl). With --follow, the command spawns an
in-container collector that emits live events from auditd (when present),
syslog/auth.log, periodic ss snapshots, and periodic ps snapshots.

Event shape (one JSON object per line):
  {"ts":"...","sessionId":"...","container":"...","type":"exec|net|file|audit",
   "pid":...,"comm":"...","args":"...","peer":"...","path":"...","msg":"...",...}

Examples:
  coi audit                           # Auto-detect container, dump host-side log
  coi audit coi-abc-1                 # Specific container, dump host-side log
  coi audit coi-abc-1 --follow        # Live in-container collector, JSONL on stdout
  coi audit --file ./session.jsonl    # Read from an arbitrary JSONL file`,
	RunE: runAudit,
}

func runAudit(cmd *cobra.Command, args []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --file overrides every other source.
	if auditFile != "" {
		return audit.HostAuditTail(auditFile, auditFollow, "", "", os.Stdout)
	}

	containerName, err := app.resolveMonitorContainer(args)
	if err != nil {
		return err
	}

	if !auditFollow {
		return runAuditDump(containerName)
	}
	return runAuditFollow(ctx, containerName)
}

// runAuditDump prints the existing host-side audit log for a container.
func runAuditDump(containerName string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}
	path := filepath.Join(homeDir, ".coi", "audit", containerName+".jsonl")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("no audit log found for container %s (start a session with monitoring enabled, or use --follow for live in-container events)", containerName)
	}
	return audit.HostAuditTail(path, false, containerName, containerName, os.Stdout)
}

// runAuditFollow pushes the agent script into the container and streams its
// stdout, decorating each event with the container name as sessionId.
func runAuditFollow(ctx context.Context, containerName string) error {
	mgr := container.NewManager(containerName)
	running, err := mgr.Running()
	if err != nil {
		return fmt.Errorf("check container: %w", err)
	}
	if !running {
		return fmt.Errorf("container %s is not running; --follow needs a live container", containerName)
	}

	// Write the embedded agent to a tempfile, push it into the container,
	// then `incus exec` it. We push to /tmp because /var may be read-only
	// on some hardened profiles.
	localPath, err := audit.WriteAgentScriptTemp()
	if err != nil {
		return fmt.Errorf("stage agent: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(localPath))

	remotePath := "/tmp/coi-audit-collector.sh"
	if err := mgr.PushFile(localPath, remotePath); err != nil {
		return fmt.Errorf("push agent into container: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[audit] streaming from %s (Ctrl+C to stop)\n", containerName)

	// Build the incus exec command directly so we can pipe its stdout.
	// We deliberately don't use container.Manager.Exec — that drives stdout
	// to os.Stderr; we need a pipe.
	incusArgs := []string{"exec", containerName, "--", "sh", remotePath}
	cmd, stdout, err := newIncusPipedCommand(ctx, incusArgs)
	if err != nil {
		return fmt.Errorf("build agent command: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	// Heartbeat watcher: detect when the in-container agent goes silent
	// (e.g. an attacker inside the sandbox kills it). Stale transitions go
	// to stderr and are also injected into the stdout JSONL stream as a
	// type=audit msg=agent.stale event so downstream consumers see them.
	stdoutMu := &sync.Mutex{}
	stdoutEnc := json.NewEncoder(os.Stdout)
	stdoutEnc.SetEscapeHTML(false)
	emitStatus := func(sessionID string, status audit.WatcherStatus, lastSeen time.Time) {
		gap := time.Since(lastSeen).Round(time.Second)
		switch status {
		case audit.StatusStale:
			fmt.Fprintf(os.Stderr,
				"[audit] WARNING agent silent on %s for %s (last heartbeat %s)\n",
				sessionID, gap, lastSeen.UTC().Format(time.RFC3339),
			)
		case audit.StatusAlive:
			fmt.Fprintf(os.Stderr,
				"[audit] agent recovered on %s after %s of silence\n",
				sessionID, gap,
			)
		case audit.StatusFirstSeen:
			// First heartbeat is informational only — quiet by default.
			return
		}
		stdoutMu.Lock()
		_ = stdoutEnc.Encode(audit.Event{
			TS:        time.Now().UTC().Format(time.RFC3339Nano),
			SessionID: sessionID,
			Container: containerName,
			Type:      audit.TypeAudit,
			Msg:       "agent." + status.String(),
			Raw:       fmt.Sprintf("gap=%s lastHeartbeat=%s", gap, lastSeen.UTC().Format(time.RFC3339)),
		})
		stdoutMu.Unlock()
	}
	watcher := audit.NewHeartbeatWatcher(emitStatus, audit.DefaultStaleAfter, audit.DefaultCheckInterval)
	watcherCtx, watcherCancel := context.WithCancel(ctx)
	defer watcherCancel()
	go watcher.Run(watcherCtx)

	collector := &audit.Collector{
		SessionID: containerName,
		Container: containerName,
		Out:       newSerializingWriter(os.Stdout, stdoutMu),
		Watcher:   watcher,
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "[audit] parse: %v\n", err)
		},
	}
	streamErr := collector.Run(ctx, stdout)

	// Wait for the agent to exit cleanly.
	_ = cmd.Wait()

	if ctx.Err() != nil {
		return nil
	}
	return streamErr
}

// serializingWriter serialises writes to an underlying writer behind a mutex
// so the collector's per-event JSON encoder and the watcher's stale-event
// injector don't interleave bytes in the stdout JSONL stream.
type serializingWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func newSerializingWriter(w io.Writer, mu *sync.Mutex) *serializingWriter {
	return &serializingWriter{w: w, mu: mu}
}

func (s *serializingWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// newIncusPipedCommand returns an exec.Cmd ready to run an incus subcommand
// with its stdout piped back to the caller. The incus binary is invoked
// directly with an argv (no intermediate shell), mirroring the direct
// invocation path in internal/container/commands.go.
func newIncusPipedCommand(ctx context.Context, args []string) (*exec.Cmd, io.ReadCloser, error) {
	incusArgs := append([]string{"--project", container.IncusProject}, args...)

	cmd := exec.CommandContext(ctx, "incus", incusArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	return cmd, stdout, nil
}
