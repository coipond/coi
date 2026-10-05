// Package logger provides per-session loggers that write to log files
// under ~/.coi/logs/.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// SessionLogger writes informational output to <container>.stdout.log and
// warnings/errors to <container>.stderr.log under ~/.coi/logs/.
// All methods are safe for concurrent use.
type SessionLogger struct {
	outMu       sync.Mutex
	errMu       sync.Mutex
	outFile     *os.File
	errFile     *os.File
	out         *log.Logger
	err         *log.Logger
	outPath     string
	errPath     string
	initWarning string // non-empty when New fell back to discard
}

// New creates both log files under homeDir/.coi/logs/.
// On any error a discard logger is returned with InitWarning() set; nothing is written to stderr.
// New never returns nil.
func New(containerName, homeDir string) *SessionLogger {
	if homeDir == "" {
		l := newDiscard()
		l.initWarning = "cannot determine home directory; session output will be suppressed"
		return l
	}

	logDir := filepath.Join(homeDir, ".coi", "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		l := newDiscard()
		l.initWarning = fmt.Sprintf("cannot create session log dir, session output suppressed: %v", err)
		return l
	}

	outPath := filepath.Join(logDir, containerName+".stdout.log")
	errPath := filepath.Join(logDir, containerName+".stderr.log")

	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l := newDiscard()
		l.initWarning = fmt.Sprintf("cannot open session stdout log, output suppressed: %v", err)
		return l
	}

	errFile, err := os.OpenFile(errPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		_ = outFile.Close()
		l := newDiscard()
		l.initWarning = fmt.Sprintf("cannot open session stderr log, output suppressed: %v", err)
		return l
	}

	return &SessionLogger{
		outFile: outFile,
		errFile: errFile,
		out:     log.New(outFile, "", log.LstdFlags),
		err:     log.New(errFile, "", log.LstdFlags),
		outPath: outPath,
		errPath: errPath,
	}
}

// InitWarning returns a non-empty string if New fell back to a discard logger due to an
// initialization error. The caller can forward this via its own progress logger.
func (l *SessionLogger) InitWarning() string { return l.initWarning }

// NewDiscard returns a no-op logger that discards all output.
// Use in tests and non-session callers (coi run, configure).
func NewDiscard() *SessionLogger {
	return newDiscard()
}

func newDiscard() *SessionLogger {
	return &SessionLogger{
		out: log.New(io.Discard, "", 0),
		err: log.New(io.Discard, "", 0),
	}
}

// Printf writes an informational message to the stdout log.
func (l *SessionLogger) Printf(format string, args ...any) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	l.out.Printf(format, args...)
}

// Println writes an informational message to the stdout log.
func (l *SessionLogger) Println(v ...any) {
	l.outMu.Lock()
	defer l.outMu.Unlock()
	l.out.Println(v...)
}

// Errorf writes a warning or error message to the stderr log.
func (l *SessionLogger) Errorf(format string, args ...any) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	l.err.Printf(format, args...)
}

// Errorln writes a warning or error message to the stderr log.
func (l *SessionLogger) Errorln(v ...any) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	l.err.Println(v...)
}

// OutPath returns the absolute path of the stdout log file.
// Returns empty string for discard loggers.
func (l *SessionLogger) OutPath() string { return l.outPath }

// ErrPath returns the absolute path of the stderr log file.
// Returns empty string for discard loggers.
func (l *SessionLogger) ErrPath() string { return l.errPath }

// Close closes both underlying log files.
// Safe to call on a discard logger or multiple times.
func (l *SessionLogger) Close() error {
	l.outMu.Lock()
	l.errMu.Lock()
	defer l.outMu.Unlock()
	defer l.errMu.Unlock()

	var firstErr error
	if l.outFile != nil {
		if err := l.outFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		l.outFile = nil
	}
	if l.errFile != nil {
		if err := l.errFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		l.errFile = nil
	}

	// Repoint the loggers at io.Discard so any write that races Close (e.g. the
	// background IP-refresh goroutine still draining via a package logger that
	// outlives the session — issue #372) is silently discarded rather than
	// written to a now-closed fd. Done under both locks so it cannot race an
	// in-flight Printf/Errorf.
	l.out = log.New(io.Discard, "", 0)
	l.err = log.New(io.Discard, "", 0)
	return firstErr
}
