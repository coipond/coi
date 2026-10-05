package network

import (
	"log"
	"sync/atomic"

	"github.com/coipond/coi/internal/logger"
)

// pkgLogger optionally redirects this package's diagnostic output to a
// file-based session logger. When unset (the default), output falls back to the
// standard log package (stderr), preserving behaviour for non-session callers
// (e.g. coi run, early boot). A coi shell session sets it so the background IP
// refresh and nft-rule diagnostics go to ~/.coi/logs/<container>.{stdout,stderr}.log
// instead of the user's tmux terminal — issue #372.
var pkgLogger atomic.Pointer[logger.SessionLogger]

// SetLogger routes network-package diagnostics to l (a file-based SessionLogger).
// Pass nil to restore the default standard-logger (stderr) behaviour. Safe for
// concurrent use with the background refresher goroutine.
func SetLogger(l *logger.SessionLogger) {
	pkgLogger.Store(l)
}

// Warnf routes a warning through the active session logger (or the standard
// logger as a fallback) for callers outside this package that must not write
// network diagnostics directly to the terminal — issue #372.
func Warnf(format string, args ...any) { logWarnf(format, args...) }

// logInfof writes an informational message to the session stdout log when a
// session logger is set, otherwise to the standard logger (stderr).
func logInfof(format string, args ...any) {
	if l := pkgLogger.Load(); l != nil {
		l.Printf(format, args...)
		return
	}
	log.Printf(format, args...) // terminal-sink-ok: fallback only when no session logger is set (pre-attach/non-session use)
}

// logWarnf writes a warning/error message to the session stderr log when a
// session logger is set, otherwise to the standard logger (stderr).
func logWarnf(format string, args ...any) {
	if l := pkgLogger.Load(); l != nil {
		l.Errorf(format, args...)
		return
	}
	log.Printf(format, args...) // terminal-sink-ok: fallback only when no session logger is set (pre-attach/non-session use)
}
