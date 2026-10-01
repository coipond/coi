package nftmonitor

import (
	"sync/atomic"

	"github.com/coipond/coi/internal/logger"
)

// pkgLogger optionally routes this package's debug diagnostics (COI_NFT_DEBUG)
// to a file-based session logger. When unset (the default), debug output falls
// back to stderr — fine for standalone/CLI use. During a `coi shell` session the
// caller sets it so debug output goes to ~/.coi/logs/<container>.stdout.log
// instead of the user's attached tmux terminal — issue #372 class.
//
// This file has no build constraint so SetLogger is callable on every platform
// (the debugf consumer is Linux-only); mirrors internal/network/netlog.go.
var pkgLogger atomic.Pointer[logger.SessionLogger]

// SetLogger routes nftmonitor debug diagnostics to l (a file-based
// SessionLogger). Pass nil to restore the stderr fallback. Safe for concurrent
// use with the daemon goroutines.
func SetLogger(l *logger.SessionLogger) {
	pkgLogger.Store(l)
}
