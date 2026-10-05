package session

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// guestOp is one step of a batched in-container setup: either a shell command
// or a file write. Setup steps that used to issue one incus round trip per
// file and per command (each ~50-150 ms) render to a single script and run in
// ONE `incus exec` instead.
type guestOp struct {
	cmd   string      // shell command, run as-is
	write *guestWrite // or: write this file
}

// guestWrite is a file to place in the container with an exact owner and mode.
type guestWrite struct {
	path, content, mode string
	uid, gid            int
}

func guestCmd(cmd string) guestOp { return guestOp{cmd: cmd} }

func guestFile(path, content string, uid, gid int, mode string) guestOp {
	return guestOp{write: &guestWrite{path: path, content: content, uid: uid, gid: gid, mode: mode}}
}

// maxGuestScriptBytes keeps a rendered script under Linux's per-argument limit
// (MAX_ARG_STRLEN, 128 KiB) with headroom: the script travels as one argv
// element of `bash -c`. Bigger batches fall back to one call per op.
const maxGuestScriptBytes = 96 * 1024

// renderGuestScript renders ops as one `set -e` shell script. File content is
// base64-encoded so arbitrary bytes (quotes, newlines, config-sourced strings)
// can never break out of the script. Each file is written to a sibling temp
// path, owned and chmod-ed, then renamed over the target: rename replaces a
// symlink at the target instead of following it, and readers never see a
// half-written file.
func renderGuestScript(ops []guestOp) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, op := range ops {
		if op.write == nil {
			b.WriteString(op.cmd)
			b.WriteByte('\n')
			continue
		}
		w := op.write
		dst := shellEscape(w.path)
		tmp := shellEscape(w.path + ".coi-new")
		fmt.Fprintf(&b, "rm -f %s && printf '%%s' '%s' | base64 -d > %s && chown %d:%d %s && chmod %s %s && mv -f %s %s\n",
			tmp, base64.StdEncoding.EncodeToString([]byte(w.content)), tmp,
			w.uid, w.gid, tmp, shellEscape(w.mode), tmp, tmp, dst)
	}
	return b.String()
}

// runGuestOps runs ops in the container in one exec (as root unless opts says
// otherwise). A batch too large for one argv element falls back to one call
// per op, preserving the old behavior.
func runGuestOps(mgr container.ContainerManager, ops []guestOp, opts container.ExecCommandOptions) error {
	opts.Capture = true
	if script := renderGuestScript(ops); len(script) <= maxGuestScriptBytes {
		_, err := mgr.ExecCommand(script, opts)
		return err
	}
	for _, op := range ops {
		if op.write != nil {
			w := op.write
			if err := mgr.CreateFileWithOwner(w.path, w.content, w.uid, w.gid, w.mode); err != nil {
				return fmt.Errorf("failed to write %s: %w", w.path, err)
			}
			continue
		}
		if _, err := mgr.ExecCommand(op.cmd, opts); err != nil {
			return err
		}
	}
	return nil
}
