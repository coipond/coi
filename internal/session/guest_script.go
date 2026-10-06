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

// renderGuestScript renders ops as one fail-fast shell script. File content is
// base64-encoded so arbitrary bytes (quotes, newlines, config-sourced strings)
// can never break out of the script. Each file is written to a sibling temp
// path, owned and chmod-ed, then renamed over the target: rename replaces a
// symlink at the target instead of following it, and readers never see a
// half-written file.
func renderGuestScript(ops []guestOp) string {
	// `set -e` alone is not enough: bash ignores a failure inside an `a && b`
	// list unless it is the last command, so every op also ends in
	// `|| exit 1` — a failed step must stop the script, never be masked by a
	// later step that succeeds.
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, op := range ops {
		if op.write == nil {
			fmt.Fprintf(&b, "{ %s; } || exit 1\n", op.cmd)
			continue
		}
		w := op.write
		dst := shellEscape(w.path)
		tmp := shellEscape(w.path + ".coi-new")
		fmt.Fprintf(&b, "{ rm -f %s && printf '%%s' '%s' | base64 -d > %s && chown %d:%d %s && chmod %s %s && mv -f %s %s; } || exit 1\n",
			tmp, base64.StdEncoding.EncodeToString([]byte(w.content)), tmp,
			w.uid, w.gid, tmp, shellEscape(w.mode), tmp, tmp, dst)
	}
	return b.String()
}

// runGuestOps runs ops in the container in one exec (as root unless opts says
// otherwise). A batch too large for one argv element falls back to one call
// per op, preserving the old behavior.
func runGuestOps(mgr container.ContainerManager, ops []guestOp, opts container.ExecCommandOptions) error {
	_, err := runGuestOpsOutput(mgr, ops, opts)
	return err
}

// runGuestOpsOutput is runGuestOps that also returns the commands' combined
// stdout, for ops that report what they did.
func runGuestOpsOutput(mgr container.ContainerManager, ops []guestOp, opts container.ExecCommandOptions) (string, error) {
	opts.Capture = true
	if script := renderGuestScript(ops); len(script) <= maxGuestScriptBytes {
		return mgr.ExecCommand(script, opts)
	}
	var out strings.Builder
	for _, op := range ops {
		if op.write != nil {
			w := op.write
			if err := mgr.CreateFileWithOwner(w.path, w.content, w.uid, w.gid, w.mode); err != nil {
				return out.String(), fmt.Errorf("failed to write %s: %w", w.path, err)
			}
			continue
		}
		o, err := mgr.ExecCommand(op.cmd, opts)
		out.WriteString(o)
		if err != nil {
			return out.String(), err
		}
	}
	return out.String(), nil
}
