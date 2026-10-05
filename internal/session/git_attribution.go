package session

import (
	"fmt"
	"strings"

	"github.com/coipond/coi/internal/container"
)

// AI coding agents auto-inject attribution into commit messages — a
// `Co-Authored-By: <tool bot>` trailer and/or a "Generated with …" footer —
// polluting authorship in the repos they work on (#788). Git has no setting
// that forbids a trailer, and per-tool opt-outs are easy to miss, so the
// tool-agnostic enforcement point is a global commit-msg hook: Coi writes a
// root-owned hook directory at /etc/coi/git-hooks inside the container and
// points core.hooksPath at it. The hook STRIPS matching lines (never rejects —
// a rejected commit would break autonomous sessions over a cosmetic issue) and
// then delegates to the repository's own hook so repo hooks keep working.
//
// Known limitations (documented, accepted):
//   - A repo whose LOCAL git config sets core.hooksPath (husky writes
//     `core.hooksPath = .husky` into .git/config, which Coi mounts read-only
//     from the host) overrides the global hooksPath — the strip does not run
//     in such repos.
//   - `git commit --no-verify` skips commit-msg hooks entirely.
//
// For Claude Code both gaps are additionally covered at the source by
// includeCoAuthoredBy=false in the managed-settings policy (setup_helpers.go).

// GitHooksDir is the root-owned in-container directory core.hooksPath points at.
const GitHooksDir = "/etc/coi/git-hooks"

// gitAttributionPatternsPath is the ERE pattern file the commit-msg hook feeds
// to `grep -Ev -f`; kept separate from the script so operators can inspect what
// is stripped without reading shell.
const gitAttributionPatternsPath = GitHooksDir + "/attribution-patterns"

// DefaultAttributionPatterns are the grep -E line patterns stripped by default:
// co-author trailers naming known AI tools or bot-style identities, and
// tool-generated "Generated with/by" footers. Overridden wholesale by
// [git] strip_attribution_patterns.
var DefaultAttributionPatterns = []string{
	`^[[:space:]]*Co-[Aa]uthored-[Bb]y:.*(noreply|no-reply|\[bot\]|[Cc]laude|[Cc]odex|[Cc]opilot|[Gg]emini|[Aa]ider|[Cc]ursor)`,
	`^[[:space:]]*(🤖[[:space:]]*)?Generated (with|by) `,
	`^[[:space:]]*(🤖[[:space:]]*)?Assisted-[Bb]y:`,
}

// delegatedHookNames are the client-side hooks that get a pure-delegation
// wrapper: core.hooksPath REPLACES the repository hooks directory (git looks
// only there), so without these the repo's own hooks would silently stop
// running in-container. Deliberately excludes high-frequency plumbing hooks
// (reference-transaction, post-index-change) — a fork+exec on every ref update
// is not worth delegating hooks repos rarely use.
// post-commit, pre-commit, pre-merge-commit and pre-push are intentionally
// absent: SetupGitHooks handles each explicitly (a root-owned enforcement
// script — identity re-stamp or branch guard — when active, a plain delegation
// symlink otherwise), so they must not be blanket-symlinked here.
// pre-merge-commit rides with pre-commit because a non-fast-forward `git merge`
// creates a commit WITHOUT firing pre-commit — only pre-merge-commit runs — so
// guarding pre-commit alone would let `git merge` land on a protected branch.
var delegatedHookNames = []string{
	"applypatch-msg", "pre-applypatch", "post-applypatch",
	"prepare-commit-msg",
	"pre-rebase", "post-checkout", "post-merge",
	"post-rewrite", "pre-auto-gc",
}

// gitDelegateHookScript forwards to the repository's own hook of the same
// name, preserving arguments and exit code. `git rev-parse --git-common-dir`
// is used (NOT --git-path hooks, which would resolve back to core.hooksPath —
// i.e. this directory — and recurse). --git-common-dir, not --git-dir: in a
// linked worktree --git-dir is .git/worktrees/<name>, which has no hooks/, so
// the repository's hooks would silently never run.
const gitDelegateHookScript = `#!/bin/sh
# Managed by coi: core.hooksPath points at this directory, which would
# otherwise hide the repository's own hooks — forward to them.
hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/$(basename "$0")"
if [ -x "$hook" ]; then
	exec "$hook" "$@"
fi
exit 0
`

// gitCommitMsgHookScript strips attribution lines from the commit message,
// then delegates to the repository's own commit-msg hook. Strip-don't-reject:
// every failure path keeps the original message and exits 0.
const gitCommitMsgHookScript = `#!/bin/sh
# Managed by coi ([git] strip_attribution): removes auto-injected AI
# attribution trailers/footers from every commit message, then runs the
# repository's own commit-msg hook. Never blocks a commit.
msg="$1"
patterns="` + gitAttributionPatternsPath + `"
if [ -f "$msg" ] && [ -s "$patterns" ]; then
	tmp="$msg.coi-strip"
	# grep -v exits 1 when NO line survives (message was attribution-only);
	# keep the original in that case rather than committing an empty message.
	if grep -Ev -f "$patterns" "$msg" > "$tmp" 2>/dev/null; then
		# Drop the trailing blank lines left where trailers were removed.
		awk 'NF{last=NR} {line[NR]=$0} END{for(i=1;i<=last;i++) print line[i]}' "$tmp" > "$msg" || :
	fi
	rm -f "$tmp"
fi
hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/commit-msg"
if [ -x "$hook" ]; then
	exec "$hook" "$@"
fi
exit 0
`

// gitPostCommitRestampHead is the top of the identity re-stamp post-commit hook:
// the recursion/single-delegate guard and the git-dir lookup. The LOCK_NAME /
// LOCK_EMAIL assignments (baked from the resolved identity) and
// gitPostCommitRestampBody are appended by renderPostCommitRestampScript.
const gitPostCommitRestampHead = `#!/bin/sh
# Managed by coi ([git] readonly identity lock): if a commit was authored or
# committed as anyone other than the locked identity (via -c user.*, --author=,
# or GIT_AUTHOR_* the agent exported), re-stamp HEAD to the locked identity,
# then run the repository's own post-commit. Never blocks (git ignores the
# post-commit exit status).
#
# The --amend below re-fires post-commit; COI_RESTAMP_ACTIVE makes that nested
# run a no-op (no amend, no delegate) so the repo hook runs EXACTLY ONCE, from
# this outer run, on the corrected commit.
[ -n "$COI_RESTAMP_ACTIVE" ] && exit 0
gitdir="$(git rev-parse --git-dir 2>/dev/null)" || exit 0
`

// gitPostCommitRestampBody is the tail: the single-delegate helper, the
// mid-sequence skip, and the amend. %ae/%ce are literal git format specifiers
// (this is a plain string, never a printf format). git rev-parse --git-dir is
// used (NOT --git-path hooks, which resolves back to this dir and recurses).
const gitPostCommitRestampBody = `
delegate() {
	# Hooks live in the COMMON dir (a linked worktree's $gitdir has none);
	# $gitdir stays per-worktree for the CHERRY_PICK_HEAD-style state checks.
	hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/post-commit"
	[ -x "$hook" ] && "$hook" "$@"
	exit 0
}
# Never amend mid-sequence — git drives these itself and an amend corrupts state.
for m in rebase-merge rebase-apply MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD BISECT_LOG sequencer; do
	[ -e "$gitdir/$m" ] && delegate "$@"
done
an="$(git log -1 --format='%an' 2>/dev/null)" || delegate "$@"
ae="$(git log -1 --format='%ae' 2>/dev/null)"
cn="$(git log -1 --format='%cn' 2>/dev/null)"
ce="$(git log -1 --format='%ce' 2>/dev/null)"
# Compare NAME and EMAIL of both author and committer: an override that keeps the
# locked email but changes the name (e.g. --author="Evil <locked-email>") must
# still be re-stamped.
if [ "$an" != "$LOCK_NAME" ] || [ "$ae" != "$LOCK_EMAIL" ] || [ "$cn" != "$LOCK_NAME" ] || [ "$ce" != "$LOCK_EMAIL" ]; then
	COI_RESTAMP_ACTIVE=1 \
	GIT_AUTHOR_NAME="$LOCK_NAME" GIT_AUTHOR_EMAIL="$LOCK_EMAIL" \
	GIT_COMMITTER_NAME="$LOCK_NAME" GIT_COMMITTER_EMAIL="$LOCK_EMAIL" \
	git commit --amend --reset-author --no-edit --no-verify --allow-empty >/dev/null 2>&1
fi
delegate "$@"
`

// renderPostCommitRestampScript bakes the resolved identity into the re-stamp
// hook (single source of truth — no hardcoded copy). shellEscape single-quotes
// the values, so the assignments are injection-safe.
func renderPostCommitRestampScript(id GitIdentity) string {
	return gitPostCommitRestampHead +
		"LOCK_NAME=" + shellEscape(strings.TrimSpace(id.Name)) + "\n" +
		"LOCK_EMAIL=" + shellEscape(strings.TrimSpace(id.Email)) + "\n" +
		gitPostCommitRestampBody
}

// Branch guard ([git] protected_branches): root-owned pre-commit and pre-push
// hooks that REJECT (never strip) a commit on, or a push to, a protected branch,
// then delegate to the repository's own hook of the same name. Reject-don't-strip
// is deliberate here — blocking the protected-branch write is the whole point,
// unlike the cosmetic attribution strip. Accepted bypasses (same as every client
// hook): `--no-verify` skips the hook, and a repo-local core.hooksPath (husky)
// overrides the global one; server-side branch protection is the real backstop.

const gitPreCommitGuardHead = `#!/bin/sh
# Managed by coi ([git] protected_branches): refuse a commit while HEAD is on a
# protected branch, then run the repository's own hook of the same name.
# Strip refs/heads/ ourselves: --short disambiguates, so a tag named like the
# branch (git tag main) makes it print "heads/main" and slip past the check.
ref="$(git symbolic-ref -q HEAD 2>/dev/null)"
branch="${ref#refs/heads/}"
# The first commit of a new repository has nothing to protect yet (and no
# feature branch to fork from) — let it through.
git rev-parse -q --verify HEAD >/dev/null 2>&1 || branch=""
`

const gitPrePushGuardHead = `#!/bin/sh
# Managed by coi ([git] protected_branches): refuse a push whose destination is a
# protected branch, then run the repository's own pre-push hook. Git feeds the
# pushed refs on stdin as "<local ref> <local sha> <remote ref> <remote sha>".
input="$(cat)"
while read -r lref lsha rref rsha; do
	case "$rref" in
		refs/heads/*) rb=${rref#refs/heads/} ;;
		*) continue ;;
	esac
`

// gitPrePushGuardTail closes the read loop with a here-doc (NOT a pipe: a piped
// `while` runs in a subshell whose `exit 1` cannot fail the hook), then delegates
// with the buffered refs replayed on the repo hook's stdin.
const gitPrePushGuardTail = `done <<COI_PROTECTED_REFS
$input
COI_PROTECTED_REFS
hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/pre-push"
if [ -x "$hook" ]; then
	# Replay the buffered refs faithfully: an empty $input means git sent no ref
	# lines, so feed the delegate empty stdin rather than a spurious blank line.
	if [ -n "$input" ]; then
		printf '%s\n' "$input" | "$hook" "$@"
	else
		"$hook" "$@" < /dev/null
	fi
	exit $?
fi
exit 0
`

// gitRefTxGuardHead opens the reference-transaction guard. Git runs this hook
// for EVERY ref update — commit, cherry-pick, revert, am, fast-forward merge,
// rebase, reset, update-ref, branch -f — and a non-zero exit in the
// "prepared" state aborts the update. That closes the paths pre-commit never
// sees. The rule: a protected branch may only point at commits some remote
// already has, so `git pull` and `reset --hard origin/main` keep working while
// any local-only commit on it is refused — including by deleting and
// recreating it (checkout -B / switch -C too). Deletion is allowed (pre-push
// still blocks pushing one), as is creating it in a repository with no
// remote-tracking refs (git init; the first commit). Bare repositories (push
// targets) are skipped.
//
// Refused although legitimate, because git moves the branch BEFORE the
// remote-tracking ref (two transactions), so the hook can't tell it from a
// local fast-forward: `git fetch origin main:main` and `git pull <url> main`.
// The rejection message names the working alternative
// (`git fetch origin && git branch -f main origin/main`).
//
// Not caught (pre-push still blocks the push). This hook is a guard-rail
// against ACCIDENTAL commits on a protected branch, not a boundary against a
// deliberate workaround; pre-push and server-side branch protection are the
// enforcement. Known deliberate workarounds: `git branch -M/-C x main` and
// `git symbolic-ref` (git 2.43 doesn't run reference-transaction for them),
// writing a local commit under refs/remotes/* first
// (`git fetch . feat:refs/remotes/x/feat`), and `git remote remove` followed
// by recreating the branch. Closing each would add false blocks for ordinary
// work (e.g. `git init -b dev`, commits, then `git checkout -b main`).
// Needs git >= 2.28; older git ignores the hook (pre-commit still applies).
const gitRefTxGuardHead = `#!/bin/sh
# Managed by coi ([git] protected_branches): refuse to move a protected branch
# to a commit no remote has, then run the repository's own hook of this name.
# Git feeds "<old> <new> <ref>" lines on stdin; $1 is the transaction state.
input="$(cat)"
# Bare repositories are push targets (the receiving side of a local push, e.g.
# a test fixture); the pushing client's pre-push hook is what guards those.
if [ "$1" = "prepared" ] && [ "$(git rev-parse --is-bare-repository 2>/dev/null)" != "true" ]; then
while read -r old new ref; do
	case "$ref" in
		refs/heads/*) b=${ref#refs/heads/} ;;
		*) continue ;;
	esac
	protected=""
`

// gitRefTxGuardTail closes the loop (here-doc, not a pipe — see
// gitPrePushGuardTail) and delegates with the buffered lines replayed.
const gitRefTxGuardTail = `	[ -n "$protected" ] || continue
	[ "$old" = "$new" ] && continue
	case "$new" in *[!0]*) ;; *) continue ;; esac # deletion
	# A remote already has it (pull, reset to upstream) iff nothing reachable
	# from $new is missing from every remote-tracking ref. rev-list walks only
	# the commits it needs; for-each-ref --contains checked each ref separately
	# and took ~1 min per update with thousands of remote branches. Fail
	# CLOSED: if rev-list errors (e.g. a broken remote-tracking ref), its
	# empty output must not read as "a remote has it".
	if missing="$(git rev-list -n1 "$new" --not --remotes 2>/dev/null)" && [ -z "$missing" ]; then
		continue
	fi
	# (Re)creating the branch must also point at a commit a remote has —
	# otherwise delete+recreate or checkout -B would sidestep the guard —
	# except in a repository with no remote-tracking refs at all (git init,
	# commits, then creating main), where there is nothing to compare against.
	# Ask the ref store, not $old: git also sends an all-zero <old> when the
	# caller didn't give one (update-ref, branch -f).
	if ! git rev-parse -q --verify "$ref" >/dev/null 2>&1 &&
		[ -z "$(git for-each-ref --count=1 refs/remotes 2>/dev/null)" ]; then
		continue
	fi
	echo "coi: refusing to move protected branch '$b' to a local-only commit (git.protected_branches)." >&2
	echo "     Work on a feature branch first: git switch -c <name>" >&2
	echo "     To sync it with its remote instead: git fetch <remote> && git branch -f $b <remote>/$b" >&2
	exit 1
done <<COI_REF_UPDATES
$input
COI_REF_UPDATES
fi
hook="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/reference-transaction"
if [ -x "$hook" ]; then
	if [ -n "$input" ]; then
		printf '%s\n' "$input" | "$hook" "$@"
	else
		"$hook" "$@" < /dev/null
	fi
	exit $?
fi
exit 0
`

// branchGuardHooks are the hook names that get a commit-style branch guard: both
// refuse a commit while HEAD is on a protected branch. pre-merge-commit is
// included because a non-fast-forward `git merge` commits WITHOUT firing
// pre-commit (only pre-merge-commit runs), so guarding pre-commit alone would let
// a merge land on a protected branch. pre-push is guarded separately (it inspects
// the pushed refs on stdin, not HEAD).
// reference-transaction catches every other way to move a protected branch
// (cherry-pick, revert, am, fast-forward merge, rebase, reset); it is only
// installed while the guard is on — see refTxHook.
var branchGuardHooks = []string{"pre-commit", "pre-merge-commit", "pre-push", refTxHook}

// refTxHook is high-frequency plumbing (it runs on every ref update, fetches
// included), so unlike the other guard hooks it is NOT replaced by a
// delegation symlink when the guard is off — see delegatedHookNames.
const refTxHook = "reference-transaction"

// renderBranchGuardScript bakes the protected-branch checks into a guard hook.
// Each branch becomes its own string-equality `if` (NOT a `case` glob or a
// shared list) so a name containing a shell/glob metacharacter can neither be
// mis-matched nor injected — shellEscape single-quotes every value. kind is one
// of branchGuardHooks; every kind delegates to the repo's own hook of that name.
func renderBranchGuardScript(kind string, branches []string) string {
	var b strings.Builder
	switch kind {
	case refTxHook:
		b.WriteString(gitRefTxGuardHead)
		for _, br := range branches {
			b.WriteString("\tif [ \"$b\" = " + shellEscape(br) + " ]; then protected=1; fi\n")
		}
		b.WriteString(gitRefTxGuardTail)
	case "pre-push":
		b.WriteString(gitPrePushGuardHead)
		for _, br := range branches {
			b.WriteString("\tif [ \"$rb\" = " + shellEscape(br) + " ]; then\n")
			b.WriteString("\t\techo \"coi: refusing to push to protected branch '$rb' (git.protected_branches).\" >&2\n")
			b.WriteString("\t\texit 1\n\tfi\n")
		}
		b.WriteString(gitPrePushGuardTail)
	default: // pre-commit / pre-merge-commit (both guard on HEAD's branch)
		b.WriteString(gitPreCommitGuardHead)
		for _, br := range branches {
			b.WriteString("if [ \"$branch\" = " + shellEscape(br) + " ]; then\n")
			b.WriteString("\techo \"coi: refusing to commit on protected branch '$branch' (git.protected_branches).\" >&2\n")
			b.WriteString("\techo \"     Work on a feature branch first: git switch -c <name>\" >&2\n")
			b.WriteString("\texit 1\nfi\n")
		}
		// Delegate to the repo's own hook of the SAME name (pre-commit or
		// pre-merge-commit), not a fixed one.
		b.WriteString("hook=\"$(git rev-parse --git-common-dir 2>/dev/null)/hooks/" + kind + "\"\n")
		b.WriteString("[ -x \"$hook\" ] && exec \"$hook\" \"$@\"\nexit 0\n")
	}
	return b.String()
}

// renderAttributionPatternsFile joins the pattern list into the grep -f file
// content. Blank/whitespace-only entries are dropped: an empty pattern line
// matches EVERY line, which with grep -v would delete the whole message.
func renderAttributionPatternsFile(patterns []string) string {
	var b strings.Builder
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		b.WriteString(p)
		b.WriteString("\n")
	}
	return b.String()
}

// effectiveAttributionPatterns resolves the pattern list: config override when
// non-empty, built-in defaults otherwise.
func effectiveAttributionPatterns(configured []string) []string {
	if len(configured) > 0 {
		return configured
	}
	return DefaultAttributionPatterns
}

// SetupGitHooks installs Coi's root-owned global git hooks inside the container
// and (for a writable global gitconfig) points core.hooksPath at them. Two
// independent policies share the one hook directory, because core.hooksPath can
// point at only one place:
//   - stripAttribution: the commit-msg strip hook (#788) + its pattern file.
//   - lockIdentity: a post-commit re-stamp hook baked with `id` that rewrites any
//     commit whose author/committer isn't the locked identity — the enforcement
//     that makes -c user.*, --author=, and agent GIT_* overrides lose.
//
// A third policy, the branch guard ([git] protected_branches), rides the same
// hook dir: when protectedBranches is non-empty, root-owned pre-commit/pre-push
// scripts reject commits on / pushes to those branches (else a plain delegation
// symlink). The guard installs independently of the two identity policies, so a
// session with only protected_branches set still gets hooks + core.hooksPath.
//
// The delegation wrappers (so a repo's own hooks keep running under the replaced
// hooks dir) are always installed. With [git] readonly the caller bakes
// core.hooksPath into the mounted gitconfig (renderReadonlyGitConfig) and passes
// setHooksPath=false. Root ownership (uid/gid 0) keeps the sandboxed non-root
// agent from editing its own policy. Non-fatal: logs a warning on failure and
// never blocks a session.
func SetupGitHooks(mgr container.ContainerManager, homeDir string, id GitIdentity, stripAttribution bool, patterns []string, lockIdentity, setHooksPath bool, protectedBranches []string, logger func(string)) {
	files := []struct {
		path, content, mode string
	}{
		{GitHooksDir + "/delegate", gitDelegateHookScript, "0755"},
	}
	if stripAttribution {
		files = append(files,
			struct{ path, content, mode string }{GitHooksDir + "/commit-msg", gitCommitMsgHookScript, "0755"},
			struct{ path, content, mode string }{gitAttributionPatternsPath, renderAttributionPatternsFile(effectiveAttributionPatterns(patterns)), "0644"},
		)
	}
	if _, err := mgr.ExecCommand("mkdir -p "+GitHooksDir, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: failed to create %s: %v", GitHooksDir, err))
		return
	}
	for _, f := range files {
		if err := mgr.CreateFileWithOwner(f.path, f.content, 0, 0, f.mode); err != nil {
			logger(fmt.Sprintf("Warning: failed to write %s: %v", f.path, err))
			return
		}
	}
	// Delegation wrappers as symlinks to the single delegate script (ln -sf is
	// idempotent for persistent reuse).
	var links strings.Builder
	for _, name := range delegatedHookNames {
		fmt.Fprintf(&links, "ln -sf delegate %s/%s && ", GitHooksDir, name)
	}
	if _, err := mgr.ExecCommand(links.String()+"true", container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: failed to link delegation hooks: %v", err))
		return
	}
	// post-commit: a real re-stamp file when locking, else a delegation symlink.
	// Remove any prior form first so CreateFileWithOwner can't follow an existing
	// symlink and clobber the delegate script, and so a lock->unlock switch on a
	// reused container converges.
	postCommit := GitHooksDir + "/post-commit"
	if _, err := mgr.ExecCommand("rm -f "+postCommit, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: failed to reset %s: %v", postCommit, err))
		return
	}
	if lockIdentity {
		if err := mgr.CreateFileWithOwner(postCommit, renderPostCommitRestampScript(id), 0, 0, "0755"); err != nil {
			logger(fmt.Sprintf("Warning: failed to write %s: %v", postCommit, err))
			return
		}
	} else if _, err := mgr.ExecCommand("ln -sf delegate "+postCommit, container.ExecCommandOptions{Capture: true}); err != nil {
		logger(fmt.Sprintf("Warning: failed to link post-commit delegation hook: %v", err))
		return
	}
	// Branch-guard hooks (pre-commit / pre-merge-commit / pre-push): a real guard
	// script when protectedBranches is non-empty, else a delegation symlink (like
	// post-commit above). rm -f first so CreateFileWithOwner can't follow a stale
	// symlink and a guard->off switch on a reused container converges.
	guardOn := len(protectedBranches) > 0
	for _, name := range branchGuardHooks {
		hookPath := GitHooksDir + "/" + name
		if _, err := mgr.ExecCommand("rm -f "+hookPath, container.ExecCommandOptions{Capture: true}); err != nil {
			logger(fmt.Sprintf("Warning: failed to reset %s: %v", hookPath, err))
			return
		}
		if guardOn {
			if err := mgr.CreateFileWithOwner(hookPath, renderBranchGuardScript(name, protectedBranches), 0, 0, "0755"); err != nil {
				logger(fmt.Sprintf("Warning: failed to write %s: %v", hookPath, err))
				return
			}
		} else if name == refTxHook {
			continue // removed above; never delegated (high-frequency hook)
		} else if _, err := mgr.ExecCommand("ln -sf delegate "+hookPath, container.ExecCommandOptions{Capture: true}); err != nil {
			logger(fmt.Sprintf("Warning: failed to link %s delegation hook: %v", name, err))
			return
		}
	}
	if setHooksPath {
		cmd := fmt.Sprintf(`HOME=%s git config --global core.hooksPath %s`,
			shellEscape(homeDir), shellEscape(GitHooksDir))
		if _, err := mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true}); err != nil {
			logger(fmt.Sprintf("Warning: failed to set core.hooksPath: %v", err))
			return
		}
	}
	switch {
	case stripAttribution && lockIdentity:
		logger("Installed git hooks: AI-attribution strip + commit-identity re-stamp (identity locked)")
	case lockIdentity:
		logger("Installed git commit-identity re-stamp hook (identity locked; overrides cannot change the author)")
	case stripAttribution:
		logger("Installed AI-attribution strip hook (git commit messages keep only the configured author)")
	}
	if guardOn {
		logger("Installed git branch guard (protected: " + strings.Join(protectedBranches, ", ") + ") — no direct commits/pushes to these branches")
	}
}

// RemoveGitAttributionHookConfig best-effort unsets core.hooksPath so a
// persistent container reused after [git] strip_attribution was turned off
// converges instead of keeping the hook active. The hook directory itself is
// left in place (inert without the config).
func RemoveGitAttributionHookConfig(mgr container.ContainerExecution, homeDir string) {
	cmd := fmt.Sprintf(`HOME=%s git config --global --unset core.hooksPath 2>/dev/null || true`,
		shellEscape(homeDir))
	_, _ = mgr.ExecCommand(cmd, container.ExecCommandOptions{Capture: true})
}
