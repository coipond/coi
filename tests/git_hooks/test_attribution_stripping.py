"""
End-to-end tests for `[git] strip_attribution` (#788).

AI agents auto-inject attribution into commit messages (a `Co-Authored-By:
<tool bot>` trailer and/or a "Generated with ..." footer). COI installs a
global commit-msg hook (core.hooksPath -> /etc/coi/git-hooks, root-owned)
that strips those lines from every commit, regardless of which tool made it.

Covered:
1. Default-on: a commit made in-container loses the Claude-style trailer and
   footer; core.hooksPath points at the COI hook dir; the hook files are
   root-owned.
2. Delegation: a repo's own hooks (pre-commit, commit-msg) still run — the
   global hooksPath would otherwise silently disable them.
3. KNOWN LIMITATION (documented, accepted): a repo whose LOCAL git config
   sets core.hooksPath (husky-style) overrides the global hook, so the
   trailer survives there.
4. Opt-out: `strip_attribution = false` keeps the trailer and leaves
   core.hooksPath unset.
5. Custom patterns replace the defaults wholesale.
6. Claude source-level layer: managed-settings.json carries
   includeCoAuthoredBy=false.
"""

import subprocess

from support.helpers import extract_container_name, write_trusted_coi_config

BOT_NAME = "coi-test-bot"
BOT_EMAIL = "bot@coi.test"
HOME = "/home/code"

# Identity so commits pass the useConfigOnly guard; strip_attribution stays at
# its default (on) unless a test overrides it. protected_branches is disabled so
# the on-by-default branch guard doesn't block these commits on master (these
# tests exercise attribution stripping, not branch protection).
IDENTITY_TOML = f'[git]\nname = "{BOT_NAME}"\nemail = "{BOT_EMAIL}"\nprotected_branches = []\n'

TRAILER_MSG = (
    "'subject line\\n\\nbody text\\n\\n"
    "\\360\\237\\244\\226 Generated with [Claude Code](https://claude.com/claude-code)\\n\\n"
    "Co-Authored-By: Claude <noreply@anthropic.com>'"
)


def _start_background_shell(coi_binary, workspace_dir, env):
    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert result.returncode == 0, f"background shell should start. stderr: {result.stderr}"
    name = extract_container_name(result)
    assert name, f"could not find container name. stderr: {result.stderr}"
    return name


def _exec(coi_binary, name, script):
    """Run a shell snippet with the code user's HOME so global git config is
    the one COI configured. `export` (not a `HOME=x cmd` prefix) so the value
    survives across the script's `&&` chains — a prefix assignment only applies
    to the first command. Returns (exit code, combined output)."""
    result = subprocess.run(
        [coi_binary, "container", "exec", name, "--", "sh", "-c", f"export HOME={HOME}; {script}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode, (result.stdout + result.stderr)


def _make_repo_and_commit(coi_binary, name, repo, extra_setup=""):
    """Create a fresh repo at `repo` in-container and commit with the
    attribution trailer/footer message. Returns (rc, combined output)."""
    return _exec(
        coi_binary,
        name,
        f"mkdir -p {repo} && cd {repo} && git init -q . && {extra_setup} "
        f'git commit --allow-empty -m "$(printf {TRAILER_MSG})"',
    )


def _last_message(coi_binary, name, repo):
    rc, out = _exec(coi_binary, name, f"cd {repo} && git log -1 --format=%B")
    assert rc == 0, f"git log failed: {out}"
    return out


def test_strip_attribution_default_on(coi_binary, workspace_dir, cleanup_containers):
    """Default config: the trailer and footer are stripped from a commit made
    in-container; the subject/body survive; core.hooksPath is installed and
    the hook files are root-owned (the agent cannot rewrite its own policy)."""
    env = write_trusted_coi_config(IDENTITY_TOML)
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, "git config --global --get core.hooksPath")
    assert rc == 0 and "/etc/coi/git-hooks" in out, (
        f"core.hooksPath should point at the COI hook dir, got rc={rc}: {out}"
    )

    rc, out = _make_repo_and_commit(coi_binary, name, "/tmp/strip-repo")
    assert rc == 0, f"commit should succeed (strip, don't reject): {out}"

    msg = _last_message(coi_binary, name, "/tmp/strip-repo")
    assert "subject line" in msg and "body text" in msg, f"real content must survive: {msg}"
    assert "Co-Authored-By" not in msg, f"co-author trailer must be stripped: {msg}"
    assert "Generated with" not in msg, f"tool footer must be stripped: {msg}"

    rc, out = _exec(
        coi_binary,
        name,
        "stat -c %u:%g /etc/coi/git-hooks/commit-msg /etc/coi/git-hooks/attribution-patterns",
    )
    assert rc == 0 and out.count("0:0") == 2, f"hook files must be root-owned, got: {out}"


def test_repo_hooks_still_run_via_delegation(coi_binary, workspace_dir, cleanup_containers):
    """core.hooksPath REPLACES the repo hooks dir, so without delegation a
    repo's own pre-commit/commit-msg would silently stop running. Both must
    still fire — and the strip must still happen."""
    env = write_trusted_coi_config(IDENTITY_TOML)
    name = _start_background_shell(coi_binary, workspace_dir, env)

    setup = (
        "printf '#!/bin/sh\\ntouch .pre-commit-ran\\n' > .git/hooks/pre-commit && "
        "printf '#!/bin/sh\\ntouch .commit-msg-ran\\n' > .git/hooks/commit-msg && "
        "chmod +x .git/hooks/pre-commit .git/hooks/commit-msg && "
    )
    rc, out = _make_repo_and_commit(coi_binary, name, "/tmp/delegate-repo", extra_setup=setup)
    assert rc == 0, f"commit should succeed: {out}"

    rc, out = _exec(coi_binary, name, "cd /tmp/delegate-repo && ls .pre-commit-ran .commit-msg-ran")
    assert rc == 0, f"the repo's own hooks must run via delegation, got: {out}"

    msg = _last_message(coi_binary, name, "/tmp/delegate-repo")
    assert "Co-Authored-By" not in msg, f"strip must still apply with repo hooks present: {msg}"


def test_husky_local_hookspath_is_a_known_hole(coi_binary, workspace_dir, cleanup_containers):
    """DOCUMENTED LIMITATION: a repo-local core.hooksPath (husky writes
    `core.hooksPath = .husky` into .git/config) overrides the global hook —
    git config precedence, local > global — so the strip does NOT run there.
    This test pins the limitation; if it ever starts failing, the docs in
    internal/session/git_attribution.go and the wiki should be updated."""
    env = write_trusted_coi_config(IDENTITY_TOML)
    name = _start_background_shell(coi_binary, workspace_dir, env)

    setup = "mkdir -p .husky && git config core.hooksPath .husky && "
    rc, out = _make_repo_and_commit(coi_binary, name, "/tmp/husky-repo", extra_setup=setup)
    assert rc == 0, f"commit should succeed: {out}"

    msg = _last_message(coi_binary, name, "/tmp/husky-repo")
    assert "Co-Authored-By" in msg, (
        "expected the trailer to SURVIVE under a local core.hooksPath (the documented "
        f"husky hole). If stripping now covers this case, update the docs. Got: {msg}"
    )


def test_strip_attribution_disabled(coi_binary, workspace_dir, cleanup_containers):
    """Opt-out: strip_attribution = false keeps the trailer and does not set
    core.hooksPath."""
    env = write_trusted_coi_config(IDENTITY_TOML + "strip_attribution = false\n")
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, "git config --global --get core.hooksPath")
    assert rc != 0 or "/etc/coi/git-hooks" not in out, (
        f"core.hooksPath must not be set when stripping is disabled, got: {out}"
    )

    rc, out = _make_repo_and_commit(coi_binary, name, "/tmp/keep-repo")
    assert rc == 0, f"commit should succeed: {out}"
    msg = _last_message(coi_binary, name, "/tmp/keep-repo")
    assert "Co-Authored-By" in msg, f"trailer must be preserved when disabled: {msg}"


def test_custom_patterns_replace_defaults(coi_binary, workspace_dir, cleanup_containers):
    """strip_attribution_patterns replaces the default list wholesale: the
    custom pattern is stripped, the (default-covered) Claude trailer is kept."""
    env = write_trusted_coi_config(
        IDENTITY_TOML + 'strip_attribution_patterns = ["^X-Custom-Footer:"]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(
        coi_binary,
        name,
        "mkdir -p /tmp/custom-repo && cd /tmp/custom-repo && git init -q . && "
        'git commit --allow-empty -m "$(printf '
        "'subject\\n\\nX-Custom-Footer: yes\\n\\nCo-Authored-By: Claude <noreply@anthropic.com>')\"",
    )
    assert rc == 0, f"commit should succeed: {out}"
    msg = _last_message(coi_binary, name, "/tmp/custom-repo")
    assert "X-Custom-Footer" not in msg, f"custom pattern must strip its line: {msg}"
    assert "Co-Authored-By" in msg, (
        f"defaults are REPLACED, so the Claude trailer must survive here: {msg}"
    )


def test_claude_managed_settings_carry_include_coauthoredby(
    coi_binary, workspace_dir, cleanup_containers
):
    """The Claude source-level layer: managed-settings.json (highest-precedence
    tier, not overridable in-session) carries includeCoAuthoredBy=false. This
    also covers the hook's blind spots (husky repos, --no-verify) for Claude."""
    env = write_trusted_coi_config(IDENTITY_TOML)
    name = _start_background_shell(coi_binary, workspace_dir, env)

    rc, out = _exec(coi_binary, name, "cat /etc/claude-code/managed-settings.json")
    assert rc == 0, f"managed settings should exist for the claude tool: {out}"
    assert '"includeCoAuthoredBy": false' in out, (
        f"managed settings must disable co-author attribution: {out}"
    )
