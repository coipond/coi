"""
The branch guard is an enforcement control: an untrusted project
`.coi/config.toml` must not be able to shrink or disable it (a cloned/agent-
planted repo could otherwise unlock pushes to main). `sanitizeUntrustedGit`
nils `protected_branches` from project scope, falling back to the default set —
so the guard stays on.

This proves it end to end: a project config sets `protected_branches = []`, yet
inside the container a commit on `main` is STILL rejected, and the downgrade is
announced rather than silently honored. (The pure-config half is covered by
TestSanitizeUntrusted_GitProtectedBranches in internal/config.)
"""

import subprocess
from pathlib import Path


def _write_project_config(workspace_dir, body):
    cfg = Path(workspace_dir) / ".coi"
    cfg.mkdir(exist_ok=True)
    (cfg / "config.toml").write_text(body)


def test_untrusted_cannot_disable_branch_guard(coi_binary, workspace_dir):
    """A project config's `protected_branches = []` is ignored: the guard stays on
    (commit on main rejected) and the downgrade warning is emitted."""
    _write_project_config(workspace_dir, "[git]\nprotected_branches = []\n")

    # Set up a throwaway repo on `main` and try to commit — the guard (restored to
    # its default because the untrusted override was dropped) must block it.
    script = (
        "rm -rf /tmp/ur && mkdir -p /tmp/ur && cd /tmp/ur && "
        "git init -q && git symbolic-ref HEAD refs/heads/main && "
        "git config user.name t && git config user.email t@e && "
        "echo x > f && git add f && git commit -m x"
    )
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=180,
    )
    combined = result.stdout + result.stderr

    # The commit on main must fail — the guard survived the untrusted disable attempt.
    assert result.returncode != 0, (
        f"untrusted `protected_branches = []` was honored — commit on main succeeded.\n{combined}"
    )
    assert "refusing to commit on protected branch 'main'" in combined, (
        f"expected the branch guard to still block the commit, got:\n{combined}"
    )
    # ...and the downgrade was announced, not silently dropped.
    lowered = combined.lower()
    assert "ignoring" in lowered and "git.protected_branches" in lowered, (
        f"expected an 'ignoring git.protected_branches' downgrade warning.\n{combined}"
    )
