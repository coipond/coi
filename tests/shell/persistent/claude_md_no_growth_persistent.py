"""
End-to-end regression test for #674: the Coi sandbox context block must not
accumulate in ~/.claude/CLAUDE.md across sessions on a persistent container.

Background: coi injects a sandbox context block into the tool's native
auto-context file (Claude's ~/.claude/CLAUDE.md) during session setup. On a
persistent container the file survives between sessions, and setup re-runs on
every session (the context block is re-rendered "for both new and resumed
sessions so dynamic info stays current"). So the block must be REPLACED, not
appended. Before the fix it was appended each session and the file grew without
bound — the reporter hit 16 identical copies / 108k chars, past Claude Code's
40k limit.

This drives the real `coi` CLI end-to-end. It creates one persistent container,
then reuses that SAME container across several sessions the way a real
stop/resume cycle does — stop it, then `coi shell --container <name>` to re-enter
it — so setup (and its auto-context injection) runs again against the same
persisted home. Each session uses `--background` (runs setup then detaches, so no
interactive/real `claude` binary is needed). The file is then read back from
inside the container; because "# COI Sandbox Environment" renders exactly once
per block, its occurrence count is the number of copies and must be exactly one.

The tool is intentionally left at its default (Claude) — i.e. COI_USE_DUMMY is
NOT set — because only the Claude tool implements the auto-context file path; the
dummy tool would never exercise it.
"""

import subprocess
import time

from support.helpers import (
    calculate_container_name,
    write_workspace_container_config,
)


def _incus_run(*args):
    """Run an incus command directly (no sg wrapper), matching the coi project."""
    return subprocess.run(
        ["incus", "--project", "default", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _container_exists(name):
    return _incus_run("info", name).returncode == 0


def test_claude_md_does_not_grow_across_persistent_sessions(
    coi_binary, cleanup_containers, workspace_dir
):
    # Persistent so the container (and its ~/.claude/CLAUDE.md) survives between
    # sessions and can be re-entered instead of recreated.
    write_workspace_container_config(workspace_dir, persistent=True)

    claude_md = "/home/code/.claude/CLAUDE.md"
    container_name = calculate_container_name(workspace_dir, 1)

    try:
        # --- Session 1: create the persistent container (slot 1). ---
        first = subprocess.run(
            [coi_binary, "shell", "--background"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert first.returncode == 0, (
            f"session 1 (create): `coi shell --background` should succeed. "
            f"stderr: {first.stderr}\nstdout: {first.stdout}"
        )
        time.sleep(2)
        assert _container_exists(container_name), (
            f"expected persistent container {container_name} to exist after session 1"
        )

        # --- Sessions 2 & 3: stop, then re-enter the SAME container. ---
        # `--container` forces reuse of this exact container (no new slot), driving
        # the setup reuse path that re-injects the auto-context block.
        extra_sessions = 2
        for i in range(extra_sessions):
            stop = subprocess.run(
                [coi_binary, "container", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert stop.returncode == 0, (
                f"stopping before resume {i + 1} should succeed. stderr: {stop.stderr}"
            )
            time.sleep(1)

            resumed = subprocess.run(
                [coi_binary, "shell", "--container", container_name, "--background"],
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                timeout=180,
            )
            assert resumed.returncode == 0, (
                f"resume {i + 1}: `coi shell --container --background` should succeed. "
                f"stderr: {resumed.stderr}\nstdout: {resumed.stdout}"
            )
            time.sleep(2)

        total_sessions = 1 + extra_sessions

        # Guard: the same container was reused, not fresh slots — otherwise each
        # session would trivially have one copy and hide a regression.
        assert not _container_exists(calculate_container_name(workspace_dir, 2)), (
            "a second container slot was created; sessions did not reuse the same "
            "persistent container, so this test would not exercise the accumulation path"
        )

        # Read the injected file back from inside the container. `coi container
        # exec` routes the command's stdout to ITS stderr, so read both streams.
        exec_res = subprocess.run(
            [coi_binary, "container", "exec", container_name, "--", "cat", claude_md],
            capture_output=True,
            text=True,
            timeout=30,
        )
        content = exec_res.stdout + exec_res.stderr
        # Sanity: the injection must have happened at all (guards against a
        # false pass where the block is simply never written).
        assert "# COI Sandbox Environment" in content, (
            f"expected the sandbox block to be present in {claude_md}; "
            f"exec rc={exec_res.returncode}, output head={content[:400]!r}"
        )

        copies = content.count("# COI Sandbox Environment")
        assert copies == 1, (
            f"#674: the Coi sandbox context block must appear exactly once in "
            f"{claude_md} after {total_sessions} sessions on one persistent container, "
            f"but found {copies} copies ({len(content)} chars). It is being appended on "
            f"every session instead of replaced, so the file grows without bound."
        )
    finally:
        _incus_run("delete", container_name, "--force")
