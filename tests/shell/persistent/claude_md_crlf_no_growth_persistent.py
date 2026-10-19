"""
#674 / #781 regression: a host auto-context file saved with CRLF line endings
(e.g. edited on Windows) that still holds an old coi BEGIN/END block must end up
with exactly one coi block across sessions on a persistent container.

With CRLF the old block's markers end in "\\r". Without the CR-tolerant marker
match the old block is not recognized, so a new block is appended next to it and
the file grows. The existing no-growth tests use LF only.

The same reconcile serves Claude's ~/.claude/CLAUDE.md and Codex's
~/.codex/AGENTS.md, so both are checked. COI_USE_DUMMY=1 keeps the tool
binaries out of the picture; setup still runs the tool's auto-context path.
"""

import os
import subprocess
import time

import pytest

from support.helpers import (
    calculate_container_name,
    write_workspace_container_config,
)

USER_MARKER = "USER-CRLF-CONTENT-674"
BEGIN = "# BEGIN COI Sandbox Context (managed by coi - do not edit this block)"
END = "# END COI Sandbox Context (managed by coi)"

HOST_CONTENT = "\r\n".join(
    [
        "# My instructions",
        USER_MARKER,
        "",
        BEGIN,
        "# COI Sandbox Environment",
        "",
        "Old block from an earlier coi version, running in Code on Incus.",
        END,
        "",
    ]
)


def _incus_run(*args):
    return subprocess.run(
        ["incus", "--project", "default", *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _container_exists(name):
    return _incus_run("info", name).returncode == 0


@pytest.mark.parametrize(
    "tool,rel_path",
    [("claude", ".claude/CLAUDE.md"), ("codex", ".codex/AGENTS.md")],
)
def test_crlf_auto_context_file_keeps_one_block_across_persistent_sessions(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, tool, rel_path
):
    """Seed a CRLF host file with an old managed block, run 3 sessions on one
    persistent container, and expect the user content and the coi block exactly
    once each."""
    coi_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(coi_dir, exist_ok=True)
    with open(os.path.join(coi_dir, "config.toml"), "w") as f:
        f.write(f'[tool]\nname = "{tool}"\n')
    write_workspace_container_config(workspace_dir, persistent=True)

    fake_home = tmp_path / "fake_home"
    host_file = fake_home / rel_path
    host_file.parent.mkdir(parents=True)
    host_file.write_bytes(HOST_CONTENT.encode())
    env = {**os.environ, "HOME": str(fake_home), "COI_USE_DUMMY": "1"}

    container_name = calculate_container_name(workspace_dir, 1)
    try:
        first = subprocess.run(
            [coi_binary, "shell", "--background"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
        assert first.returncode == 0, f"session 1 should succeed. stderr: {first.stderr}"
        time.sleep(2)
        assert _container_exists(container_name), f"expected {container_name} after session 1"

        for i in range(2):
            stop = subprocess.run(
                [coi_binary, "container", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert stop.returncode == 0, f"stop before resume {i + 1}: {stop.stderr}"
            time.sleep(1)
            resumed = subprocess.run(
                [coi_binary, "shell", "--container", container_name, "--background"],
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                timeout=180,
                env=env,
            )
            assert resumed.returncode == 0, f"resume {i + 1}: {resumed.stderr}"
            time.sleep(2)

        assert not _container_exists(calculate_container_name(workspace_dir, 2)), (
            "sessions forked a new slot instead of reusing the same container"
        )

        # `coi container exec` routes the command's stdout to ITS stderr.
        exec_res = subprocess.run(
            [
                coi_binary,
                "container",
                "exec",
                container_name,
                "--",
                "cat",
                f"/home/code/{rel_path}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        content = exec_res.stdout + exec_res.stderr

        user_copies = content.count(USER_MARKER)
        block_copies = content.count("# COI Sandbox Environment")
        begin_copies = content.count(BEGIN)
        assert user_copies == 1, (
            f"host {rel_path} content must survive exactly once, found {user_copies}. "
            f"Content head: {content[:400]!r}"
        )
        assert block_copies == 1 and begin_copies == 1, (
            f"the coi block must appear exactly once in {rel_path} after 3 sessions, found "
            f"{block_copies} headers / {begin_copies} BEGIN markers: the CRLF old block was "
            f"not recognized (#674). Content head: {content[:400]!r}"
        )
    finally:
        _incus_run("delete", container_name, "--force")
