"""
Test for coi shell in persistent mode - [tool] memory = "fresh" starts a new
session without the tool's memory of earlier sessions, but keeps the rest of
the container.

Tests that, for claude and codex (the dummy stands in for the tool's launch,
coi still handles the tool's real config dir):
1. A new session (no --resume) in the restarted persistent container keeps a
   file installed outside the workspace and the seeded credentials
2. The tool's history and memory files from the first session are gone
3. --resume of the first session, both in the container left running by a
   plain exit and in the restarted one, brings its memory back from the saved
   session on the host, drops the second session's memory, and keeps a config
   file the second session changed

A plain `coi shell` reuses only a stopped persistent container (a running one
is a live session, so it gets a new slot), so session 1 always powers off.

Flow:
  1. memory = "fresh", persistent; start, install a file, plant history,
     memory and a config file; power off
  2. coi shell (no --resume): install and credentials there, memory gone;
     change the config file, plant new memory; leave (exit or poweroff)
  3. coi shell --resume <session 1>: its memory restored, the new memory
     gone, config file unchanged
"""

import subprocess
import time

import pytest

from support.helpers import (
    calculate_container_name,
    container_cat,
    container_path_exists,
    exec_in,
    exit_tool_to_bash,
    leave_session,
    spawn_coi,
    wait_for_container_ready,
    wait_for_container_stopped,
    wait_for_prompt,
    write_trusted_coi_config,
)

INSTALLED = "/home/code/.local/bin/installed-tool"
# Planted memory holds this; the dummy creates an empty history.jsonl itself.
OLD = "old"

TOOLS = {
    "claude": {
        "seed": {".claude/.credentials.json": '{"marker": "fresh-memory"}'},
        "cred": "/home/code/.claude/.credentials.json",
        "setup": "/home/code/.claude/setup-marker.txt",
        "later": "/home/code/.claude/todos/later.json",
        "memory": [
            "/home/code/.claude/history.jsonl",
            "/home/code/.claude/projects/-workspace/memory/MEMORY.md",
            "/home/code/.claude/todos/old.json",
        ],
    },
    "codex": {
        "seed": {
            ".codex/auth.json": '{"tokens": {"access_token": "fresh-memory"}}',
            ".codex/config.toml": 'model = "gpt-5-codex"\n',
        },
        "cred": "/home/code/.codex/auth.json",
        "setup": "/home/code/.codex/setup-marker.txt",
        "later": "/home/code/.codex/sessions/2026/01/02/rollout-later.jsonl",
        "memory": [
            "/home/code/.codex/history.jsonl",
            "/home/code/.codex/sessions/2026/01/01/rollout-old.jsonl",
        ],
    },
}


def _leave(coi_binary, container, child, stop):
    """Exit the tool, then exit bash (container keeps running) or power off.

    After a poweroff, wait until the container is stopped: coi can exit
    while it still shuts down, and the next session would reuse it as
    running and see it stop during setup."""
    if not exit_tool_to_bash(child):
        child.close(force=True)
        raise AssertionError("the tool did not exit to bash")
    leave_session(child, "sudo poweroff" if stop == "poweroff" else "exit", require_exit=True)
    if stop == "poweroff":
        stopped, last = wait_for_container_stopped(coi_binary, container)
        assert stopped, f"{container} still running after poweroff: {last.stdout}{last.stderr}"


def _has_old(coi_binary, container, path):
    """Return whether path holds the memory planted in session 1."""
    ok, out = container_cat(coi_binary, container, path, user=1000)
    return ok and out.strip() == OLD


def _wait_for_saved_sessions(sessions_dir, config_dir, count, timeout=30):
    """Poll until count sessions have their config dir saved on the host."""
    deadline = time.monotonic() + timeout
    while True:
        saved = []
        if sessions_dir.is_dir():
            saved = [p.name for p in sessions_dir.iterdir() if (p / config_dir).is_dir()]
        if len(saved) >= count or time.monotonic() > deadline:
            return saved
        time.sleep(0.5)


def _start(coi_binary, workspace_dir, env, *args):
    child = spawn_coi(coi_binary, ["shell", *args], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)
    return child


@pytest.mark.parametrize("stop", ["exit", "poweroff"])
@pytest.mark.parametrize("tool_name", sorted(TOOLS))
def test_fresh_tool_memory_persistent(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, tool_name, stop
):
    spec = TOOLS[tool_name]
    container = calculate_container_name(workspace_dir, 1)

    fake_home = tmp_path / "fake_home"
    for rel, content in spec["seed"].items():
        path = fake_home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    env = write_trusted_coi_config(
        f'[tool]\nname = "{tool_name}"\nmemory = "fresh"\n[container]\npersistent = true\n'
    )
    env["HOME"] = str(fake_home)
    env["COI_USE_DUMMY"] = "1"
    sessions_dir = fake_home / ".coi" / f"sessions-{tool_name}"
    config_dir = f".{tool_name}"

    try:
        # === Phase 1: install something and leave memory behind ===
        child = _start(coi_binary, workspace_dir, env)
        plant = " && ".join(
            f"mkdir -p $(dirname {p}) && echo {OLD} > {p}"
            for p in [INSTALLED, spec["setup"], *spec["memory"]]
        )
        rc, out = exec_in(coi_binary, container, plant, user=1000)
        assert rc == 0, f"planting files failed: {out}"
        _leave(coi_binary, container, child, "poweroff")

        sessions = _wait_for_saved_sessions(sessions_dir, config_dir, 1)
        assert len(sessions) == 1, f"expected one saved session, got: {sessions}"
        first_session = sessions[0]

        # === Phase 2: a new session keeps the container, not the memory ===
        child = _start(coi_binary, workspace_dir, env)
        installed_kept = container_path_exists(coi_binary, container, INSTALLED)
        cred_kept = container_path_exists(coi_binary, container, spec["cred"])
        memory_left = [p for p in spec["memory"] if _has_old(coi_binary, container, p)]
        later = spec["later"]
        rc, out = exec_in(
            coi_binary,
            container,
            f"echo new > {spec['setup']} && mkdir -p $(dirname {later}) && echo later > {later}",
            user=1000,
        )
        assert rc == 0, f"changing the config file failed: {out}"
        _leave(coi_binary, container, child, stop)
        saved = _wait_for_saved_sessions(sessions_dir, config_dir, 2)
        assert len(saved) == 2, f"expected the second session saved, got: {saved}"

        assert installed_kept, f"{INSTALLED} should survive in the persistent container"
        assert cred_kept, f"{spec['cred']} should be kept on a fresh session"
        assert not memory_left, f"memory files should be gone on a fresh session: {memory_left}"

        # === Phase 3: --resume brings the first session's memory back ===
        child = _start(coi_binary, workspace_dir, env, f"--resume={first_session}")
        memory_missing = [p for p in spec["memory"] if not _has_old(coi_binary, container, p)]
        _, setup_after_resume = container_cat(coi_binary, container, spec["setup"], user=1000)
        later_after_resume = container_path_exists(coi_binary, container, spec["later"])
        _leave(coi_binary, container, child, "poweroff")

        assert not memory_missing, (
            f"--resume {first_session} should restore its memory: missing {memory_missing}"
        )
        assert not later_after_resume, (
            f"--resume {first_session} must not keep the later session's memory: {spec['later']}"
        )
        assert setup_after_resume.strip() == "new", (
            f"--resume must not revert {spec['setup']} to the saved copy: {setup_after_resume!r}"
        )
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container, "--force"],
            capture_output=True,
            timeout=30,
        )
