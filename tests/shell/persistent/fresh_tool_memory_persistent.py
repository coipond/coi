"""
Test for coi shell in persistent mode - [tool] memory = "fresh" starts a new
session without the tool's memory of earlier sessions, but keeps the rest of
the container.

Tests that, for claude and codex (the dummy stands in for the tool's launch,
coi still handles the tool's real config dir), both after a plain exit (the
container keeps running) and after a poweroff (it is restarted):
1. A new session (no --resume) in the reused persistent container keeps a
   file installed outside the workspace and the seeded credentials
2. The tool's history and memory files from the first session are gone
3. --resume of the first session brings its memory back from the saved
   session on the host, drops the second session's memory, and keeps a config
   file the second session changed

Flow:
  1. memory = "fresh", persistent; start, install a file, plant history,
     memory and a config file; leave (exit or poweroff)
  2. coi shell (no --resume): install and credentials there, memory gone;
     change the config file, plant new memory; leave
  3. coi shell --resume <session 1>: its memory restored, the new memory
     gone, config file unchanged
"""

import subprocess
import time

import pytest
from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    exec_in,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
    write_trusted_coi_config,
)

INSTALLED = "/home/code/.local/bin/installed-tool"

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


def _leave(child, stop):
    """Exit the tool, then exit bash (container keeps running) or power off."""
    child.send("exit")
    time.sleep(0.3)
    child.send("\x0d")
    time.sleep(3)
    child.send("sudo poweroff" if stop == "poweroff" else "exit")
    time.sleep(0.3)
    child.send("\x0d")
    try:
        child.expect(EOF, timeout=60)
    except TIMEOUT:
        pass
    try:
        child.close(force=False)
    except Exception:
        child.close(force=True)


def _start(coi_binary, workspace_dir, env, *args):
    child = spawn_coi(coi_binary, ["shell", *args], cwd=workspace_dir, env=env, timeout=120)
    wait_for_container_ready(child, timeout=60)
    wait_for_prompt(child, timeout=90)
    return child


def _present(coi_binary, container, path):
    rc, _ = exec_in(coi_binary, container, f"test -e {path}", user=1000)
    return rc == 0


def _read(coi_binary, container, path):
    _, out = exec_in(coi_binary, container, f"cat {path}", user=1000)
    return out.strip()


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

    try:
        # === Phase 1: install something and leave memory behind ===
        child = _start(coi_binary, workspace_dir, env)
        plant = " && ".join(
            f"mkdir -p $(dirname {p}) && echo old > {p}"
            for p in [INSTALLED, spec["setup"], *spec["memory"]]
        )
        rc, out = exec_in(coi_binary, container, plant, user=1000)
        assert rc == 0, f"planting files failed: {out}"
        _leave(child, stop)
        time.sleep(3)

        sessions = [p.name for p in sessions_dir.iterdir() if (p / "metadata.json").is_file()]
        assert len(sessions) == 1, f"expected one saved session, got: {sessions}"
        first_session = sessions[0]

        # === Phase 2: a new session keeps the container, not the memory ===
        child = _start(coi_binary, workspace_dir, env)
        installed_kept = _present(coi_binary, container, INSTALLED)
        cred_kept = _present(coi_binary, container, spec["cred"])
        memory_left = [p for p in spec["memory"] if _present(coi_binary, container, p)]
        later = spec["later"]
        rc, out = exec_in(
            coi_binary,
            container,
            f"echo new > {spec['setup']} && mkdir -p $(dirname {later}) && echo later > {later}",
            user=1000,
        )
        assert rc == 0, f"changing the config file failed: {out}"
        _leave(child, stop)
        time.sleep(3)

        assert installed_kept, f"{INSTALLED} should survive in the persistent container"
        assert cred_kept, f"{spec['cred']} should be kept on a fresh session"
        assert not memory_left, f"memory files should be gone on a fresh session: {memory_left}"

        # === Phase 3: --resume brings the first session's memory back ===
        child = _start(coi_binary, workspace_dir, env, f"--resume={first_session}")
        memory_missing = [p for p in spec["memory"] if not _present(coi_binary, container, p)]
        setup_after_resume = _read(coi_binary, container, spec["setup"])
        later_after_resume = _present(coi_binary, container, spec["later"])
        _leave(child, "poweroff")

        assert not memory_missing, (
            f"--resume {first_session} should restore its memory: missing {memory_missing}"
        )
        assert not later_after_resume, (
            f"--resume {first_session} must not keep the later session's memory: {spec['later']}"
        )
        assert setup_after_resume == "new", (
            f"--resume must not revert {spec['setup']} to the saved copy: {setup_after_resume!r}"
        )
    finally:
        time.sleep(2)
        subprocess.run(
            [coi_binary, "container", "delete", container, "--force"],
            capture_output=True,
            timeout=30,
        )
