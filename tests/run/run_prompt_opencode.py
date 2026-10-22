"""
Integration tests for `coi run --prompt` with the opencode tool: the prompt
must reach `opencode run` verbatim (even when it starts with "-") and the
agent's exit code must propagate.
"""

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

from support.helpers import (
    tool_data_dir,
    write_trusted_coi_config,
    write_workspace_container_config,
)

FAKE_OPENCODE = """#!/bin/sh
printf '%s\\n' "$@" > /workspace/.opencode-args
cat > /workspace/.opencode-stdin
exit 7
"""

PROMPT = "---\ntitle: nightly\n---\n- fix the bug\n- add a test\n"


def test_run_prompt_opencode(coi_binary, cleanup_containers, workspace_dir, dummy_image, tmp_path):
    """`[tool] binary` points at a stub in the workspace. The stub records its
    arguments and stdin, then exits with a set code. Checks `opencode run` with
    the prompt on stdin, exit-code propagation, and no hang when the caller
    keeps its stdin open."""
    write_workspace_container_config(workspace_dir, image=dummy_image)
    script = Path(workspace_dir) / "fake-opencode.sh"
    script.write_text(FAKE_OPENCODE)
    script.chmod(0o755)

    prompt = tmp_path / "task.md"
    prompt.write_text(PROMPT)

    env = write_trusted_coi_config(
        '[tool]\nname = "opencode"\nbinary = "/workspace/fake-opencode.sh"\n'
    )
    env.pop("COI_USE_DUMMY", None)

    # Keep coi's stdin open and idle: the launch must not wait on it.
    log = tmp_path / "coi.log"
    with open(log, "w") as out:
        proc = subprocess.Popen(
            [coi_binary, "run", "--workspace", workspace_dir, "--prompt-file", str(prompt)],
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=subprocess.STDOUT,
            env=env,
        )
        try:
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError(
                f"coi run --prompt with opencode blocked on an open stdin:\n{log.read_text()}"
            ) from None
        finally:
            proc.stdin.close()
    output = log.read_text()

    assert proc.returncode == 7, (
        f"the agent's exit code should propagate (7). Got {proc.returncode}. output:\n{output}"
    )
    args = (Path(workspace_dir) / ".opencode-args").read_text().splitlines()
    assert args == ["run"], f"expected `opencode run` with no positional prompt, got {args}"
    received = (Path(workspace_dir) / ".opencode-stdin").read_text()
    assert received == PROMPT, f"the prompt should reach stdin verbatim, got {received!r}"


def test_run_prompt_real_opencode(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """The real opencode from the default image, with no credentials. The
    configured model does not exist, so opencode stores the prompt in its
    session database, fails before any model call, and exits 1. The database
    lives in a host dir outside the workspace (#929), so the test reads the
    prompt back from it on the host."""
    prompt = tmp_path / "task.md"
    prompt.write_text(PROMPT)

    env = write_trusted_coi_config(
        '[tool]\nname = "opencode"\n\n'
        "[defaults.environment]\n"
        'OPENCODE_CONFIG_CONTENT = \'{"model": "coi-test/none"}\'\n'
    )
    env.pop("COI_USE_DUMMY", None)
    data_dir = tool_data_dir(workspace_dir, "opencode", "share")
    try:
        _check_real_opencode_prompt(coi_binary, workspace_dir, tmp_path, prompt, env, data_dir)
    finally:
        shutil.rmtree(data_dir.parent, ignore_errors=True)


def _check_real_opencode_prompt(coi_binary, workspace_dir, tmp_path, prompt, env, data_dir):
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt-file", str(prompt)],
        capture_output=True,
        text=True,
        timeout=240,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"opencode should fail on the unknown model and coi should return its exit code (1). "
        f"Got {result.returncode}. output:\n{output}"
    )

    assert not (Path(workspace_dir) / ".local").exists(), (
        "opencode data must not land in the workspace: its snapshot repo tracks "
        "the work tree and would snapshot itself (#929)"
    )

    # Copy the database (and its WAL) so sqlite can open it outside the mount.
    assert (data_dir / "opencode.db").exists(), (
        f"opencode did not create its session database. output:\n{output}"
    )
    for name in ("opencode.db", "opencode.db-wal", "opencode.db-shm"):
        if (data_dir / name).exists():
            shutil.copy(data_dir / name, tmp_path / name)
    with sqlite3.connect(tmp_path / "opencode.db") as db:
        texts = [json.loads(row[0]).get("text") for row in db.execute("SELECT data FROM part")]
    assert PROMPT in texts, f"the prompt should reach opencode verbatim, got {texts!r}"
