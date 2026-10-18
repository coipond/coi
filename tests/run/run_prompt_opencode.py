"""
Integration test for `coi run --prompt` with the opencode tool (#48996).

`[tool] binary` points at a stub in the workspace, so no real opencode or auth
is needed. The stub records its arguments and stdin, then exits with a set
code. It checks the headless launch end to end: `opencode run` with the prompt
on stdin (verbatim, even when it starts with "-"), exit-code propagation, and
no hang when the caller keeps its stdin open.
"""

import subprocess
from pathlib import Path

from support.helpers import write_trusted_coi_config, write_workspace_container_config

FAKE_OPENCODE = """#!/bin/sh
printf '%s\\n' "$@" > /workspace/.opencode-args
cat > /workspace/.opencode-stdin
exit 7
"""

PROMPT = "---\ntitle: nightly\n---\n- fix the bug\n- add a test\n"


def test_run_prompt_opencode(coi_binary, cleanup_containers, workspace_dir, dummy_image, tmp_path):
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
