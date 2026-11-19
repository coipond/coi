"""
Test for coi run --prompt with the goose tool.

Tests that:
1. A plain prompt launches `goose run --quiet --instructions -`.
2. A prompt that starts with "-" reaches goose verbatim on stdin, not in argv.
3. goose's exit code becomes coi's exit code.
"""

import subprocess
from pathlib import Path

from support.helpers import write_trusted_coi_config, write_workspace_container_config

FAKE_GOOSE = """#!/bin/sh
printf '%s\\n' "$@" > /workspace/.goose-args
cat > /workspace/.goose-stdin
exit 7
"""

PROMPT = "--help me"


def test_run_prompt_goose(coi_binary, cleanup_containers, workspace_dir, dummy_image):
    """`[tool] binary` points at a stub in the workspace. The stub records its
    arguments and stdin, then exits 7."""
    write_workspace_container_config(workspace_dir, image=dummy_image)
    script = Path(workspace_dir) / "fake-goose.sh"
    script.write_text(FAKE_GOOSE)
    script.chmod(0o755)

    env = write_trusted_coi_config('[tool]\nname = "goose"\nbinary = "/workspace/fake-goose.sh"\n')
    env.pop("COI_USE_DUMMY", None)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, f"--prompt={PROMPT}"],
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr

    assert result.returncode == 7, (
        f"the agent's exit code should propagate (7). Got {result.returncode}. output:\n{output}"
    )
    args = (Path(workspace_dir) / ".goose-args").read_text().splitlines()
    assert args == ["run", "--quiet", "--instructions", "-"], (
        f"expected `goose run --quiet --instructions -` with no prompt in argv, got {args}"
    )
    received = (Path(workspace_dir) / ".goose-stdin").read_text()
    assert received == PROMPT, f"the prompt should reach stdin verbatim, got {received!r}"
