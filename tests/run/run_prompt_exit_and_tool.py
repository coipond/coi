"""
Integration tests for `coi run` headless prompt mode (#701): the agent's exit
code becomes coi's exit code, an unsupported tool is refused before any
container work, and a `[prompts]` `file =` path resolves relative to the
config file's directory.

The agent is a `[tool] binary` stub in the workspace (bind-mounted into the
container). COI_USE_DUMMY is removed from the environment: it swaps argv[0] for
the dummy stub and would bypass `binary`.
"""

import os
import subprocess
from pathlib import Path

from support.helpers import write_trusted_coi_config, write_workspace_container_config

PROMPT_MARKER = ".coi-prompt-received"

# claude's headless argv ends with the prompt text: record it, then exit with
# the given code.
FAKE_CLAUDE = f"""#!/bin/sh
for arg; do last="$arg"; done
printf '%s' "$last" > /workspace/{PROMPT_MARKER}
exit {{code}}
"""


def _write_stub(workspace_dir, code):
    script = Path(workspace_dir) / "fake-claude.sh"
    script.write_text(FAKE_CLAUDE.format(code=code))
    script.chmod(0o755)
    return "/workspace/fake-claude.sh"


def test_run_prompt_agent_exit_code(coi_binary, cleanup_containers, workspace_dir, dummy_image):
    """A claude agent that exits 3 makes `coi run --prompt` exit 3, not 0 or 1."""
    write_workspace_container_config(workspace_dir, image=dummy_image)
    binary = _write_stub(workspace_dir, 3)
    env = write_trusted_coi_config(f'[tool]\nname = "claude"\nbinary = "{binary}"\n')
    env.pop("COI_USE_DUMMY", None)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt", "fail on purpose"],
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 3, (
        f"the agent's exit code should propagate (3). Got {result.returncode}. output:\n{output}"
    )
    assert "Agent exited with code 3" in output
    received = (Path(workspace_dir) / PROMPT_MARKER).read_text()
    assert received == "fail on purpose", f"the stub should get the prompt, got {received!r}"


def test_run_prompt_unsupported_tool(coi_binary, workspace_dir):
    """`[tool] name = "codex"` is refused with exit 2 before any container work."""
    env = write_trusted_coi_config('[tool]\nname = "codex"\n')

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt", "say hello"],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr
    # Should fail with exit code 2 (usage error)
    assert result.returncode == 2, f"want exit 2, got {result.returncode}. output:\n{output}"
    assert (
        "coi run headless prompt mode currently supports only the claude and opencode tools "
        '(configured: "codex")'
    ) in output
    assert "Launching container" not in output, f"no container should be started:\n{output}"


def test_run_prompt_name_file_relative_to_config(
    coi_binary, cleanup_containers, workspace_dir, dummy_image, tmp_path
):
    """`[prompts] name = { file = "prompts/x.md" }` reads the file next to the
    config file. coi runs from the workspace, which holds a decoy
    `prompts/x.md`, so a path resolved against the working directory sends the
    decoy text instead."""
    write_workspace_container_config(workspace_dir, image=dummy_image)
    binary = _write_stub(workspace_dir, 0)

    decoy = Path(workspace_dir) / "prompts" / "x.md"
    decoy.parent.mkdir()
    decoy.write_text("decoy prompt from the working directory")

    config_dir = tmp_path / "config"
    (config_dir / "prompts").mkdir(parents=True)
    (config_dir / "prompts" / "x.md").write_text("prompt next to the config file")
    config = config_dir / "config.toml"
    config.write_text(
        f'[tool]\nname = "claude"\nbinary = "{binary}"\n\n'
        '[prompts]\nnightly = { file = "prompts/x.md" }\n'
    )
    env = {**os.environ, "COI_CONFIG": str(config)}
    env.pop("COI_USE_DUMMY", None)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt-name", "nightly"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"named prompt run should exit 0. Got {result.returncode}:\n{output}"
    )
    received = (Path(workspace_dir) / PROMPT_MARKER).read_text()
    assert received == "prompt next to the config file", (
        f"the prompt file should resolve next to the config file, got {received!r}"
    )
