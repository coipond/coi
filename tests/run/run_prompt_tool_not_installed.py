"""
Test for coi run --prompt - a configured tool missing from the container.

Tests that:
1. A `[tool] binary` command name not on the container's PATH makes `coi run --prompt`
   print coi's hint naming the binary, the tool and [container.build] agents.
2. bash's own "command not found" does not appear.
3. coi exits 127 (bash's "command not found" status).
"""

import subprocess

from support.helpers import write_trusted_coi_config

# A bare name, looked up on PATH: bash says "command not found" for it
# (for a missing absolute path it says "No such file or directory").
MISSING = "coi-no-such-agent"


def test_run_prompt_tool_not_installed(coi_binary, cleanup_containers, workspace_dir):
    """The launch guard catches the missing binary before bash tries to run it.
    COI_USE_DUMMY is NOT set: it would replace argv[0] and hide the binary."""
    env = write_trusted_coi_config(f'[tool]\nbinary = "{MISSING}"\n')
    env.pop("COI_USE_DUMMY", None)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--prompt", "say hello"],
        capture_output=True,
        text=True,
        timeout=180,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    output = result.stdout + result.stderr

    # exit code 127: the tool binary is not installed
    assert result.returncode == 127, (
        f"a missing tool should exit 127. Got {result.returncode}. output:\n{output}"
    )
    assert f"coi: {MISSING} not found in this container." in output, (
        f"expected coi's not-installed hint. output:\n{output}"
    )
    assert (
        "If claude is missing from the image, add it to [container.build] agents, "
        "run coi build --force"
    ) in output, f"the hint should name the tool and the fix. output:\n{output}"
    assert "command not found" not in output, (
        f"bash's own error should not reach the user. output:\n{output}"
    )
