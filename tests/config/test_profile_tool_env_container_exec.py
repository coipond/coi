"""
Profile [tool.*] config must reach an external `coi container exec` (#744).

Before the fix, a profile's [tool.claude] model/effort were only delivered to
coi's own tool launch (via the in-container settings.json written on fresh
setup). A consumer that prepares the container with `coi shell --background`
and then runs the tool through a separate `coi container exec` got none of it.

The fix persists the tool's resolved env as container-level `environment.*`
Incus config, which Incus injects into every exec. This asserts the direct
reproduction: `coi container exec` sees the profile's ANTHROPIC_MODEL /
CLAUDE_CODE_EFFORT_LEVEL. The stale-key reconciliation on a reused container is
covered by unit tests (planToolContainerEnv) rather than here, since forcing
container reuse in the harness is brittle.
"""

import os
import subprocess

from support.helpers import container_config_get, write_profile

MODEL = "coi-test-model-opus"


def _start_background_shell(coi_binary, workspace_dir, profile):
    r = subprocess.run(
        [
            coi_binary,
            "shell",
            "--workspace",
            workspace_dir,
            "--profile",
            profile,
            "--background",
            "--debug",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "COI_USE_DUMMY": "1"},
        cwd=workspace_dir,
    )
    assert r.returncode == 0, f"background shell should start. stderr: {r.stderr}"
    name = None
    for line in r.stderr.split("\n"):
        if "Container name:" in line:
            name = line.split("Container name:")[-1].strip()
            break
    assert name, f"could not find container name. stderr: {r.stderr}"
    return name


def _printenv(coi_binary, container_name, var):
    """Return the value of `var` inside the container via `coi container exec`.

    coi surfaces the guest command's stdout on stderr for non-capture exec.
    """
    r = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "printenv", var],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return (r.stdout + r.stderr).strip()


def test_profile_model_reaches_container_exec(coi_binary, workspace_dir, cleanup_containers):
    """A profile's [tool.claude] model/effort is visible to `coi container exec`."""
    write_profile(
        workspace_dir,
        "modeltest",
        f"""
[container]
image = "coi-default"
persistent = true

[tool]
name = "claude"

[tool.claude]
model = "{MODEL}"
effort_level = "high"
""",
    )

    container_name = _start_background_shell(coi_binary, workspace_dir, "modeltest")

    # The direct reproduction: an external exec inherits the profile's tool env.
    assert _printenv(coi_binary, container_name, "ANTHROPIC_MODEL") == MODEL, (
        "coi container exec must see the profile's ANTHROPIC_MODEL"
    )
    assert _printenv(coi_binary, container_name, "CLAUDE_CODE_EFFORT_LEVEL") == "high", (
        "coi container exec must see the profile's CLAUDE_CODE_EFFORT_LEVEL"
    )

    # And it's recorded as container-level config (not a per-exec flag).
    got = container_config_get(container_name, "environment.ANTHROPIC_MODEL")
    assert got == MODEL, f"environment.ANTHROPIC_MODEL should be set on the container, got {got!r}"
