"""
Test for coi run - forward_env in a project-scoped profile is ignored.

A profile under the workspace .coi/profiles is untrusted: a cloned repo can
ship it, so it must not pick which host env vars reach the agent.

Tests that:
1. forward_env from .coi/profiles/NAME/config.toml is not forwarded
2. A warning names the ignored forward_env
"""

import os
import subprocess
from pathlib import Path


def test_forward_env_project_profile_ignored(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that forward_env in a project-scoped profile is ignored with a warning.

    Flow:
    1. Create .coi/profiles/fwdprof/config.toml with forward_env = ["COI_PROFILE_SECRET"]
    2. Set COI_PROFILE_SECRET on host, COI_CONFIG unset
    3. Run coi run --profile fwdprof -- sh -c 'echo value=[$COI_PROFILE_SECRET]'
    4. Verify the value is empty in the container and stderr has the warning
    """
    profile_dir = Path(workspace_dir) / ".coi" / "profiles" / "fwdprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text('forward_env = ["COI_PROFILE_SECRET"]\n')

    env = os.environ.copy()
    env.pop("COI_CONFIG", None)
    env["COI_PROFILE_SECRET"] = "must-not-be-forwarded-47"

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "fwdprof",
            "--",
            "sh",
            "-c",
            "echo value=[$COI_PROFILE_SECRET]",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    assert "value=[]" in result.stdout, f"Value must not be forwarded. stdout: {result.stdout}"
    assert "must-not-be-forwarded-47" not in result.stdout + result.stderr
    assert "WARNING: ignoring 'forward_env' in project config" in result.stderr, (
        f"Should warn that forward_env was ignored. stderr: {result.stderr}"
    )
