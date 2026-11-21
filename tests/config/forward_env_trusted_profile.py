"""
Test for coi run - forward_env in a trusted profile is forwarded.

Profiles under ~/.coi/profiles or next to $COI_CONFIG are user-controlled,
so their forward_env reaches the container. This is the positive pair of
forward_env_project_profile_ignored.py: it shows profile forward_env is
applied at all, so an empty value there means the project profile was
filtered out.

Tests that:
1. forward_env from ~/.coi/profiles/NAME/config.toml is forwarded
2. forward_env from dirname($COI_CONFIG)/profiles/NAME/config.toml is forwarded
3. No warning about an ignored forward_env is printed
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("location", ["home", "coi_config"])
def test_forward_env_trusted_profile(
    coi_binary, cleanup_containers, workspace_dir, tmp_path, location
):
    """
    Test that forward_env in a trusted profile reaches the container.

    Flow:
    1. Create <trusted>/profiles/fwdprof/config.toml with forward_env = ["COI_PROFILE_SECRET"]
       (home: a fake HOME's ~/.coi, COI_CONFIG unset; coi_config: next to $COI_CONFIG)
    2. Set COI_PROFILE_SECRET on host
    3. Run coi run --profile fwdprof -- sh -c 'echo value=[$COI_PROFILE_SECRET]'
    4. Verify the value is forwarded and stderr has no ignored-forward_env warning
    """
    env = os.environ.copy()
    if location == "home":
        fake_home = tmp_path / "fake_home"
        coi_dir = fake_home / ".coi"
        coi_dir.mkdir(parents=True)
        # Keep the runner's own settings (CI sets network mode there).
        real_config = Path.home() / ".coi" / "config.toml"
        if real_config.is_file():
            shutil.copy(real_config, coi_dir / "config.toml")
        env["HOME"] = str(fake_home)
        env.pop("COI_CONFIG", None)
    else:
        coi_dir = tmp_path / "trusted"
        coi_dir.mkdir()
        (coi_dir / "config.toml").write_text("")
        env["COI_CONFIG"] = str(coi_dir / "config.toml")

    profile_dir = coi_dir / "profiles" / "fwdprof"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text('forward_env = ["COI_PROFILE_SECRET"]\n')
    env["COI_PROFILE_SECRET"] = "trusted-profile-value-58"

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
    assert "value=[trusted-profile-value-58]" in result.stdout, (
        f"Trusted profile forward_env should be forwarded. stdout: {result.stdout}"
    )
    assert "ignoring 'forward_env'" not in result.stderr, (
        f"Trusted profile forward_env must not be ignored. stderr: {result.stderr}"
    )
