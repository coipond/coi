"""
Test that forward_env from a config file works.

forward_env is trusted-scope only: these tests write the workspace
.coi/config.toml and also point COI_CONFIG at it, which loads it as trusted.
A project config alone does not forward anything (last test).

Tests that:
1. forward_env in [defaults] section forwards host env vars into container
2. Values are resolved from the host, not stored in config
3. Multiple forward_env entries are all forwarded
"""

import os
import subprocess
from pathlib import Path


def test_forward_env_from_config(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that forward_env in .coi/config.toml forwards host env vars.

    Flow:
    1. Create .coi/config.toml with forward_env = ["COI_CFG_SECRET"]
    2. Set COI_CFG_SECRET on host
    3. Run coi run -- sh -c 'echo $COI_CFG_SECRET'
    4. Verify the value is forwarded
    """
    # Create project config with forward_env
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    config_path = config_dir / "config.toml"
    config_path.write_text(
        """
[defaults]
forward_env = ["COI_CFG_SECRET"]
"""
    )

    env = os.environ.copy()
    env["COI_CONFIG"] = str(config_dir / "config.toml")  # forward_env is trusted-scope only
    env["COI_CFG_SECRET"] = "secret-from-config-99"

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "echo $COI_CFG_SECRET",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"

    combined_output = result.stdout + result.stderr
    assert "secret-from-config-99" in combined_output, (
        f"Output should contain forwarded env var value from config. Got:\n{combined_output}"
    )


def test_forward_env_config_multiple(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that multiple forward_env entries in config are all forwarded.

    Flow:
    1. Create .coi/config.toml with forward_env = ["COI_FROM_CFG", "COI_FROM_CFG2"]
    2. Set both vars on host
    3. Run and verify both are forwarded
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    config_path = config_dir / "config.toml"
    config_path.write_text(
        """
[defaults]
forward_env = ["COI_FROM_CFG", "COI_FROM_CFG2"]
"""
    )

    env = os.environ.copy()
    env["COI_CONFIG"] = str(config_dir / "config.toml")  # forward_env is trusted-scope only
    env["COI_FROM_CFG"] = "cfg-value"
    env["COI_FROM_CFG2"] = "cfg2-value"

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "echo CFG=$COI_FROM_CFG CFG2=$COI_FROM_CFG2",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"

    combined_output = result.stdout + result.stderr
    assert "CFG=cfg-value" in combined_output, (
        f"First config forward_env should be forwarded. Got:\n{combined_output}"
    )
    assert "CFG2=cfg2-value" in combined_output, (
        f"Second config forward_env should be forwarded. Got:\n{combined_output}"
    )


def test_forward_env_ignored_from_project_config(coi_binary, cleanup_containers, workspace_dir):
    """
    forward_env in an untrusted project .coi/config.toml is ignored with a
    warning: a cloned repo must not pick which host env vars reach the agent.
    """
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        """
[defaults]
forward_env = ["COI_UNTRUSTED_SECRET"]
"""
    )

    env = os.environ.copy()
    env.pop("COI_CONFIG", None)
    env["COI_UNTRUSTED_SECRET"] = "must-not-be-forwarded-31"

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "echo value=[$COI_UNTRUSTED_SECRET]",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    assert "value=[]" in result.stdout, f"Value must not be forwarded. stdout: {result.stdout}"
    assert "must-not-be-forwarded-31" not in result.stdout + result.stderr
    assert "ignoring 'forward_env' in project config" in result.stderr, (
        f"Should warn that forward_env was ignored. stderr: {result.stderr}"
    )
