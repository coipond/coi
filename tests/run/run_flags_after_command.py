"""
Test for coi run - flags after the command go to the command.

Tests that:
1. Everything after the command's name is passed to the command, flags
   included (coi run ls -la, coi run grep -w <dir> pattern)
2. A "--" after the command's name is passed to the command too
3. coi flags before the command still apply (coi run -w <dir> ls -la)
4. --resume and --continue are rejected with exit code 2 and a hint to use
   coi shell, before any container work
"""

import os
import subprocess

import pytest


def _make_dirs(workspace_dir, tmp_path):
    """Mark the workspace and a second dir that must never become the workspace."""
    with open(os.path.join(workspace_dir, ".workspace_marker"), "w") as f:
        f.write("workspace-dir\n")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    (other_dir / ".other_marker").write_text("other-dir\n")
    return str(other_dir)


def test_run_flags_after_command_go_to_command(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Test that flags after the command's name reach the command.

    Flow:
    1. From the workspace, run coi run ls -la (no coi flags)
    2. Verify ls got -la: the hidden workspace marker is listed
    3. From the workspace, run coi run grep -w <other dir> <file>
    4. Verify grep got -w and the other dir as its pattern, and coi did not
       use the other dir as the workspace
    """
    other_dir = _make_dirs(workspace_dir, tmp_path)

    result = subprocess.run(
        [coi_binary, "run", "ls", "-la"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    combined_output = result.stdout + result.stderr
    assert ".workspace_marker" in combined_output, (
        f"ls should get -la and list the hidden marker. Got:\n{combined_output}"
    )

    with open(os.path.join(workspace_dir, "words.txt"), "w") as f:
        f.write(f"path {other_dir} end\n{other_dir}-suffix\n")

    result = subprocess.run(
        [coi_binary, "run", "grep", "-w", other_dir, "words.txt"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=180,
    )

    # grep exits 2 if words.txt is missing, i.e. the other dir became the workspace
    assert result.returncode == 0, (
        f"grep should match in the workspace's words.txt. Got {result.returncode}. "
        f"stdout: {result.stdout} stderr: {result.stderr}"
    )
    combined_output = result.stdout + result.stderr
    assert f"path {other_dir} end" in combined_output, (
        f"grep should print the whole-word match. Got:\n{combined_output}"
    )
    assert f"{other_dir}-suffix" not in combined_output, (
        f"grep should get -w and skip the partial-word line. Got:\n{combined_output}"
    )


def test_run_double_dash_after_command_goes_to_command(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """
    Test that coi flags and "--" after the command's name reach the command
    (like coi run npm test -- --watch).

    Flow:
    1. Run coi run -w <workspace> sh -c <print args> sh test --workspace <other dir> -- --watch
    2. Verify the command got every argument, "--" included
    3. Verify the workspace is the one given before the command
    """
    other_dir = _make_dirs(workspace_dir, tmp_path)

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "-w",
            workspace_dir,
            "sh",
            "-c",
            'for a in "$@"; do echo "[$a]"; done; ls -a /workspace',
            "sh",
            "test",
            "--workspace",
            other_dir,
            "--",
            "--watch",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    combined_output = result.stdout + result.stderr
    expected = f"[test]\n[--workspace]\n[{other_dir}]\n[--]\n[--watch]\n"
    assert expected in combined_output, (
        f"Command should get all args in order. Want:\n{expected}Got:\n{combined_output}"
    )
    assert ".workspace_marker" in combined_output, (
        f"/workspace should be the -w dir. Got:\n{combined_output}"
    )
    assert ".other_marker" not in combined_output, (
        f"--workspace after the command must not change the workspace. Got:\n{combined_output}"
    )


def test_run_flags_before_command_apply(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    Test that coi flags before the command still apply.

    Flow:
    1. From the other dir, run coi run -w <workspace> ls -la
    2. Verify /workspace is the -w dir, not the current dir
    """
    other_dir = _make_dirs(workspace_dir, tmp_path)

    result = subprocess.run(
        [coi_binary, "run", "-w", workspace_dir, "ls", "-la"],
        cwd=other_dir,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, f"Run should succeed. stderr: {result.stderr}"
    combined_output = result.stdout + result.stderr
    assert ".workspace_marker" in combined_output, (
        f"/workspace should be the -w dir. Got:\n{combined_output}"
    )
    assert ".other_marker" not in combined_output, (
        f"The current dir must not be the workspace. Got:\n{combined_output}"
    )


@pytest.mark.parametrize(
    "flags",
    [
        ["--resume", "some-session-id"],
        ["--resume=some-session-id"],
        ["--continue"],
    ],
)
def test_run_resume_flags_rejected(coi_binary, workspace_dir, flags):
    """
    Test that coi run rejects --resume and --continue.

    Flow:
    1. Run coi run <flag> touch ran
    2. Verify exit code 2 and the coi shell hint
    3. Verify the command did not run
    """
    flag = flags[0].split("=")[0]

    result = subprocess.run(
        [coi_binary, "run", *flags, "touch", "ran"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )

    # Should fail with exit code 2 (usage error)
    assert result.returncode == 2, (
        f"want exit 2, got {result.returncode}. stdout: {result.stdout} stderr: {result.stderr}"
    )
    combined_output = result.stdout + result.stderr
    assert f"coi run does not support {flag}" in combined_output, combined_output
    assert f"use coi shell {flag} to resume a session" in combined_output, combined_output
    assert not os.path.exists(os.path.join(workspace_dir, "ran")), "The command should not run"
