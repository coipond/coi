"""
Tests for exit code 3 (incus unavailable) when incus is not on PATH.

coi documents exit 3 for "incus not installed or daemon unreachable"
(internal/cli/errors.go, #806). The commands below run with a PATH that has
no incus binary, and with a throwaway HOME so no user config is read.
"""

import subprocess

import pytest

EXIT_INCUS_UNAVAILABLE = 3
NOT_INSTALLED = "incus is not installed — please install Incus first"


def _run_without_incus(coi_binary, args, tmp_path, workspace_dir):
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir(exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return subprocess.run(
        [coi_binary, *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace_dir,
        env={"PATH": str(empty_bin), "HOME": str(home)},
    )


@pytest.mark.parametrize(
    "args",
    [["shell"], ["run", "--", "true"], ["build"]],
    ids=["shell", "run", "build"],
)
def test_command_exits_3_without_incus(coi_binary, tmp_path, workspace_dir, args):
    """
    Flow:
    1. Run the command with no incus on PATH
    2. Verify it exits 3, not the generic 1
    3. Verify it says incus is not installed
    """
    result = _run_without_incus(coi_binary, args, tmp_path, workspace_dir)
    output = result.stderr + result.stdout

    assert result.returncode == EXIT_INCUS_UNAVAILABLE, (
        f"coi {' '.join(args)} without incus should exit {EXIT_INCUS_UNAVAILABLE}, "
        f"got {result.returncode}. Output:\n{output}"
    )
    assert NOT_INSTALLED in output, f"should say incus is not installed. Got:\n{output}"


def test_list_exits_3_without_incus(coi_binary, tmp_path, workspace_dir):
    """
    Flow:
    1. Run coi list with no incus on PATH
    2. Verify it exits 3
    """
    result = _run_without_incus(coi_binary, ["list"], tmp_path, workspace_dir)

    assert result.returncode == EXIT_INCUS_UNAVAILABLE, (
        f"coi list without incus should exit {EXIT_INCUS_UNAVAILABLE}, "
        f"got {result.returncode}. Output:\n{result.stderr}{result.stdout}"
    )
