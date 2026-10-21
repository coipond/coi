"""
Test [[mounts.default]] entries whose host source does not exist.

Tests that, for coi shell and coi run:
1. A readonly mount with a missing source logs "Warning: readonly mount source
   <path> does not exist, skipping", the session still starts, and the path is
   not created on the host or mounted in the container
2. A writable mount with a missing source is created on the host (with its
   missing parents, mode 0755) and mounted in the container
"""

import stat
import subprocess

from support.helpers import calculate_container_name, write_trusted_coi_config


def _config(tmp_path):
    ro = tmp_path / "missing-ro" / "data"
    rw = tmp_path / "missing-rw" / "data"
    env = write_trusted_coi_config(
        f"""\
[[mounts.default]]
host = "{ro}"
container = "/mnt/missing-ro"
readonly = true

[[mounts.default]]
host = "{rw}"
container = "/mnt/missing-rw"
"""
    )
    return ro, rw, env


def _assert_host_side(output, ro, rw):
    assert f"Warning: readonly mount source {ro} does not exist, skipping" in output, (
        f"expected the skip warning for {ro}, got:\n{output}"
    )
    assert not ro.exists(), f"a readonly mount must not create its missing source {ro}"
    assert not ro.parent.exists(), f"a readonly mount must not create parents of {ro}"
    assert rw.is_dir(), f"a writable mount should create its missing source {rw}"
    mode = stat.S_IMODE(rw.stat().st_mode)
    assert mode == 0o755, f"{rw} should be created with mode 0755, got {oct(mode)}"


def test_shell_mount_missing_source(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    coi shell skips a readonly mount with a missing source and creates a
    writable one.

    Flow:
    1. Trusted config with a readonly and a writable mount, both sources missing
    2. coi shell --background (dummy tool): it starts
    3. Check the warning, the host paths, and which mount points exist in the
       container
    """
    ro, rw, env = _config(tmp_path)
    env["COI_USE_DUMMY"] = "1"
    container_name = calculate_container_name(workspace_dir, 1)

    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"coi shell should start despite a missing readonly source:\n{output}"
    )

    _assert_host_side(output, ro, rw)

    check = subprocess.run(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "sh",
            "-c",
            "test -d /mnt/missing-rw && ! test -e /mnt/missing-ro",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert check.returncode == 0, (
        "the container should have /mnt/missing-rw and no /mnt/missing-ro.\n"
        f"stdout: {check.stdout}\nstderr: {check.stderr}"
    )


def test_run_mount_missing_source(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """
    coi run skips a readonly mount with a missing source and creates a writable
    one.

    Flow:
    1. Trusted config with a readonly and a writable mount, both sources missing
    2. coi run checks the mount points inside the container
    3. Check the warning and the host paths
    """
    ro, rw, env = _config(tmp_path)

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "test -d /mnt/missing-rw && ! test -e /mnt/missing-ro && echo MOUNTS-OK",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
        cwd=workspace_dir,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"coi run should succeed despite a missing readonly source:\n{output}"
    )
    assert "MOUNTS-OK" in result.stdout, (
        f"the container should have /mnt/missing-rw and no /mnt/missing-ro:\n{output}"
    )

    _assert_host_side(output, ro, rw)
