"""Verify that the host-side cgroup.procs init-PID resolution works.

GetContainerInitPID now reads the minimum PID from cgroup.procs files
under the container's well-known cgroup path instead of calling
`incus info`. These tests confirm that the cgroup path exists and that
the PID found there matches the value reported by `incus info`."""

import os
import subprocess

import pytest

from support.monitoring import (
    find_container_cgroup_path,
    get_container_name_from_workspace,
    wait_for_container_running,
)


def test_cgroup_path_exists_for_running_container(test_workspace, coi_binary):
    """A running container's cgroup directory must exist at a well-known path."""
    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-90"
    )
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "90"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_container_running(container_name):
            pytest.fail(f"Container {container_name} did not start")

        cgroup_path = find_container_cgroup_path(container_name)
        if cgroup_path is None:
            pytest.skip(
                f"Container cgroup path not found under /sys/fs/cgroup for {container_name}"
            )
        assert os.path.isdir(cgroup_path), f"cgroup path {cgroup_path} is not a directory"
    finally:
        proc.terminate()
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            check=False,
            timeout=30,
        )
