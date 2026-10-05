"""Verify that the host-side cgroup.procs init-PID resolution works.

GetContainerInitPID now reads the minimum PID from cgroup.procs files
under the container's well-known cgroup path instead of calling
`incus info`. These tests confirm that the cgroup path exists and that
the PID found there matches the value reported by `incus info`."""

import subprocess

import pytest

from support.monitoring import (
    find_container_cgroup_path,
    get_container_name_from_workspace,
    wait_for_container_running,
)


def test_cgroup_procs_pid_matches_incus_info(test_workspace, coi_binary):
    """The minimum PID in cgroup.procs must match the PID reported by incus info."""
    import glob

    container_name = (
        get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-91"
    )
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "91"],
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

        # Collect minimum PID from all cgroup.procs files in the tree.
        procs_files = glob.glob(f"{cgroup_path}/**/cgroup.procs", recursive=True)
        procs_files.append(f"{cgroup_path}/cgroup.procs")
        all_pids = []
        for pf in procs_files:
            try:
                with open(pf) as fh:
                    for line in fh:
                        line = line.strip()
                        if line.isdigit():
                            all_pids.append(int(line))
            except OSError:
                pass
        assert all_pids, f"No PIDs found under {cgroup_path}"
        cgroup_pid = min(all_pids)

        # Get PID from incus info.
        result = subprocess.run(
            ["incus", "info", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"incus info failed: {result.stderr}"
        incus_pid = None
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("PID:") or stripped.startswith("Pid:"):
                parts = stripped.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    incus_pid = int(parts[1])
                    break
        assert incus_pid is not None, (
            f"Could not parse PID from incus info output:\n{result.stdout}"
        )

        assert cgroup_pid == incus_pid, (
            f"cgroup.procs min PID {cgroup_pid} != incus info PID {incus_pid}"
        )
    finally:
        proc.terminate()
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            check=False,
            timeout=30,
        )
