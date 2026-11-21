"""
Test for coi kill - usage errors and a partially missing target list.

Tests that:
1. --slot and --all with a container name exit 2 and leave the container running
2. A missing target among real ones exits 1 and names it, after killing the rest
3. A repeated target is acted on once
"""

import subprocess
import time

from support.helpers import calculate_container_name, incus_status


def test_kill_partial_and_usage_errors(coi_binary, cleanup_containers, workspace_dir):
    """
    Test coi kill usage errors and a partial kill.

    Flow:
    1. Launch a container
    2. Run kill --all <name> and kill --slot 2 <name>; verify exit 2, still running
    3. Run kill --force <name> <name> <missing>; verify exit 1, <missing> named,
       <name> killed once and deleted
    """
    container_name = calculate_container_name(workspace_dir, 1)
    missing_name = calculate_container_name(workspace_dir, 2)

    # === Phase 1: Launch container ===

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # === Phase 2: Usage errors touch no container ===

    # No --force: should --all ever act again, the prompt reads "n" and kills nothing.
    for argv in (["--all", container_name], ["--slot", "2", container_name]):
        result = subprocess.run(
            [coi_binary, "kill", *argv],
            input="n\n",
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Exit code 2 (usage error)
        assert result.returncode == 2, (
            f"kill {' '.join(argv)} should exit 2, got {result.returncode}. "
            f"Output:\n{result.stdout + result.stderr}"
        )
        assert incus_status(container_name) == "RUNNING", (
            f"kill {' '.join(argv)} must not touch {container_name}"
        )

    # === Phase 3: Partial kill with a repeated target ===

    result = subprocess.run(
        [coi_binary, "kill", "--force", container_name, container_name, missing_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined_output = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"Partial kill should exit 1, got {result.returncode}. Output:\n{combined_output}"
    )
    assert f"failed to kill 1 of 2 container(s): {missing_name}" in combined_output, (
        f"Should name the missing container out of 2 unique targets. Got:\n{combined_output}"
    )
    assert combined_output.count(f"Killing container {container_name}...") == 1, (
        f"Repeated target should be killed once. Got:\n{combined_output}"
    )

    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, f"{container_name} should be deleted despite the missing one"
