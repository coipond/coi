"""
Test for coi shutdown - usage errors and a partially missing target list.

Tests that:
1. --slot and --all with a container name exit 2 and leave the container
   running, for coi shutdown and its alias coi close
2. A missing target among real ones exits 1 and names it, after shutting
   down the rest
3. A repeated target is acted on once
"""

import subprocess
import time

from support.helpers import calculate_container_name, incus_status


def test_shutdown_partial_and_usage_errors(coi_binary, cleanup_containers, workspace_dir):
    """
    Test coi shutdown / coi close usage errors and a partial shutdown.

    Flow:
    1. Launch two containers
    2. Run shutdown and close with --all <name> and --slot 2 <name>; verify
       exit 2, still running
    3. Run shutdown --force <first> <first> <missing>; verify exit 1,
       <missing> named, <first> shut down once and deleted
    4. Run close --force <second> <missing>; verify the same
    """
    first = calculate_container_name(workspace_dir, 1)
    missing_name = calculate_container_name(workspace_dir, 2)
    second = calculate_container_name(workspace_dir, 3)

    # === Phase 1: Launch containers ===

    for container_name in (first, second):
        result = subprocess.run(
            [coi_binary, "container", "launch", "coi-default", container_name],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    time.sleep(3)

    # === Phase 2: Usage errors touch no container ===

    # No --force: should --all ever act again, the prompt reads "n" and stops nothing.
    for command in ("shutdown", "close"):
        for argv in (["--all", first], ["--slot", "2", first]):
            result = subprocess.run(
                [coi_binary, command, *argv],
                input="n\n",
                capture_output=True,
                text=True,
                timeout=60,
            )
            # Exit code 2 (usage error)
            assert result.returncode == 2, (
                f"{command} {' '.join(argv)} should exit 2, got {result.returncode}. "
                f"Output:\n{result.stdout + result.stderr}"
            )
            for container_name in (first, second):
                assert incus_status(container_name) == "RUNNING", (
                    f"{command} {' '.join(argv)} must not touch {container_name}"
                )

    # === Phase 3: Partial shutdown with a repeated target ===

    result = subprocess.run(
        [coi_binary, "shutdown", "--force", first, first, missing_name],
        capture_output=True,
        text=True,
        timeout=180,
    )
    combined_output = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"Partial shutdown should exit 1, got {result.returncode}. Output:\n{combined_output}"
    )
    assert f"failed to shut down 1 of 2 container(s): {missing_name}" in combined_output, (
        f"Should name the missing container out of 2 unique targets. Got:\n{combined_output}"
    )
    assert combined_output.count(f"Shutting down container {first} ") == 1, (
        f"Repeated target should be shut down once. Got:\n{combined_output}"
    )

    # === Phase 4: Partial close ===

    result = subprocess.run(
        [coi_binary, "close", "--force", second, missing_name],
        capture_output=True,
        text=True,
        timeout=180,
    )
    combined_output = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"Partial close should exit 1, got {result.returncode}. Output:\n{combined_output}"
    )
    assert f"failed to shut down 1 of 2 container(s): {missing_name}" in combined_output, (
        f"Should name the missing container. Got:\n{combined_output}"
    )

    for container_name in (first, second):
        result = subprocess.run(
            [coi_binary, "container", "exists", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, f"{container_name} should be deleted despite the missing one"
