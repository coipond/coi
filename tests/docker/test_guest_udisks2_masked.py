"""
Tests that the coi image masks udisks2.service (#706).

udisks2 keeps /proc/swaps open, which Incus backs with lxcfs on the host. A
running udisksd wedges when the host suspends and blocks the suspend, so the
image disables and masks the unit. This test pins down that:

1. udisks2.service is masked
2. udisks2.service is not running
"""

import re
import subprocess
import time

from support.helpers import calculate_container_name


def test_guest_udisks2_masked(coi_binary, cleanup_containers, workspace_dir):
    """udisks2.service is masked and not running in a container from the default image."""
    container_name = calculate_container_name(workspace_dir, 1)

    # === Phase 1: Launch container ===
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"
    time.sleep(5)

    # === Phase 2: The unit is masked ===

    # is-enabled exits non-zero for a masked unit, so only its output matters.
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "systemctl",
            "is-enabled",
            "udisks2.service",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = result.stdout + result.stderr
    assert re.search(r"^masked$", output, re.MULTILINE), (
        f"udisks2.service should be masked in the image. output: {output}"
    )

    # === Phase 3: The unit is not running ===
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "systemctl",
            "is-active",
            "udisks2.service",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    output = result.stdout + result.stderr
    assert not re.search(r"^active$", output, re.MULTILINE), (
        f"udisks2.service should not be running. output: {output}"
    )

    # === Cleanup ===
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
