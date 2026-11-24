"""
Test for coi run - the hardened profile runs without sudo for the code user.

Tests that:
1. `sudo -n true` fails
2. `sudo -n sysctl -w net.ipv6.conf.all.disable_ipv6=0` fails
3. writing /etc/crontab fails, with sudo and without, and leaves it unchanged
"""

import subprocess

from support.helpers import NO_SUDO_PROBE, NO_SUDO_PROBE_MARKERS


def test_run_hardened_no_sudo(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a hardened session gives the code user no sudo.

    Flow:
    1. Run the probe script with coi run --profile hardened
    2. Verify every sudo use and the crontab write were refused
    """
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--profile",
            "hardened",
            "--",
            "sh",
            "-c",
            NO_SUDO_PROBE,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode == 0, f"Run should succeed. Output:\n{combined_output}"

    for want in NO_SUDO_PROBE_MARKERS:
        assert want in combined_output, f"Missing {want}. Output:\n{combined_output}"
