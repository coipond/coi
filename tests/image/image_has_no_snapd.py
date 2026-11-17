"""
Test that the coi image ships without snapd.

The Ubuntu cloud image ships snapd, which contacts api.snapcraft.io as soon as
the container boots, before coi sets up the firewall. In restricted and
allowlist modes the security monitor flagged that connection and paused the
container. The image build removes snapd and pins it so it is not installed
again as a dependency.
"""

import subprocess

from support.helpers import calculate_container_name, exec_in


def test_image_has_no_snapd(coi_binary, cleanup_containers, workspace_dir):
    """snapd is not installed, has no running service, and apt will not install it."""
    container_name = calculate_container_name(workspace_dir, 1)
    launch = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert launch.returncode == 0, f"launch should succeed. stderr: {launch.stderr}"
    try:
        rc, out = exec_in(coi_binary, container_name, "dpkg -s snapd")
        assert rc != 0, f"snapd should not be installed: {out}"

        rc, out = exec_in(coi_binary, container_name, "command -v snap || pgrep -x snapd")
        assert rc != 0, f"no snap command or snapd process expected: {out}"

        # The image has no apt lists, so check the pin itself.
        rc, out = exec_in(coi_binary, container_name, "cat /etc/apt/preferences.d/no-snapd")
        assert rc == 0 and "Package: snapd" in out and "Pin-Priority: -10" in out, (
            f"apt should pin snapd at -10: {out}"
        )
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )
