"""
Test for coi clean --orphans - keeps a master-less veth that coi did not make.

Tests that:
1. Create a plain veth pair with ip link add (no bridge master, like a CNI
   or manual netns pair)
2. Run coi clean --orphans --force
3. Verify both ends still exist
"""

import os
import secrets
import subprocess


def test_clean_orphans_keeps_unrecorded_veth(coi_binary):
    a = f"veth{secrets.token_hex(4)}"
    b = f"veth{secrets.token_hex(4)}"
    subprocess.run(
        ["sudo", "-n", "ip", "link", "add", a, "type", "veth", "peer", "name", b],
        check=True,
        timeout=30,
    )
    try:
        result = subprocess.run(
            [coi_binary, "clean", "--orphans", "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Clean --orphans should succeed. stderr: {result.stderr}"
        combined_output = result.stdout + result.stderr
        for veth in (a, b):
            assert veth not in combined_output, (
                f"clean --orphans must not name {veth}:\n{combined_output}"
            )
            assert os.path.exists(f"/sys/class/net/{veth}"), (
                f"coi clean --orphans deleted the unrecorded veth {veth}"
            )
    finally:
        subprocess.run(["sudo", "-n", "ip", "link", "delete", a], timeout=30)
