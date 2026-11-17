"""
Test for coi clean --orphans - removes a master-less veth that coi recorded.

Tests that:
1. Create a plain veth pair with ip link add and record one end as a coi
   container's veth (~/.coi/veths/<name>)
2. Run coi clean --orphans --force
3. Verify the recorded end is gone and its record is dropped
"""

import os
import secrets
import subprocess
from pathlib import Path


def test_clean_orphans_removes_recorded_veth(coi_binary):
    a = f"veth{secrets.token_hex(4)}"
    b = f"veth{secrets.token_hex(4)}"
    subprocess.run(
        ["sudo", "-n", "ip", "link", "add", a, "type", "veth", "peer", "name", b],
        check=True,
        timeout=30,
    )
    record = Path.home() / ".coi" / "veths" / a
    record.parent.mkdir(parents=True, exist_ok=True)
    record.touch()
    try:
        result = subprocess.run(
            [coi_binary, "clean", "--orphans", "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Clean --orphans should succeed. stderr: {result.stderr}"
        assert f"Removing orphaned veth: {a}" in result.stdout + result.stderr, (
            f"clean --orphans should remove {a}:\n{result.stdout}{result.stderr}"
        )
        assert not os.path.exists(f"/sys/class/net/{a}"), f"{a} should be deleted"
        assert not record.exists(), f"the record of {a} should be dropped"
    finally:
        record.unlink(missing_ok=True)
        if os.path.exists(f"/sys/class/net/{a}"):
            subprocess.run(["sudo", "-n", "ip", "link", "delete", a], timeout=30)
