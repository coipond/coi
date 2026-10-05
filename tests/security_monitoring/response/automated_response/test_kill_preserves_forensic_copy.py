"""Test automated threat response system."""

import subprocess
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    forensic_copies,
    trigger_critical_and_wait_kill,
)


def test_kill_preserves_forensic_copy(test_workspace, enable_monitoring_forensics, coi_binary):
    """An auto-kill fires exactly when the container state is most worth
    investigating — the responder must preserve a stopped forensic copy
    BEFORE the (ephemeral) container is stopped and deleted, so the
    evidence survives the response ("snapshot state for investigation
    before deactivating", Trail of Bits). Default-on behavior."""
    proc, container_name, killed = trigger_critical_and_wait_kill(
        coi_binary, test_workspace, slot=4, kill_timeout=120
    )
    try:
        copies = forensic_copies(container_name)

        # The forensic copy is made BEFORE the stop and delete, so this kill
        # takes longer than a plain one (hence the longer kill_timeout above).
        if not copies or not killed:
            logs = ""
            for log in (Path.home() / ".coi" / "logs").glob(f"{container_name}*"):
                try:
                    logs += f"\n--- {log} ---\n" + log.read_text()[-3000:]
                except OSError:
                    pass
            pytest.fail(
                f"auto-kill should leave a forensic copy (killed={killed}, "
                f"copies={copies}). Responder logs:{logs}"
            )
        for row in copies:
            assert "STOPPED" in row.upper(), f"forensic copy should be stopped: {row}"
    finally:
        proc.terminate()
        for row in forensic_copies(container_name):
            name = row.split(",")[0]
            subprocess.run(["incus", "delete", "--force", name], capture_output=True, timeout=60)
        cleanup_container(container_name, coi_binary)
