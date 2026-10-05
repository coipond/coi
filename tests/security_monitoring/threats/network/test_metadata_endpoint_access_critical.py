"""Test network-based threat detection."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    poll_network_threats,
    wait_for_container_running,
)


def test_metadata_endpoint_access_critical(test_workspace, enable_monitoring, coi_binary):
    """Test connection to cloud metadata endpoint triggers CRITICAL threat."""
    metadata_script = Path(test_workspace) / "metadata.py"
    metadata_script.write_text(
        """#!/usr/bin/env python3
import subprocess
import time

# Try to access cloud metadata endpoint (AWS/GCP/Azure)
subprocess.Popen(
    ["timeout", "5", "curl", "-s", "http://169.254.169.254/latest/meta-data/"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

time.sleep(60)
"""
    )
    metadata_script.chmod(0o755)

    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", str(test_workspace), "--slot", "9"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(str(test_workspace)).rsplit("-", 1)[0] + "-9"

    if not wait_for_container_running(container_name):
        proc.terminate()
        pytest.fail(f"Container {container_name} did not start")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Execute metadata access attempt
    subprocess.Popen(
        ["incus", "exec", container_name, "--", "python3", "/workspace/metadata.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        # Best-effort connection (the metadata endpoint is blocked, so the SYN
        # may never establish): poll, and skip honestly if nothing is detected
        # rather than pass vacuously. test_network_connection_detection.py has
        # the reliable unconditional metadata-endpoint coverage.
        network_threats = poll_network_threats(container_name)
        if not network_threats:
            pytest.skip(
                "no network threat detected within the poll window (best-effort "
                "metadata connection); see test_network_connection_detection.py"
            )
        critical = [e for e in network_threats if e.get("level") == "critical"]
        assert len(critical) > 0, "Metadata endpoint access should be CRITICAL"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
