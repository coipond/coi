"""A nearly full /tmp raises a WARNING carrying disk-space evidence, end to
end: the monitor measures the real container's /tmp and writes the event to
the audit log."""

import subprocess
import time

from support.monitoring import (
    cleanup_container,
    coi_session_logs,
    disk_space_warnings,
    fill_tmp,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    tmp_size_mb,
    wait_for_container_running,
)


def test_tmp_over_80_percent_warns_with_disk_space_evidence(
    test_workspace, enable_monitoring_small_tmp, coi_binary
):
    proc = subprocess.Popen(
        [coi_binary, "shell", "--workspace", test_workspace, "--slot", "40"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-40"
    try:
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )
        total_mb = tmp_size_mb(container_name)
        assert 0 < total_mb <= 64, f"/tmp should be the 64MiB tmpfs, got {total_mb}MB"

        # Half full: below the 80% threshold, no warning across several polls.
        fill_tmp(container_name, "fill_half", total_mb // 2)
        time.sleep(8)
        assert disk_space_warnings(container_name) == [], (
            "a half-full /tmp must not raise a disk-space warning"
        )

        # ~90% full: the warning appears, with the measured usage as evidence.
        fill_tmp(container_name, "fill_more", total_mb * 2 // 5)
        warnings = []
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and not warnings:
            time.sleep(1)
            warnings = disk_space_warnings(container_name)

        assert warnings, (
            "expected a disk-space WARNING once /tmp is ~90% full; "
            f"events: {get_threat_events(container_name)}{coi_session_logs(container_name)}"
        )
        warning = warnings[0]
        disk = warning["evidence"]["disk_space"]
        assert "disk space" in warning.get("title", "").lower(), warning
        assert disk["tmp_used_percent"] > 80, disk
        assert 0 < disk["tmp_total_mb"] <= 64, disk
        assert 0 < disk["tmp_used_mb"] <= disk["tmp_total_mb"], disk

        # A warning only alerts: the container keeps running.
        assert get_container_state(container_name) == "Running"
    finally:
        proc.terminate()
        cleanup_container(container_name, coi_binary)
