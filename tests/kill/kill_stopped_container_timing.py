"""
Test for coi kill - removing a stopped container makes no IP lookups.

Tests that:
1. Launch a container and stop it
2. Kill it with COI_TIMING_DEBUG_JSON set
3. The kill read the container state once, made no JSON IP lookup and no stop
4. Verify it's deleted
"""

import json
import os
import subprocess

from support.helpers import calculate_container_name


def test_kill_stopped_container_skips_ip_lookup(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """coi kill on a stopped container reads its state once and never polls for an IP."""
    container_name = calculate_container_name(workspace_dir, 1)

    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"

    result = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"Container stop should succeed. stderr: {result.stderr}"

    json_path = tmp_path / "kill-timing.json"
    env = os.environ.copy()
    env.pop("COI_TIMING_DEBUG", None)
    env["COI_TIMING_DEBUG_JSON"] = str(json_path)

    result = subprocess.run(
        [coi_binary, "kill", container_name],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, f"Kill should succeed. stderr: {result.stderr}"

    data = json.loads(json_path.read_text())
    incus_calls = [r["label"] for r in data["records"] if r["category"] == "incus"]

    json_lists = [c for c in incus_calls if c.startswith("list") and "--format=json" in c]
    assert not json_lists, f"kill polled a stopped container for its IP: {json_lists}"
    lists = [c for c in incus_calls if c.startswith("list") and container_name in c]
    assert len(lists) == 1, f"kill should read the container state once, got: {lists}"
    stops = [c for c in incus_calls if c.startswith("stop")]
    assert not stops, f"kill stopped an already stopped container: {stops}"

    result = subprocess.run(
        [coi_binary, "container", "exists", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0, f"Container should not exist after kill. stdout: {result.stdout}"
