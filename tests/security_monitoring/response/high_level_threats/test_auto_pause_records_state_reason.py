"""Test for coi list - the reason coi froze a container.

Tests that:
1. A HIGH threat with auto_pause_on_high=true freezes the container, and
   `coi list --json` then shows state_reason "monitor:<threat title>" and a
   UTC RFC 3339 state_reason_at.
2. The text output shows the reason.
3. `coi unfreeze` clears both fields.
"""

import json
import subprocess
import time
from datetime import datetime, timedelta

from support.monitoring import (
    append_sudoers_line,
    get_container_state,
    get_threat_events,
    monitored_shell,
)

SLOT = 3

CONFIG = """
[network]
mode = "open"

[monitoring]
enabled = true
auto_pause_on_high = true
auto_kill_on_critical = false
poll_interval_sec = 1
file_read_threshold_mb = 500
file_read_rate_mb_per_sec = 1000
process_count_threshold = 9999
process_spawn_rate_threshold = 9999
"""


def _list_item(coi_binary, container_name):
    result = subprocess.run(
        [coi_binary, "list", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    items = json.loads(result.stdout)["active_containers"]
    match = [c for c in items if c["name"] == container_name]
    assert match, f"{container_name} not in coi list: {result.stdout}"
    return match[0]


def test_auto_pause_records_state_reason(test_workspace, coi_binary):
    with monitored_shell(test_workspace, coi_binary, SLOT, CONFIG) as (container_name, _):
        start = datetime.now().astimezone() - timedelta(seconds=1)
        append_sudoers_line(container_name)

        # The reason is written right after `incus pause`; poll for it. The
        # LogWatcher can miss a line written during its start, so re-append
        # while the container still runs.
        item = {}
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            item = _list_item(coi_binary, container_name)
            if item["state_reason"]:
                break
            if item["status"] == "Running":
                append_sudoers_line(container_name)
            time.sleep(2)

        events = get_threat_events(container_name)
        paused = [e for e in events if e.get("action") == "paused"]
        assert get_container_state(container_name) == "Frozen", f"Not frozen. Events: {events}"
        assert paused, f"Expected an action='paused' audit event. Events: {events}"
        assert item["state_reason"] == "monitor:" + paused[0]["title"], item
        at = item["state_reason_at"]
        assert at.endswith("Z"), item
        assert datetime.fromisoformat(at.replace("Z", "+00:00")) >= start, item

        text = subprocess.run(
            [coi_binary, "list"], capture_output=True, text=True, timeout=30, check=False
        )
        assert f"Reason: {item['state_reason']} ({at})" in text.stdout, text.stdout

        result = subprocess.run(
            [coi_binary, "unfreeze", container_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        item = _list_item(coi_binary, container_name)
        assert item["state_reason"] == "" and item["state_reason_at"] == "", item
