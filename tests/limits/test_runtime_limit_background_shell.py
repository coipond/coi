"""`[limits.runtime] max_duration` stops a `coi shell --background` session.

A background session is the unattended case the runtime limit exists for, so
the container must be stopped once the limit passes, even though the
`coi shell` command itself has already returned.
"""

import json
import subprocess
import time
from pathlib import Path

from support.helpers import calculate_container_name


def _running(name):
    result = subprocess.run(
        ["incus", "list", "--format=json"], capture_output=True, text=True, timeout=30
    )
    if result.returncode != 0:
        return True  # unknown: don't claim it stopped
    return any(
        c.get("name") == name and c.get("status") == "Running" for c in json.loads(result.stdout)
    )


def test_runtime_limit_stops_background_shell(coi_binary, workspace_dir, cleanup_containers):
    coi_dir = Path(workspace_dir) / ".coi"
    coi_dir.mkdir(exist_ok=True)
    (coi_dir / "config.toml").write_text('[limits.runtime]\nmax_duration = "15s"\n')
    name = calculate_container_name(workspace_dir, 1)

    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    assert _running(name), f"{name} should be running right after the background start"

    # 15s limit + a graceful stop (~10s) + slack for a loaded runner.
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and _running(name):
        time.sleep(2)
    assert not _running(name), (
        f"{name} is still running 90s after a 15s runtime limit in a background session"
    )
