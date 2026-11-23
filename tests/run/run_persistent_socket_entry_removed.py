"""
Test for coi run - a reused persistent container drops the socket of a
[[sockets]] entry removed from config.

Tests that:
1. A first run with a [[sockets]] entry reaches the host socket through its
   container path (a host ssh-agent: ssh-add -l lists the test key)
2. A second run in the same persistent container without the entry can't:
   ssh-add -l through that path fails to connect, and its env var is unset
3. The container no longer has the entry's socket-0 device
"""

import shutil
import subprocess

import pytest

from support.helpers import (
    calculate_container_name,
    container_device_get,
    host_ssh_agent,
    write_trusted_coi_config,
)

KEY_COMMENT = "coi-socket-entry-removed-test"
CONTAINER_SOCK = "/tmp/agent-fwd.sock"
# ssh-add -l exits 2 when it can't connect to an agent.
SOCKET_PROBE = f"echo sock=[$AGENT_FWD_SOCK]; SSH_AUTH_SOCK={CONTAINER_SOCK} ssh-add -l; echo rc=$?"


def _run_probe(coi_binary, workspace_dir, slot, env):
    return subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--slot",
            str(slot),
            "--",
            "sh",
            "-c",
            SOCKET_PROBE,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )


@pytest.mark.skipif(shutil.which("ssh-agent") is None, reason="ssh-agent not installed on host")
def test_run_persistent_socket_entry_removed(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Start a host ssh-agent with a throwaway key
    2. coi run in a persistent container forwarding it as a [[sockets]] entry
    3. coi run in the same container with the entry removed: socket unreachable
    4. The socket-0 device is gone from the container
    """
    slot = 7
    container_name = calculate_container_name(workspace_dir, slot)

    with host_ssh_agent(KEY_COMMENT) as agent_sock:
        with_entry = write_trusted_coi_config(
            "[container]\npersistent = true\n\n"
            "[[sockets]]\n"
            f'host = "{agent_sock}"\n'
            f'container = "{CONTAINER_SOCK}"\n'
            'env = "AGENT_FWD_SOCK"\n'
        )
        first = _run_probe(coi_binary, workspace_dir, slot, with_entry)
        assert first.returncode == 0, f"first run should succeed. stderr: {first.stderr}"
        assert KEY_COMMENT in first.stdout and "rc=0" in first.stdout, (
            f"first run should reach the host socket. stdout:\n{first.stdout}\nstderr:\n{first.stderr}"
        )
        assert f"sock=[{CONTAINER_SOCK}]" in first.stdout, first.stdout

        # The host socket stays live at the same path: only config changes.
        without_entry = write_trusted_coi_config("[container]\npersistent = true\n")
        second = _run_probe(coi_binary, workspace_dir, slot, without_entry)
        assert second.returncode == 0, f"second run should succeed. stderr: {second.stderr}"
        assert "existing" in second.stderr.lower() or "restart" in second.stderr.lower(), (
            f"second run should reuse the persistent container. stderr:\n{second.stderr}"
        )
        assert KEY_COMMENT not in second.stdout and "rc=2" in second.stdout, (
            f"removed socket entry must be unreachable. stdout:\n{second.stdout}"
        )
        assert "sock=[]" in second.stdout, f"AGENT_FWD_SOCK must be unset. stdout:\n{second.stdout}"

    assert container_device_get(container_name, "socket-0", "type") is None, (
        "the socket-0 device should be removed from the reused container"
    )
