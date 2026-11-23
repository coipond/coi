"""
Test for coi run - a reused persistent container drops the SSH agent forward
once [ssh] forward_agent is turned off.

Tests that:
1. A first run with forward_agent = true reaches the host agent through
   /tmp/ssh-agent.sock (ssh-add -l lists the test key)
2. A second run in the same persistent container with forward_agent = false
   can't: ssh-add -l through /tmp/ssh-agent.sock fails to connect, and
   SSH_AUTH_SOCK is unset
3. The container no longer has the ssh-agent device
"""

import shutil

import pytest

from support.helpers import (
    calculate_container_name,
    container_device_get,
    host_ssh_agent,
    run_coi_in_workspace,
    write_trusted_coi_config,
)

KEY_COMMENT = "coi-agent-forward-off-test"
# ssh-add -l exits 2 when it can't connect to an agent.
AGENT_PROBE = "echo sock=[$SSH_AUTH_SOCK]; SSH_AUTH_SOCK=/tmp/ssh-agent.sock ssh-add -l; echo rc=$?"


@pytest.mark.skipif(shutil.which("ssh-agent") is None, reason="ssh-agent not installed on host")
def test_run_persistent_agent_forward_turned_off(coi_binary, cleanup_containers, workspace_dir):
    """
    Flow:
    1. Start a host ssh-agent with a throwaway key
    2. coi run in a persistent container with forward_agent = true: key listed
    3. coi run in the same container with forward_agent = false: no agent
    4. The ssh-agent device is gone from the container
    """
    slot = 6
    container_name = calculate_container_name(workspace_dir, slot)

    with host_ssh_agent(KEY_COMMENT) as agent_sock:
        on = write_trusted_coi_config(
            "[container]\npersistent = true\n\n[ssh]\nforward_agent = true\n"
        )
        on["SSH_AUTH_SOCK"] = agent_sock
        first = run_coi_in_workspace(
            coi_binary, workspace_dir, ["sh", "-c", AGENT_PROBE], env=on, timeout=180, slot=slot
        )
        assert first.returncode == 0, f"first run should succeed. stderr: {first.stderr}"
        assert KEY_COMMENT in first.stdout and "rc=0" in first.stdout, (
            f"first run should reach the host agent. stdout:\n{first.stdout}\nstderr:\n{first.stderr}"
        )

        # The host agent stays live at the same path: only config changes.
        off = write_trusted_coi_config(
            "[container]\npersistent = true\n\n[ssh]\nforward_agent = false\n"
        )
        off["SSH_AUTH_SOCK"] = agent_sock
        second = run_coi_in_workspace(
            coi_binary, workspace_dir, ["sh", "-c", AGENT_PROBE], env=off, timeout=180, slot=slot
        )
        assert second.returncode == 0, f"second run should succeed. stderr: {second.stderr}"
        assert "existing" in second.stderr.lower() or "restart" in second.stderr.lower(), (
            f"second run should reuse the persistent container. stderr:\n{second.stderr}"
        )
        assert KEY_COMMENT not in second.stdout and "rc=2" in second.stdout, (
            f"host agent must be unreachable with forward_agent off. stdout:\n{second.stdout}"
        )
        assert "sock=[]" in second.stdout, f"SSH_AUTH_SOCK must be unset. stdout:\n{second.stdout}"

    assert container_device_get(container_name, "ssh-agent", "type") is None, (
        "the ssh-agent device should be removed from the reused container"
    )
