"""
Test for coi shell - the hardened profile runs without sudo for the code user.

Tests that:
1. `sudo -n true` fails in a `coi shell --profile hardened` session
2. `sudo -n sysctl -w net.ipv6.conf.all.disable_ipv6=0` fails
3. writing /etc/crontab fails, with sudo and without, and leaves it unchanged
4. ~/SANDBOX_CONTEXT.json reports sudo_available and docker_available false
5. `close` says there is no sudo instead of failing with a sudo error
"""

import subprocess

from pexpect import EOF, TIMEOUT

from support.helpers import (
    NO_SUDO_PROBE,
    NO_SUDO_PROBE_MARKERS,
    calculate_container_name,
    exec_in,
    spawn_coi,
    wait_for_container_ready,
    wait_for_prompt,
)

CONTEXT_PROBE = """
test -f ~/SANDBOX_CONTEXT.json || exit 1
grep -q '"sudo_available": false' ~/SANDBOX_CONTEXT.json && echo NO_SUDO_IN_CONTEXT
grep -q '"docker_available": false' ~/SANDBOX_CONTEXT.json && echo NO_DOCKER_IN_CONTEXT
true
"""


def test_hardened_shell_no_sudo(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a hardened shell session gives the code user no sudo.

    Flow:
    1. Start coi shell --profile hardened with the dummy tool
    2. Run the probe script and read the context JSON as the code user
    3. Verify every sudo use and the crontab write were refused
    4. Run close and verify it explains the missing sudo
    """
    container_name = calculate_container_name(workspace_dir, 1)
    child = spawn_coi(
        coi_binary,
        ["shell", "--profile", "hardened"],
        cwd=workspace_dir,
        env={"COI_USE_DUMMY": "1"},
        timeout=120,
    )
    try:
        wait_for_container_ready(child, timeout=90)
        wait_for_prompt(child, timeout=90)

        rc, out = exec_in(coi_binary, container_name, NO_SUDO_PROBE, user=1000)
        assert rc == 0, f"probe should run:\n{out}"
        for want in NO_SUDO_PROBE_MARKERS:
            assert want in out, f"Missing {want}. Output:\n{out}"

        rc, out = exec_in(coi_binary, container_name, CONTEXT_PROBE, user=1000)
        assert rc == 0, f"~/SANDBOX_CONTEXT.json should exist:\n{out}"
        for want in ("NO_SUDO_IN_CONTEXT", "NO_DOCKER_IN_CONTEXT"):
            assert want in out, f"Missing {want}. Output:\n{out}"

        rc, out = exec_in(coi_binary, container_name, "close", user=1000)
        assert rc != 0, f"close cannot power off without sudo:\n{out}"
        assert "no sudo in this session" in out and "coi shutdown" in out, (
            f"close should explain the missing sudo:\n{out}"
        )
    finally:
        child.sendline("exit")
        try:
            child.expect(EOF, timeout=30)
        except TIMEOUT:
            pass
        try:
            child.close(force=False)
        except Exception:
            child.close(force=True)
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
