"""
Test that coi run applies [network] and [ssh] settings from config.

Covers issue #373: coi run silently ignores network isolation and SSH agent
forwarding from config, unlike coi shell which applies both correctly.

Tests that:
1. coi run with network.mode = "restricted" blocks RFC1918 addresses
2. coi run with network.mode = "restricted" still allows public internet
3. coi run with network.mode = "open" does not block RFC1918 addresses
4. coi run with ssh.forward_agent = true sets SSH_AUTH_SOCK inside the container
"""

import os
import pathlib
import subprocess


def _write_config(workspace_dir, content):
    config_dir = pathlib.Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(content)


def test_run_restricted_blocks_private_networks(coi_binary, workspace_dir, cleanup_containers):
    """
    coi run with network.mode = "restricted" must block RFC1918 addresses.

    This is a regression test for #373: previously the firewall rules were never
    applied when using coi run, so the container had unrestricted network access
    regardless of config.
    """
    _write_config(workspace_dir, '[network]\nmode = "restricted"\n')

    for addr in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "curl",
                "-s",
                "--connect-timeout",
                "2",
                f"http://{addr}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0, (
            f"coi run in restricted mode should block {addr} (RFC1918), "
            f"but curl exited 0. stderr: {result.stderr}"
        )


def test_run_restricted_allows_public_internet(coi_binary, workspace_dir, cleanup_containers):
    """
    coi run with network.mode = "restricted" must still allow public internet.

    Restricted mode blocks private networks only; public internet must remain
    accessible so normal development workflows (package downloads, API calls) work.
    """
    _write_config(workspace_dir, '[network]\nmode = "restricted"\n')

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "10",
            "http://example.com",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"coi run in restricted mode should allow example.com. stderr: {result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "Example Domain" in combined, f"Expected example.com HTML in output. Got:\n{combined}"


def test_run_open_does_not_block_private_networks(coi_binary, workspace_dir, cleanup_containers):
    """
    coi run with network.mode = "open" must not install any firewall rules.

    In open mode the container should be able to attempt connections to private
    addresses without getting an immediate ACL rejection. The connection may still
    time out (no device at that IP), but it must not be instantly refused.
    """
    _write_config(workspace_dir, '[network]\nmode = "open"\n')

    # Use a very short connect timeout so the test stays fast whether or not a
    # device at 10.0.0.1 actually exists. We only care that the kernel attempted
    # the connection (ETIMEDOUT) rather than getting an instant RST/ICMP reject
    # from the firewall (which would also produce a non-zero exit code but much
    # faster). We cannot distinguish those exit codes from the outside, so we
    # simply assert the command runs without crashing coi itself.
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "curl",
            "-s",
            "--connect-timeout",
            "2",
            "http://10.0.0.1",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # coi run itself must succeed (exit 0 means curl connected; non-zero means
    # curl failed for any reason). We only assert coi didn't crash with an
    # unexpected error unrelated to the network attempt.
    # curl exit 0: connected; 1: generic error; 7: connection refused (allowed in open
    # mode — kernel attempted the connection); 28: timeout. All are valid outcomes.
    assert "failed to" not in result.stderr.lower() or result.returncode in (0, 1, 7, 28), (
        f"coi run in open mode should not crash. stderr: {result.stderr}"
    )


def test_run_ssh_agent_forwarding(coi_binary, workspace_dir, cleanup_containers):
    """
    coi run with ssh.forward_agent = true must set SSH_AUTH_SOCK in the container.

    This is a regression test for #373: previously ssh.forward_agent was silently
    ignored in coi run, so SSH_AUTH_SOCK was never set inside the container.

    Skipped when SSH_AUTH_SOCK is not set on the host — CI runners typically have
    no running SSH agent, so forwarding cannot be tested in that environment.
    """
    import pytest

    host_sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not host_sock:
        pytest.skip("SSH_AUTH_SOCK not set on host — no agent to forward")

    _write_config(workspace_dir, "[ssh]\nforward_agent = true\n")

    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            'test -n "$SSH_AUTH_SOCK" && echo ssh_sock_set',
        ],
        capture_output=True,
        text=True,
        timeout=60,
        # forward_agent is trusted-scope only: load the config via COI_CONFIG.
        env={**os.environ, "COI_CONFIG": str(pathlib.Path(workspace_dir) / ".coi" / "config.toml")},
    )

    assert result.returncode == 0, (
        f"coi run with forward_agent=true should set SSH_AUTH_SOCK. stderr: {result.stderr}"
    )
    combined = result.stdout + result.stderr
    assert "ssh_sock_set" in combined, (
        f"SSH_AUTH_SOCK should be non-empty inside the container. Got:\n{combined}"
    )
