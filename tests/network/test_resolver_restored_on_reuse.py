"""
Test for coi shell - a container reused from an allowlist session gets its
resolver back.

Allowlist mode stops systemd-resolved with a runtime mask
(/run/systemd/system/systemd-resolved.service), which lasts until the next boot.
A restricted- or open-mode session in the same, still running container must
undo that, or the container has no DNS.

Tests that:
1. an allowlist session stops systemd-resolved and leaves the runtime mask
2. a restricted- or open-mode session on the same running container starts
   systemd-resolved again and removes the runtime mask
"""

import subprocess

import pytest

from support.helpers import exec_in, extract_container_name, write_trusted_coi_config

RUNTIME_MASK = "/run/systemd/system/systemd-resolved.service"


@pytest.mark.parametrize("mode", ["restricted", "open"])
def test_resolver_restored_on_reuse(coi_binary, workspace_dir, cleanup_containers, mode):
    """A restricted- or open-mode session on a running allowlist container restores resolved."""
    allowlist_env = write_trusted_coi_config(
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1"]\nrefresh_interval_minutes = 30\n'
    )
    first = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
        capture_output=True,
        text=True,
        timeout=90,
        env=allowlist_env,
    )
    assert first.returncode == 0, f"Failed to start container: {first.stderr}"
    container_name = extract_container_name(first)
    assert container_name, f"Could not find container name: {first.stdout}{first.stderr}"

    def output(cmd):
        return exec_in(coi_binary, container_name, cmd)[1].strip().splitlines()[0]

    def resolver_state():
        return output("systemctl is-active systemd-resolved")

    def mask_present():
        return output(f"test -L {RUNTIME_MASK} && echo yes || echo no")

    assert resolver_state() == "inactive", "allowlist mode must stop systemd-resolved"
    assert mask_present() == "yes", f"allowlist mode must leave the runtime mask {RUNTIME_MASK}"

    second = subprocess.run(
        [coi_binary, "shell", "--container", container_name, "--background"],
        cwd=workspace_dir,
        capture_output=True,
        text=True,
        timeout=90,
        env=write_trusted_coi_config(f'[network]\nmode = "{mode}"\n'),
    )
    assert second.returncode == 0, (
        f"{mode} session on the running container failed: {second.stderr}"
    )

    assert resolver_state() == "active", f"{mode} mode must start systemd-resolved again"
    assert mask_present() == "no", f"{mode} mode must remove the runtime mask {RUNTIME_MASK}"
