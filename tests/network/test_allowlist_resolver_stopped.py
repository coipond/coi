"""
Test for coi shell - allowlist mode stops the container's resolver.

Allowlist mode blocks all DNS, so systemd-resolved has no reachable upstream.
Left running, it retries the blocked bridge resolver for every name not in
/etc/hosts; each rejected query costs an ICMP error from the host, the kernel
rate-limits those per container, and a blocked lookup then waits out its
timeout instead of failing.

Tests that:
1. systemd-resolved is inactive in an allowlist container
2. a name that is not in /etc/hosts fails at once
"""

import subprocess
import time

from support.helpers import exec_in, extract_container_name, write_trusted_coi_config


def test_allowlist_resolver_stopped(coi_binary, workspace_dir, cleanup_containers):
    """An allowlist container has no running resolver, and an unlisted name fails fast."""
    env = write_trusted_coi_config(
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1"]\nrefresh_interval_minutes = 30\n'
    )
    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    assert result.returncode == 0, f"Failed to start container: {result.stderr}"
    container_name = extract_container_name(result)
    assert container_name, f"Could not find container name: {result.stdout}{result.stderr}"

    _, state = exec_in(coi_binary, container_name, "systemctl is-active systemd-resolved")
    assert state.strip().splitlines()[0] == "inactive", (
        f"systemd-resolved must be stopped in allowlist mode: {state}"
    )

    start = time.monotonic()
    rc, lookup = exec_in(coi_binary, container_name, "getent hosts example.org", timeout=15)
    elapsed = time.monotonic() - start
    assert rc != 0, f"example.org is not allowlisted: {lookup}"
    assert elapsed < 5, f"a blocked lookup must fail at once, took {elapsed:.1f}s"
