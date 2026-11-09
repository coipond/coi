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

import os
import subprocess
import tempfile
import time


def test_allowlist_resolver_stopped(coi_binary, workspace_dir, cleanup_containers):
    """An allowlist container has no running resolver, and an unlisted name fails fast."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write("""
[network]
mode = "allowlist"
allowed_domains = ["1.1.1.1"]
refresh_interval_minutes = 30
""")
        config_file = f.name

    try:
        env = os.environ.copy()
        env["COI_CONFIG"] = config_file
        result = subprocess.run(
            [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
        )
        assert result.returncode == 0, f"Failed to start container: {result.stderr}"

        output = result.stdout + result.stderr
        container_name = None
        for line in output.split("\n"):
            if "Container: " in line:
                container_name = line.split("Container: ")[1].strip()
                break
        assert container_name, f"Could not find container name in output: {output}"

        def exec_in(*cmd, timeout=30):
            return subprocess.run(
                [coi_binary, "container", "exec", container_name, "--", *cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

        state = exec_in("systemctl", "is-active", "systemd-resolved")
        assert (state.stdout + state.stderr).strip().splitlines()[0] == "inactive", (
            f"systemd-resolved must be stopped in allowlist mode: {state.stdout}{state.stderr}"
        )

        start = time.monotonic()
        lookup = exec_in("getent", "hosts", "example.org", timeout=15)
        elapsed = time.monotonic() - start
        assert lookup.returncode != 0, f"example.org is not allowlisted: {lookup.stdout}"
        assert elapsed < 5, f"a blocked lookup must fail at once, took {elapsed:.1f}s"
    finally:
        os.unlink(config_file)
