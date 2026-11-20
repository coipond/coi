"""
Test for coi network allowlist mode - warning for a private allowed_domains entry.

Allowlist mode rejects 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and
169.254.0.0/16 ahead of the allowed_domains accepts unless
allow_local_network_access = true, so a private literal entry is unreachable.

Tests that:
1. `coi run` prints a warning for the private entry on stderr, and none for
   the public entry
2. `coi shell` prints the same warning in its [setup] output
"""

from support.helpers import (
    run_coi_in_workspace,
    start_background_shell,
    write_trusted_coi_config,
)

PRIVATE_ENTRY = "192.168.254.50"
PUBLIC_ENTRY = "8.8.8.8"
CONFIG = f"""
[network]
mode = "allowlist"
allowed_domains = ["{PUBLIC_ENTRY}", "{PRIVATE_ENTRY}:5000"]
"""
WARNING = f"Warning: allowed_domains entry {PRIVATE_ENTRY} is in a private range"


def _assert_warns(output):
    assert WARNING in output, f"Should warn about {PRIVATE_ENTRY}. Output:\n{output}"
    assert "allow_local_network_access = true" in output, output
    assert "[[network.hosts]]" in output, output
    assert output.count(WARNING) == 1, f"Should warn once. Output:\n{output}"
    assert f"allowed_domains entry {PUBLIC_ENTRY} " not in output, (
        f"Should not warn about {PUBLIC_ENTRY}. Output:\n{output}"
    )


def test_run_warns_private_entry(coi_binary, workspace_dir, cleanup_containers):
    """`coi run` prints the warning on stderr, not only to a log file."""
    env = write_trusted_coi_config(CONFIG)
    result = run_coi_in_workspace(coi_binary, workspace_dir, ["true"], env=env, timeout=240)
    assert result.returncode == 0, f"coi run should succeed. stderr: {result.stderr}"
    assert "Network isolation applied: allowlist" in result.stderr, result.stderr
    _assert_warns(result.stderr)


def test_shell_warns_private_entry(coi_binary, workspace_dir, cleanup_containers):
    """`coi shell` prints the warning as a [setup] line."""
    env = write_trusted_coi_config(CONFIG)
    _, result = start_background_shell(coi_binary, workspace_dir, env, timeout=240)
    output = result.stdout + result.stderr
    assert f"[setup] {WARNING}" in output, f"Should warn in [setup] output. Output:\n{output}"
    _assert_warns(output)
