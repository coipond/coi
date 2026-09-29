"""
Regression test for issue #398: error messages referenced the non-existent
'--network=open' flag, causing users to follow broken instructions.

Root cause: when firewalld is unavailable, Coi printed:
  "Alternatively, run with unrestricted network access: coi shell --network=open"
But '--network' was removed as a CLI flag in an earlier refactor and is
now configured via config.toml. Following the suggestion produced:
  "Error: unknown flag: --network"

Fix: all four occurrences of '--network=open' in user-facing strings were
replaced with instructions to set 'mode = "open"' in the [network] section
of config.toml.

This test verifies:
  1. 'coi shell --network=open' fails with "unknown flag: --network",
     confirming the flag does not exist and the old messages were wrong.
  2. 'coi health' output never contains '--network=open', confirming the
     fix is in place regardless of the system's firewalld state.
"""

import subprocess


def test_network_flag_does_not_exist(coi_binary):
    """coi shell --network=open must fail with 'unknown flag: --network'.

    This documents that the flag was removed and should never be referenced
    in user-facing error messages.
    """
    result = subprocess.run(
        [coi_binary, "shell", "--network=open"],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode != 0, "Should fail: --network is not a registered flag"
    combined = result.stdout + result.stderr
    assert "unknown flag" in combined.lower(), (
        f"Expected 'unknown flag' error for --network=open, got:\n{combined}"
    )
    assert "--network" in combined, f"Error should mention the unknown flag name, got:\n{combined}"


def test_health_output_does_not_suggest_network_flag(coi_binary):
    """'coi health' must not suggest '--network=open' in any output.

    Before the fix, health checks for firewalld absence (common on Colima)
    and ufw conflicts printed '--network=open' as the workaround. After the
    fix they point to the config file instead. This test passes on any system
    regardless of whether firewalld is installed.
    """
    result = subprocess.run(
        [coi_binary, "health"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    combined = result.stdout + result.stderr
    assert "--network=open" not in combined, (
        f"coi health must not suggest the non-existent --network=open flag. Got:\n{combined}"
    )
    assert "--network" not in combined, (
        f"coi health must not reference the removed --network CLI flag at all. Got:\n{combined}"
    )
