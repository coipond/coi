"""
Test for coi run - a file the command writes to /tmp at once survives boot.

Tests that:
1. coi run does not start the command before boot's systemd-tmpfiles-setup
   has run (it empties /tmp, `D /tmp`)
2. A file the command writes to /tmp first thing is still there once that
   unit has finished
"""

import subprocess

from support.helpers import calculate_container_name, write_workspace_container_config

# Holds systemd-tmpfiles-setup back on the next boot, so a command that is
# started before the unit has run always writes /tmp before it is emptied.
DELAY_DROPIN = "[Service]\nExecStartPre=/bin/sleep 5\n"

# The markers are built at run time: coi echoes the command itself
# ("Executing: ...") on stderr, so a literal marker would always match.
PROBE = (
    "printf '%s-%s\\n' probe written > /tmp/coi-boot-probe; "
    "i=0; "
    "until systemctl show -P ActiveState systemd-tmpfiles-setup.service 2>/dev/null"
    " | grep -qx active; do "
    'i=$((i+1)); [ "$i" -lt 300 ] || { echo tmpfiles-setup-never-finished; exit 3; }; '
    "sleep 0.2; done; "
    "cat /tmp/coi-boot-probe || printf '%s-%s\\n' probe missing"
)


def test_run_tmp_file_survives_boot(coi_binary, cleanup_containers, workspace_dir):
    """
    Test that a /tmp file written at command start survives the boot.

    Flow:
    1. Persistent run: add a drop-in that delays systemd-tmpfiles-setup
    2. Second run restarts the container (full boot); the command writes
       /tmp/coi-boot-probe at once, waits for systemd-tmpfiles-setup to be
       active, then reads the file back
    3. Verify the output has "probe-written", not "probe-missing"
    """
    slot = 9
    container_name = calculate_container_name(workspace_dir, slot)
    write_workspace_container_config(workspace_dir, persistent=True)

    try:
        # === Phase 1: Delay systemd-tmpfiles-setup on the next boot ===

        result = subprocess.run(
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
                "sudo mkdir -p /etc/systemd/system/systemd-tmpfiles-setup.service.d && "
                f"printf '{DELAY_DROPIN}' | sudo tee "
                "/etc/systemd/system/systemd-tmpfiles-setup.service.d/coi-test-delay.conf",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, f"First run should succeed. stderr: {result.stderr}"

        # === Phase 2: Restart and write /tmp first thing ===

        result = subprocess.run(
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
                PROBE,
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        # === Phase 3: Verify the file survived ===

        combined_output = result.stdout + result.stderr
        assert "probe-missing" not in combined_output, (
            f"systemd-tmpfiles-setup deleted the command's /tmp file. Got:\n{combined_output}"
        )
        assert result.returncode == 0, f"Second run should succeed. Got:\n{combined_output}"
        assert "probe-written" in combined_output, (
            f"Probe file content should be printed. Got:\n{combined_output}"
        )
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=30,
        )
