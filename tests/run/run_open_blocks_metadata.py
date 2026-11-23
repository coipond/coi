"""
Test for coi run - open mode rejects the cloud metadata endpoint under
block_metadata_endpoint (the default).

Tests that:
1. curl to 169.254.169.254 in a coi run container is refused at once: coi's
   reject answers TCP with a reset ("Connection refused", exit 7), where
   without it the request reaches the metadata service or times out
"""

import subprocess

from support.helpers import write_trusted_coi_config


def test_run_open_blocks_metadata(coi_binary, workspace_dir, cleanup_containers):
    """
    Flow:
    1. coi run in open mode (trusted config, block_metadata_endpoint default)
    2. curl 169.254.169.254 and print curl's exit code
    3. Verify curl was refused (exit 7, "Connection refused")
    """
    env = write_trusted_coi_config('[network]\nmode = "open"\n')
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            "curl -sS -o /dev/null --connect-timeout 5 http://169.254.169.254/; echo CURL_RC=$?",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    output = result.stdout + result.stderr
    assert "CURL_RC=7" in output and "Connection refused" in output, (
        f"169.254.169.254 must be rejected by coi in open mode. Output:\n{output}"
    )
