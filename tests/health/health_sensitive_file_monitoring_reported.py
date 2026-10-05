"""
`coi health` says whether sensitive-file monitoring can run.

The security monitor watches /etc/shadow reads and sudoers/authorized_keys
writes with fanotify, which needs CAP_SYS_ADMIN. A non-root coi doesn't have
it, so the watcher switches itself off; health must report that instead of
letting monitoring look complete. (CI runs coi as a non-root user.)
"""

import json
import os
import subprocess

from support.helpers import write_trusted_coi_config


def test_health_reports_sensitive_file_monitoring_unavailable(coi_binary):
    env = write_trusted_coi_config("[monitoring]\nenabled = true\n")
    result = subprocess.run(
        [coi_binary, "health", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    check = json.loads(result.stdout)["checks"].get("sensitive_file_monitoring")
    assert check is not None, "health must report sensitive-file monitoring when monitoring is on"
    if os.geteuid() == 0:
        assert check["status"] == "ok", check
    else:
        assert check["status"] == "warning", check
        assert "not detected" in check["message"], check
