"""
`coi health` leaves out the sensitive-file monitoring check when security
monitoring is off: there is nothing to warn about then.
"""

import json
import subprocess

from support.helpers import write_trusted_coi_config


def test_health_omits_sensitive_file_check_when_monitoring_off(coi_binary):
    env = write_trusted_coi_config("[monitoring]\nenabled = false\n")
    result = subprocess.run(
        [coi_binary, "health", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    assert "sensitive_file_monitoring" not in json.loads(result.stdout)["checks"]
