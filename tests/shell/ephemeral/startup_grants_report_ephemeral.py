"""
Test that `coi shell` prints a startup report of the session's effective grants.

Verifies that the report:
1. lists the workspace mount and an extra read-only [[mounts]] entry;
2. names a forwarded env var but never prints its value;
3. states "none" for sockets when nothing is forwarded.
"""

import subprocess

from support.helpers import write_trusted_coi_config

SECRET_VALUE = "grants-report-secret-value-8231"


def test_startup_grants_report(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    extra = tmp_path / "extra"
    extra.mkdir()
    env = write_trusted_coi_config(
        "[defaults]\n"
        'forward_env = ["COI_GRANTS_TEST_VAR"]\n'
        "[ssh]\n"
        "forward_agent = false\n"
        "[[mounts]]\n"
        f'host = "{extra}"\n'
        'container = "/mnt/extra"\n'
        "readonly = true\n"
    )
    env["COI_GRANTS_TEST_VAR"] = SECRET_VALUE
    env["COI_USE_DUMMY"] = "1"

    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"

    out = result.stderr
    assert "Effective grants:" in out, f"no grants report in output:\n{out}"
    assert f"{workspace_dir} -> /workspace (read-write)" in out, out
    assert f"{extra} -> /mnt/extra (read-only)" in out, out
    assert "COI_GRANTS_TEST_VAR (from host)" in out, out
    assert SECRET_VALUE not in out + result.stdout, "the report must not print env values"

    report = out[out.index("Effective grants:") :]
    sockets_line = next(line for line in report.splitlines() if line.strip().startswith("Sockets"))
    assert sockets_line.split()[-1] == "none", f"expected no sockets, got: {sockets_line}"
