"""
Tests for the startup grants report `coi shell` prints before the tool starts.

The report lists what the container can reach on the host. It is built after
setup, so it must show what was granted, not what was configured.

Verifies that the report:
1. lists the workspace, an extra read-only mount and protected paths that exist;
   names a forwarded env var but never prints its value; says "none" for
   sockets when nothing is forwarded;
2. lists forwarded sockets (a [[sockets]] entry and the SSH agent), published
   ports, env_commands names, credentials whose host file exists (not missing
   ones) and resource limits;
3. describes allowlist mode: the entries and the port cap;
4. describes restricted mode: LAN and metadata blocking, pinned DNS;
5. leaves out untrusted project entries that trust gating dropped.
"""

import os
import shutil
import socket
import subprocess
import tempfile

from support.helpers import write_trusted_coi_config

SECRET_VALUE = "grants-report-secret-value-8231"
MINTED_VALUE = "grants-report-minted-value-5517"


def _run_shell(coi_binary, workspace_dir, env):
    env["COI_USE_DUMMY"] = "1"
    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", workspace_dir, "--slot", "1"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert result.returncode == 0, f"coi shell --background failed:\n{result.stderr}"
    return result


def _report(output):
    """Parse the report into {label: [lines]}; continuation lines (blank label)
    belong to the label above them."""
    assert "Effective grants:" in output, f"no grants report in output:\n{output}"
    rows = {}
    label = None
    for line in output[output.index("Effective grants:") :].splitlines()[1:]:
        if not line.startswith("  ") or not line.strip():
            break
        body = line[2:]
        if body[0] != " ":
            label, _, value = body.partition(" ")
            rows[label] = [value.strip()]
        else:
            rows[label].append(body.strip())
    return rows


class _HostSocket:
    """A bound, listening host Unix socket in a short /tmp dir (AF_UNIX paths are
    capped at ~108 bytes, too short for pytest's tmp_path)."""

    def __init__(self, name):
        self.dir = tempfile.mkdtemp(prefix="coigr")
        self.path = os.path.join(self.dir, name)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(1)

    def close(self):
        self.srv.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def _gate_active_env():
    """Copy of the environment with COI_TRUST_ALL removed, so trust gating is on."""
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def test_report_mounts_env_and_protected_paths(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    extra = tmp_path / "extra"
    extra.mkdir()
    # .husky is in the default protected_paths; .vscode is too but is absent from
    # the workspace, so it has nothing to protect and must not be listed.
    os.mkdir(os.path.join(workspace_dir, ".husky"))
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

    result = _run_shell(coi_binary, workspace_dir, env)
    rows = _report(result.stderr)

    assert rows["Workspace"] == [f"{workspace_dir} -> /workspace (read-write)"], rows
    assert rows["Mounts"] == [f"{extra} -> /mnt/extra (read-only)"], rows
    assert ".husky" in rows["Protected"][0], rows
    assert ".vscode" not in rows["Protected"][0], rows
    assert rows["Env"] == ["COI_GRANTS_TEST_VAR (from host)"], rows
    assert rows["Sockets"] == ["none"], rows
    assert rows["Agent"][0].startswith("runs as non-root"), rows
    assert SECRET_VALUE not in result.stderr + result.stdout, "the report must not print env values"


def test_report_sockets_ports_credentials_and_limits(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    broker = _HostSocket("broker.sock")
    agent = _HostSocket("agent.sock")
    present = tmp_path / "present-cred"
    present.write_text("cred")
    missing = tmp_path / "missing-cred"
    try:
        env = write_trusted_coi_config(
            "[defaults.env_commands]\n"
            f"COI_GRANTS_MINTED = \"printf '{MINTED_VALUE}'\"\n"
            "[ssh]\n"
            "forward_agent = true\n"
            "[[sockets]]\n"
            f'host = "{broker.path}"\n'
            'container = "/tmp/broker.sock"\n'
            'env = "BROKER_SOCK"\n'
            "[[ports.map]]\n"
            'name = "web"\n'
            "container = 3000\n"
            "[[credentials]]\n"
            f'host = "{present}"\n'
            'container = "/home/code/.present-cred"\n'
            "[[credentials]]\n"
            f'host = "{missing}"\n'
            'container = "/home/code/.missing-cred"\n'
            "[limits.memory]\n"
            'limit = "2GiB"\n'
            "[limits.runtime]\n"
            'max_duration = "2h"\n'
        )
        env["SSH_AUTH_SOCK"] = agent.path

        result = _run_shell(coi_binary, workspace_dir, env)
        rows = _report(result.stderr)

        assert f"{broker.path} -> /tmp/broker.sock (BROKER_SOCK)" in rows["Sockets"], rows
        assert f"{agent.path} -> /tmp/ssh-agent.sock (SSH_AUTH_SOCK)" in rows["Sockets"], rows
        assert any(p.startswith("web: container 3000 -> host 127.0.0.1:") for p in rows["Ports"]), (
            rows
        )
        assert "COI_GRANTS_MINTED (env_commands)" in rows["Env"], rows
        assert rows["Credentials"] == [f"{present} -> /home/code/.present-cred"], rows
        assert rows["Limits"] == ["memory 2GiB, max duration 2h"], rows
        assert MINTED_VALUE not in result.stderr + result.stdout, (
            "the report must not print minted values"
        )
    finally:
        broker.close()
        agent.close()


def test_report_allowlist_network(coi_binary, cleanup_containers, workspace_dir):
    env = write_trusted_coi_config(
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1", "8.8.8.8"]\n'
        "allowed_ports = [443]\n"
    )

    rows = _report(_run_shell(coi_binary, workspace_dir, env).stderr)

    assert rows["Network"][0] == "allowlist: 1.1.1.1, 8.8.8.8", rows
    assert "ports 443 only" in rows["Network"], rows


def test_report_restricted_network(coi_binary, cleanup_containers, workspace_dir):
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "restricted"\n'
        "block_private_networks = true\n"
        "block_metadata_endpoint = true\n"
        "allow_local_network_access = false\n"
        'dns_servers = ["1.1.1.1"]\n'
    )

    rows = _report(_run_shell(coi_binary, workspace_dir, env).stderr)

    assert rows["Network"][0] == (
        "restricted: internet (LAN blocked, metadata endpoint blocked)"
    ), rows
    assert "DNS pinned to 1.1.1.1" in rows["Network"], rows


def test_report_omits_untrusted_entries(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """An untrusted project config's out-of-workspace mount and socket are dropped
    by trust gating, so the report must not list them."""
    outside = tmp_path / "outside"
    outside.mkdir()
    sock = _HostSocket("gated.sock")
    try:
        project = os.path.join(workspace_dir, ".coi")
        os.mkdir(project)
        with open(os.path.join(project, "config.toml"), "w") as f:
            f.write(
                "[[mounts]]\n"
                f'host = "{outside}"\n'
                'container = "/mnt/outside"\n'
                "[[sockets]]\n"
                f'host = "{sock.path}"\n'
                'container = "/tmp/gated.sock"\n'
            )
        env = _gate_active_env()
        env.pop("SSH_AUTH_SOCK", None)

        result = _run_shell(coi_binary, workspace_dir, env)
        rows = _report(result.stderr)

        assert rows["Mounts"] == ["none"], rows
        assert rows["Sockets"] == ["none"], rows
        report = result.stderr[result.stderr.index("Effective grants:") :]
        assert str(outside) not in report and sock.path not in report, report
    finally:
        sock.close()
