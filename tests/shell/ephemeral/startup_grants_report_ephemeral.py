"""
Tests for the startup grants report `coi shell` prints before the tool starts.

The report lists what the container can reach on the host. It is built after
setup, so it must show what was granted, not what was configured.

Verifies that the report:
1. lists the workspace, an extra read-only mount and protected paths that exist;
   names forwarded and config-set env vars but never prints their values; says
   "none" for sockets when nothing is forwarded;
2. lists forwarded sockets (a [[sockets]] entry and the SSH agent), published
   ports, env_commands names, credentials that were copied (not missing ones)
   and resource limits;
3. describes allowlist mode: the entries and the port cap;
4. describes restricted mode: LAN and metadata blocking, pinned DNS;
5. leaves out untrusted project entries that trust gating dropped;
6. for a git worktree workspace, lists the read-write common dir and its
   read-only git internals;
7. on a reused persistent container, still lists a mount attached at creation
   that trust gating now drops (it stays attached, so it is still reachable);
8. lists the tool's own config and login files copied from the host (Claude's
   .credentials.json and .claude.json), and on reuse the ones already there;
9. lists what the container inherits from an Incus profile: a host disk, a
   storage-pool volume (as a volume, not a host path) and environment.* names;
10. on resume, lists the login files re-copied from the host as copied this
    launch, not as left over;
11. names the tool's own env from [tool] config;
12. when the tool is already running in tmux, says the running tool keeps its
    env and lists the names as reaching new panes only;
13. on reuse, lists a [[credentials]] file coi copied earlier as already there,
    but not a file the image ships at another entry's destination;
14. on reuse, shows the limits the container runs with, not changed config.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time

from support.helpers import (
    calculate_container_name,
    write_trusted_coi_config,
    write_workspace_container_config,
)

SECRET_VALUE = "grants-report-secret-value-8231"
STATIC_VALUE = "grants-report-static-value-6604"
MINTED_VALUE = "grants-report-minted-value-5517"


def _run_shell(coi_binary, workspace_dir, env, args=("--slot", "1")):
    env["COI_USE_DUMMY"] = "1"
    result = subprocess.run(
        [coi_binary, "shell", "--background", "--workspace", str(workspace_dir), *args],
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
            # Labels may hold one space ("Tool config"); the column gap is two+.
            label, value = re.split(r"\s{2,}", body, maxsplit=1)
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
    # .husky and .vscode are in the default protected_paths. .husky exists;
    # .vscode doesn't, but coi mounts an empty read-only placeholder over it so the
    # agent can't plant one, so it is protected (and listed) too.
    os.mkdir(os.path.join(workspace_dir, ".husky"))
    env = write_trusted_coi_config(
        "[defaults]\n"
        'forward_env = ["COI_GRANTS_TEST_VAR"]\n'
        "[defaults.environment]\n"
        f'COI_GRANTS_STATIC = "{STATIC_VALUE}"\n'
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
    assert ".vscode" in rows["Protected"][0], rows
    # A container environment line (e.g. a locked git identity) may follow.
    assert rows["Env"][:2] == [
        "COI_GRANTS_TEST_VAR (from host)",
        "COI_GRANTS_STATIC (set by config)",
    ], rows
    assert rows["Sockets"] == ["none"], rows
    assert rows["Agent"][0].startswith("runs as non-root"), rows
    output = result.stderr + result.stdout
    assert SECRET_VALUE not in output and STATIC_VALUE not in output, (
        "the report must not print env values"
    )


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


def _git(*args, cwd=None):
    return subprocess.run(
        ["git", "-c", "user.email=t@t.dev", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def test_report_worktree_common_dir(coi_binary, tmp_path):
    """A linked-worktree workspace: the external common dir is mounted read-write
    and its git internals are re-covered read-only; the report shows both."""
    main = tmp_path / "main"
    main.mkdir()
    _git("init", "-q", str(main))
    _git("commit", "-q", "--allow-empty", "-m", "init", cwd=str(main))
    wt = tmp_path / "wt"
    _git("worktree", "add", "-q", str(wt), cwd=str(main))
    common = os.path.realpath(main / ".git")
    try:
        rows = _report(_run_shell(coi_binary, wt, dict(os.environ)).stderr)

        assert any(m.startswith(f"{common} -> {common} (read-write)") for m in rows["Mounts"]), rows
        protected = rows["Protected"][0]
        assert f"{common}/hooks" in protected and f"{common}/config" in protected, rows
    finally:
        for slot in range(1, 4):
            subprocess.run(
                [
                    coi_binary,
                    "container",
                    "delete",
                    calculate_container_name(str(wt), slot),
                    "--force",
                ],
                capture_output=True,
                timeout=60,
            )


def test_report_reused_container_keeps_leftover_mount(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A mount attached when a persistent container was created stays attached on
    reuse even once trust gating drops it from config, so the report must keep
    listing it rather than understate what the container can reach."""
    outside = tmp_path / "outside"
    outside.mkdir()
    project = os.path.join(workspace_dir, ".coi")
    os.mkdir(project)
    with open(os.path.join(project, "config.toml"), "w") as f:
        f.write(f'[[mounts]]\nhost = "{outside}"\ncontainer = "/mnt/outside"\n')
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)
    mount_line = f"{outside} -> /mnt/outside (read-write)"

    # Created trusted (the suite sets COI_TRUST_ALL), so the mount is attached.
    first = _report(_run_shell(coi_binary, workspace_dir, dict(os.environ)).stderr)
    assert mount_line in first["Mounts"], first

    stop = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert stop.returncode == 0, stop.stderr
    time.sleep(1)

    # Re-entered with the trust gate on: config drops the mount, the device stays.
    reused = _report(
        _run_shell(
            coi_binary, workspace_dir, _gate_active_env(), args=("--container", container_name)
        ).stderr
    )
    assert mount_line in reused["Mounts"], reused


def test_report_tool_config_files(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """The tool's login and state files copied from the host are listed; on a
    reused container that doesn't re-copy them they're listed as already there."""
    fake_home = tmp_path / "fake_home"
    claude_dir = fake_home / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / ".credentials.json").write_text('{"token": "test"}')
    (fake_home / ".claude.json").write_text("{}")
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)
    env = dict(os.environ)
    env["HOME"] = str(fake_home)

    rows = _report(_run_shell(coi_binary, workspace_dir, dict(env)).stderr)
    tool_files = rows.get("Tool config", [])
    creds_line = f"{claude_dir}/.credentials.json -> /home/code/.claude/.credentials.json"
    assert creds_line in tool_files, rows
    assert f"{fake_home}/.claude.json -> /home/code/.claude.json" in tool_files, rows

    stop = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert stop.returncode == 0, stop.stderr
    time.sleep(1)

    # The reused container keeps its config; the login file is still in it.
    reused = _report(
        _run_shell(
            coi_binary, workspace_dir, dict(env), args=("--container", container_name)
        ).stderr
    )
    assert any(
        line.startswith(creds_line) and "already in the container" in line
        for line in reused.get("Tool config", [])
    ), reused


def _incus(*args):
    r = subprocess.run(["incus", *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"incus {' '.join(args)}: {r.stderr}"
    return r.stdout.strip()


def _stop(coi_binary, container_name, env=None):
    stop = subprocess.run(
        [coi_binary, "container", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert stop.returncode == 0, stop.stderr
    time.sleep(1)


def test_report_lists_incus_profile_grants(coi_binary, cleanup_containers, workspace_dir, tmp_path):
    """What the container inherits from an Incus profile is reachable, so it is
    listed: a host disk, a storage-pool volume (named as a volume, since it is
    not a host path) and environment.* names (never values)."""
    shared = tmp_path / "from-profile"
    shared.mkdir()
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)
    profile = f"coi-test-grants-{os.getpid()}"
    volume = f"coi-test-grants-vol-{os.getpid()}"
    profile_value = "grants-profile-env-value-3391"

    _run_shell(coi_binary, workspace_dir, dict(os.environ))
    _stop(coi_binary, container_name)
    # The root disk comes from the default profile, which the instance can't
    # read as its own device.
    pool = _incus("profile", "device", "get", "default", "root", "pool")

    _incus("profile", "create", profile)
    volume_created = False
    try:
        _incus(
            "profile",
            "device",
            "add",
            profile,
            "shared",
            "disk",
            f"source={shared}",
            "path=/mnt/from-profile",
        )
        _incus("storage", "volume", "create", pool, volume)
        volume_created = True
        _incus(
            "profile",
            "device",
            "add",
            profile,
            "vol",
            "disk",
            f"pool={pool}",
            f"source={volume}",
            "path=/mnt/vol",
        )
        _incus("profile", "set", profile, f"environment.COI_PROFILE_ENV={profile_value}")
        _incus("profile", "add", container_name, profile)

        result = _run_shell(
            coi_binary, workspace_dir, dict(os.environ), args=("--container", container_name)
        )
        rows = _report(result.stderr)
        assert f"{shared} -> /mnt/from-profile (read-write)" in rows["Mounts"], rows
        assert f"volume {pool}/{volume} -> /mnt/vol (read-write)" in rows["Mounts"], rows
        assert any(
            "COI_PROFILE_ENV" in line and line.endswith("(container environment)")
            for line in rows["Env"]
        ), rows
        assert profile_value not in result.stderr + result.stdout, (
            "the report must not print env values"
        )
    finally:
        subprocess.run(
            [coi_binary, "container", "delete", container_name, "--force"],
            capture_output=True,
            timeout=60,
        )
        subprocess.run(["incus", "profile", "delete", profile], capture_output=True, timeout=60)
        if volume_created:
            subprocess.run(
                ["incus", "storage", "volume", "delete", pool, volume],
                capture_output=True,
                timeout=60,
            )


def test_report_resume_lists_recopied_tool_files(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """Resume re-copies the tool's login files from the host, so they are listed
    as copied this launch, not as already in the container."""
    fake_home = tmp_path / "fake_home"
    claude_dir = fake_home / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / ".credentials.json").write_text('{"token": "test"}')
    (fake_home / ".claude.json").write_text("{}")
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)
    env = dict(os.environ)
    env["HOME"] = str(fake_home)

    _run_shell(coi_binary, workspace_dir, dict(env))
    _stop(coi_binary, container_name, env)

    # A saved session for this container, as session cleanup would write it.
    sessions = [d for d in (fake_home / ".coi").iterdir() if d.name.startswith("sessions-")]
    assert len(sessions) == 1, sessions
    session_id = "grants-resume-test"
    saved = sessions[0] / session_id
    (saved / ".claude").mkdir(parents=True)
    (saved / "metadata.json").write_text(
        json.dumps(
            {
                "session_id": session_id,
                "container_name": container_name,
                "persistent": True,
                "workspace": str(workspace_dir),
                "saved_at": "2026-01-01T00:00:00Z",
            }
        )
    )

    rows = _report(
        _run_shell(coi_binary, workspace_dir, dict(env), args=(f"--resume={session_id}",)).stderr
    )
    creds_line = f"{claude_dir}/.credentials.json -> /home/code/.claude/.credentials.json"
    assert creds_line in rows.get("Tool config", []), rows


def test_report_tool_settings_env(coi_binary, cleanup_containers, workspace_dir):
    """The tool's own env from [tool] config reaches the agent, so it is named."""
    env = write_trusted_coi_config('[tool.claude]\neffort_level = "high"\nmodel = "opus"\n')

    rows = _report(_run_shell(coi_binary, workspace_dir, env).stderr)

    assert "ANTHROPIC_MODEL, CLAUDE_CODE_EFFORT_LEVEL (tool settings)" in rows["Env"], rows


def test_report_running_tool_keeps_its_env(coi_binary, cleanup_containers, workspace_dir):
    """Re-entering a container whose tool is still running in tmux doesn't
    restart it, so env_commands minted now never reach the tool, only panes
    opened from now on: the report says so rather than claiming them."""
    env = write_trusted_coi_config(
        f"[defaults.env_commands]\nCOI_GRANTS_MINTED = \"printf '{MINTED_VALUE}'\"\n"
    )
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)

    first = _report(_run_shell(coi_binary, workspace_dir, dict(env)).stderr)
    assert "COI_GRANTS_MINTED (env_commands)" in first["Env"], first

    # Still running: the second launch finds the tool's tmux session.
    second = _report(
        _run_shell(
            coi_binary, workspace_dir, dict(env), args=("--container", container_name)
        ).stderr
    )
    assert second["Env"][0] == ("the running tool keeps the env it started with; new panes get:"), (
        second
    )
    assert "COI_GRANTS_MINTED (env_commands)" in second["Env"], second


def test_report_reused_container_leftover_credentials(
    coi_binary, cleanup_containers, workspace_dir, tmp_path
):
    """A reused container isn't re-seeded, so a [[credentials]] file coi copied at
    creation is listed as already there. A destination coi never copied to (its
    host file is missing) is not, even though the image ships a file there."""
    present = tmp_path / "present-cred"
    present.write_text("cred")
    missing = tmp_path / "missing-cred"
    env = write_trusted_coi_config(
        "[[credentials]]\n"
        f'host = "{present}"\n'
        'container = "/home/code/.present-cred"\n'
        "[[credentials]]\n"
        f'host = "{missing}"\n'
        'container = "/home/code/.bashrc"\n'
    )
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)

    first = _report(_run_shell(coi_binary, workspace_dir, dict(env)).stderr)
    assert first["Credentials"] == [f"{present} -> /home/code/.present-cred"], first
    _stop(coi_binary, container_name, env)

    reused = _report(
        _run_shell(
            coi_binary, workspace_dir, dict(env), args=("--container", container_name)
        ).stderr
    )
    assert reused["Credentials"] == [
        f"{present} -> /home/code/.present-cred (already in the container, not copied this launch)"
    ], reused


def test_report_reused_container_applied_limits(coi_binary, cleanup_containers, workspace_dir):
    """Limits are applied when a container is created; a reused one keeps them,
    so the report shows those rather than what config now says."""
    write_workspace_container_config(workspace_dir, persistent=True)
    container_name = calculate_container_name(workspace_dir, 1)

    first_env = write_trusted_coi_config('[limits.cpu]\ncount = "1"\n')
    first = _report(_run_shell(coi_binary, workspace_dir, dict(first_env)).stderr)
    assert first["Limits"] == ["cpu 1"], first
    _stop(coi_binary, container_name, first_env)

    changed_env = write_trusted_coi_config('[limits.cpu]\ncount = "2"\n')
    reused = _report(
        _run_shell(
            coi_binary, workspace_dir, dict(changed_env), args=("--container", container_name)
        ).stderr
    )
    assert reused["Limits"] == ["cpu 1"], reused
