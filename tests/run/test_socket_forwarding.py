"""
End-to-end tests for host Unix socket forwarding (`[[sockets]]` and the built-in
`[ssh] forward_agent` fast-track).

A forwarded socket is exposed inside the container via an Incus proxy device, so
the host endpoint never enters the container. `[ssh] forward_agent = true` is the
simple fast-track (one built-in socket: /tmp/ssh-agent.sock + SSH_AUTH_SOCK).
Sockets declared by an untrusted project .coi/config.toml are gated behind
`coi trust` exactly like out-of-workspace mounts (a forwarded host socket exposes
a host capability), and the trust fingerprint spans both mounts and sockets.

These tests are genuinely end-to-end: a host process listens on a Unix socket and
replies with a sentinel; the container connects to the *forwarded* socket (using
the system Node.js shipped in the base image — no socat/nc there) and must read
that sentinel back, proving bytes actually traverse the proxy device. The gate
tests assert the sentinel is *unreachable* until `coi trust`.
"""

import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading

CONTAINER_SOCK = "/tmp/broker.sock"
ENV_NAME = "BROKER_SOCK"
SENTINEL = "SOCKET_SENTINEL_8842"


class HostSocketServer:
    """A host Unix-socket server that replies with SENTINEL on every connection
    then closes, so a client sees a clean EOF. Lives in a short /tmp dir because
    AF_UNIX paths are capped at ~108 bytes (pytest's tmp_path is too deep)."""

    def __init__(self, sentinel=SENTINEL):
        self.sentinel = sentinel
        self.dir = tempfile.mkdtemp(prefix="coisock")
        self.path = os.path.join(self.dir, "broker.sock")
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(self.path)
        self.srv.listen(8)
        self.srv.settimeout(0.5)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.sendall(self.sentinel.encode())
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        self._t.join(timeout=2)
        try:
            self.srv.close()
        except OSError:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


# Node one-liner: connect to a forwarded Unix socket, print whatever the host
# sends, and fail loudly (non-zero, no sentinel on stdout) if it can't connect.
# Node is installed system-wide in the base image; socat/nc are not.
def _node_read_script(container_path):
    return (
        "const net=require('net');"
        f"const s=net.connect('{container_path}');"
        "let d='';s.setEncoding('utf8');"
        "s.on('data',c=>d+=c);"
        "s.on('end',()=>{process.stdout.write(d);process.exit(0)});"
        "s.on('error',e=>{process.stderr.write('CONNERR:'+e.message);process.exit(2)});"
        "setTimeout(()=>{process.stderr.write('TIMEOUT');process.exit(3)},10000);"
    )


def read_through_socket(coi_binary, workspace_dir, env, container_path, extra_args=None):
    """Run `coi run` and have the container read the sentinel back through the
    forwarded socket via Node."""
    args = [coi_binary, "run"]
    if extra_args:
        args += extra_args
    args += ["--", "node", "-e", _node_read_script(container_path)]
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workspace_dir,
        env=env,
    )


def env_gate_active():
    return {k: v for k, v in os.environ.items() if k != "COI_TRUST_ALL"}


def test_ssh_forward_agent_regression(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """`[ssh] forward_agent = true` still forwards $SSH_AUTH_SOCK to the fixed
    /tmp/ssh-agent.sock — and bytes actually traverse it (read the sentinel back
    from the host through the forwarded agent socket)."""
    server = HostSocketServer()
    try:
        cfg = tmp_path / "trusted-config.toml"
        cfg.write_text("[ssh]\nforward_agent = true\n")
        env = dict(os.environ)
        env["COI_CONFIG"] = str(cfg)
        env["SSH_AUTH_SOCK"] = server.path

        r = read_through_socket(coi_binary, workspace_dir, env, "/tmp/ssh-agent.sock")
        assert SENTINEL in r.stdout, (
            f"SSH agent socket should forward bytes end-to-end. out={r.stdout} err={r.stderr}"
        )
    finally:
        server.close()


def _assert_agent_not_forwarded(r):
    """The container ran but /tmp/ssh-agent.sock led nowhere, with the loader warning."""
    combined = r.stdout + r.stderr
    assert SENTINEL not in r.stdout, (
        f"host SSH agent must not be reachable from a project config. out={r.stdout} err={r.stderr}"
    )
    # Node's connect failure proves the container ran, so the check above isn't vacuous.
    assert "CONNERR" in combined, f"container read never ran. out={r.stdout} err={r.stderr}"
    assert "ignoring '[ssh] forward_agent = true' in project config" in r.stderr, (
        f"expected the forward_agent warning. err={r.stderr}"
    )


def test_ssh_forward_agent_ignored_from_project_config(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """`[ssh] forward_agent = true` in an untrusted project .coi/config.toml is
    dropped: a cloned repo must not hand the container the host SSH agent. Not
    gated by `coi trust`, so COI_TRUST_ALL=1 doesn't enable it either."""
    server = HostSocketServer()
    try:
        cfg_dir = pathlib.Path(workspace_dir) / ".coi"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / "config.toml").write_text("[ssh]\nforward_agent = true\n")
        env = dict(os.environ)
        env.pop("COI_CONFIG", None)
        env["COI_TRUST_ALL"] = "1"
        env["SSH_AUTH_SOCK"] = server.path

        r = read_through_socket(coi_binary, workspace_dir, env, "/tmp/ssh-agent.sock")
        _assert_agent_not_forwarded(r)
    finally:
        server.close()


def test_ssh_forward_agent_ignored_from_project_profile(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """Same for a project-scoped profile (./.coi/profiles/dev)."""
    server = HostSocketServer()
    try:
        prof = pathlib.Path(workspace_dir) / ".coi" / "profiles" / "dev"
        prof.mkdir(parents=True)
        (prof / "config.toml").write_text("[ssh]\nforward_agent = true\n")
        env = dict(os.environ)
        env.pop("COI_CONFIG", None)
        env["COI_TRUST_ALL"] = "1"
        env["SSH_AUTH_SOCK"] = server.path

        r = read_through_socket(
            coi_binary, workspace_dir, env, "/tmp/ssh-agent.sock", extra_args=["--profile", "dev"]
        )
        _assert_agent_not_forwarded(r)
    finally:
        server.close()


def test_configured_socket_end_to_end(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """A [[sockets]] entry from a trusted-scope ($COI_CONFIG) config is forwarded,
    its env var is injected, and the container reads the host sentinel back through
    both the literal container path and the env-var-resolved path."""
    server = HostSocketServer()
    try:
        cfg = tmp_path / "trusted-config.toml"
        cfg.write_text(
            f'[[sockets]]\nhost = "{server.path}"\ncontainer = "{CONTAINER_SOCK}"\nenv = "{ENV_NAME}"\n'
        )
        env = dict(os.environ)
        env["COI_CONFIG"] = str(cfg)

        # End-to-end byte transfer through the literal container path.
        r = read_through_socket(coi_binary, workspace_dir, env, CONTAINER_SOCK)
        assert SENTINEL in r.stdout, (
            f"configured socket should forward bytes end-to-end. out={r.stdout} err={r.stderr}"
        )

        # The env var must be set to the container path and resolve to the same
        # working socket (connect via $BROKER_SOCK).
        r = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "sh",
                "-c",
                f'echo "ENV=${ENV_NAME}"; node -e "'
                "const net=require('net');"
                f"const s=net.connect(process.env.{ENV_NAME});"
                "let d='';s.setEncoding('utf8');s.on('data',c=>d+=c);"
                "s.on('end',()=>{process.stdout.write(d)});"
                "s.on('error',e=>{process.stderr.write('CONNERR:'+e.message)});"
                'setTimeout(()=>process.exit(0),10000)"',
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
            env=env,
        )
        assert f"ENV={CONTAINER_SOCK}" in r.stdout, f"{ENV_NAME} should be set. out={r.stdout}"
        assert SENTINEL in r.stdout, (
            f"socket reached via $env var should work end-to-end. out={r.stdout} err={r.stderr}"
        )
    finally:
        server.close()


def test_untrusted_socket_gated_until_trusted(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """A socket declared by the untrusted project .coi/config.toml is unreachable
    until `coi trust`, then works end-to-end; `coi untrust` re-arms the gate."""
    server = HostSocketServer()
    try:
        cfg_dir = pathlib.Path(workspace_dir) / ".coi"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / "config.toml").write_text(
            f'[[sockets]]\nhost = "{server.path}"\ncontainer = "{CONTAINER_SOCK}"\nenv = "{ENV_NAME}"\n'
        )
        env = env_gate_active()

        # 1. Untrusted -> gated: socket not forwarded, sentinel unreachable, warning.
        r = read_through_socket(coi_binary, workspace_dir, env, CONTAINER_SOCK)
        assert SENTINEL not in r.stdout, (
            f"untrusted socket must be unreachable before trust. out={r.stdout} err={r.stderr}"
        )
        assert "ignoring untrusted socket" in r.stderr.lower(), (
            f"expected the socket gate warning. err={r.stderr}"
        )

        # 2. Approve it.
        t = subprocess.run(
            [coi_binary, "trust"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=workspace_dir,
            env=env,
        )
        assert t.returncode == 0, f"coi trust should succeed. err={t.stderr}"
        assert "trusted" in (t.stdout + t.stderr).lower(), (
            f"unexpected trust output: {t.stdout}{t.stderr}"
        )

        # 3. Now reachable end-to-end.
        r = read_through_socket(coi_binary, workspace_dir, env, CONTAINER_SOCK)
        assert SENTINEL in r.stdout, (
            f"socket should forward end-to-end after trust. out={r.stdout} err={r.stderr}"
        )

        # 4. Revoke -> gated again.
        u = subprocess.run(
            [coi_binary, "untrust"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=workspace_dir,
            env=env,
        )
        assert u.returncode == 0, f"untrust failed: {u.stderr}"
        r = read_through_socket(coi_binary, workspace_dir, env, CONTAINER_SOCK)
        assert SENTINEL not in r.stdout, (
            f"socket must be unreachable again after untrust. out={r.stdout} err={r.stderr}"
        )
    finally:
        server.close()


def test_untrusted_socket_trust_all_bypass(coi_binary, workspace_dir, cleanup_containers, tmp_path):
    """COI_TRUST_ALL=1 bypasses the socket gate for CI/automation (reachable end-to-end)."""
    server = HostSocketServer()
    try:
        cfg_dir = pathlib.Path(workspace_dir) / ".coi"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / "config.toml").write_text(
            f'[[sockets]]\nhost = "{server.path}"\ncontainer = "{CONTAINER_SOCK}"\nenv = "{ENV_NAME}"\n'
        )
        env = dict(os.environ)
        env["COI_TRUST_ALL"] = "1"

        r = read_through_socket(coi_binary, workspace_dir, env, CONTAINER_SOCK)
        assert SENTINEL in r.stdout, (
            f"COI_TRUST_ALL=1 should bypass the socket gate end-to-end. out={r.stdout} err={r.stderr}"
        )
    finally:
        server.close()


def test_project_scoped_profile_socket_gated(
    coi_binary, workspace_dir, cleanup_containers, tmp_path
):
    """A socket declared by a project-scoped PROFILE (./.coi/profiles/dev) is
    untrusted too — gated until approved (the profile bypass must be closed)."""
    server = HostSocketServer()
    try:
        prof = pathlib.Path(workspace_dir) / ".coi" / "profiles" / "dev"
        prof.mkdir(parents=True)
        (prof / "config.toml").write_text(
            f'[[sockets]]\nhost = "{server.path}"\ncontainer = "{CONTAINER_SOCK}"\nenv = "{ENV_NAME}"\n'
        )
        env = env_gate_active()

        r = read_through_socket(
            coi_binary, workspace_dir, env, CONTAINER_SOCK, extra_args=["--profile", "dev"]
        )
        assert SENTINEL not in r.stdout, (
            f"profile-declared socket should be gated. out={r.stdout} err={r.stderr}"
        )
        assert "ignoring untrusted socket" in r.stderr.lower(), (
            f"expected the gate warning for the profile socket. err={r.stderr}"
        )
    finally:
        server.close()
