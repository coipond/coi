"""
End-to-end tests for host port publishing (`[ports]` pool + `[[ports.map]]`).

A published port is an Incus proxy device pointing the opposite way from
`[[sockets]]`: it listens on the host's localhost and connects into the
container, so agent-started services are reachable as http://localhost:<port>
on the host (#558). The pool is identity-mapped (host port == container
port) and allocated deterministically per (workspace, slot); map entries
publish fixed container ports with an auto or pinned host side.

Genuinely end-to-end: a Node HTTP server inside the container replies with a
sentinel; the HOST fetches http://127.0.0.1:<published-port>/ and must read
it back, proving bytes traverse the proxy device. The preflight test proves
a taken pinned port aborts the session BEFORE any container is created.
"""

import hashlib
import json
import os
import re
import socket
import subprocess
from pathlib import Path

from support.helpers import (
    NODE_PORT_SERVER,
    PORT_SENTINEL,
    calculate_container_name,
    fetch_host_port,
    free_host_port,
    incus_status,
    write_workspace_container_config,
)


def expected_pool_port(workspace_dir, slot=1, index=0):
    """Replicate session.AllocateHostPort: 20000 + (hash%400)*100 + (slot-1)*10 + index.

    The hash is the first 4 hex chars of sha256(abs workspace path) — the same
    identity container names use (support.helpers.calculate_container_name).
    """
    abs_path = os.path.abspath(workspace_dir)
    h = hashlib.sha256(abs_path.encode()).hexdigest()[:4]
    return 20000 + (int(h, 16) % 400) * 100 + (slot - 1) * 10 + index


def write_ports_config(workspace_dir, toml):
    config_dir = Path(workspace_dir) / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(toml)


def test_ports_env_exposed(coi_binary, cleanup_containers, workspace_dir):
    """COI_PORTS lists the pool numbers; COI_PORT_<NAME> carries map entries."""
    write_ports_config(
        workspace_dir,
        """
[ports]
pool = 2

[[ports.map]]
name = "web"
container = 3000
""",
    )
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            'echo "POOL=[$COI_PORTS] WEB=[$COI_PORT_WEB]"',
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
    )
    assert result.returncode == 0, f"coi run should succeed. stderr: {result.stderr}"

    # Ports come from this workspace's deterministic block; busy host ports
    # may shift entries forward within it, so assert membership + ordering
    # rather than exact values (the reachability tests pin the semantics).
    m = re.search(r"POOL=\[(\d+) (\d+)\] WEB=\[(\d+)\]", result.stdout)
    assert m, f"env vars missing or malformed. Got:\n{result.stdout}\nstderr:{result.stderr}"
    p1, p2, web = int(m.group(1)), int(m.group(2)), int(m.group(3))
    block_start = expected_pool_port(workspace_dir)
    for v in (p1, p2, web):
        assert block_start <= v < block_start + 10, (
            f"{v} outside this workspace's slot block [{block_start}, {block_start + 9}]"
        )
    assert p1 < p2 < web, "pool ports precede the auto map entry within the block"


def test_pinned_map_port_reachable_from_host(coi_binary, cleanup_containers, workspace_dir):
    """A named map entry with a pinned host port carries real traffic."""
    pin = free_host_port()
    write_ports_config(
        workspace_dir,
        f"""
[[ports.map]]
name = "web"
container = 8000
host = {pin}
""",
    )
    proc = subprocess.Popen(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            f"PORT=8000 {NODE_PORT_SERVER}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace_dir,
    )
    try:
        body = fetch_host_port(pin, timeout_total=90)
        assert PORT_SENTINEL in body, f"host fetch through pinned port returned: {body!r}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_pool_port_identity_reachable_from_host(coi_binary, cleanup_containers, workspace_dir):
    """Pool ports are identity-mapped: the container binds the SAME number the
    host connects to — the whole point of the pool UX."""
    expected = expected_pool_port(workspace_dir)
    write_ports_config(
        workspace_dir,
        """
[ports]
pool = 1
""",
    )
    # The in-container server binds the first COI_PORTS number; the host
    # fetches the deterministic expectation of that same number.
    proc = subprocess.Popen(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "sh",
            "-c",
            f'PORT="${{COI_PORTS%% *}}" {NODE_PORT_SERVER}',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=workspace_dir,
    )
    try:
        body = fetch_host_port(expected, timeout_total=90)
        assert PORT_SENTINEL in body, f"host fetch through pool port returned: {body!r}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_ports_survive_persistent_reuse(coi_binary, cleanup_containers, workspace_dir):
    """Reusing a persistent container must not collide with its own previous
    port devices (regression: the stale proxy device re-bound the pinned host
    port at start, so every reuse died with 'already in use'; pool/auto
    numbers drifted forward each session)."""
    pin = free_host_port()
    write_ports_config(
        workspace_dir,
        f"""
[ports]
pool = 2

[[ports.map]]
name = "web"
container = 8000
host = {pin}
""",
    )
    write_workspace_container_config(workspace_dir, persistent=True)

    pools = []
    for attempt in (1, 2):
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                'echo "POOL=[$COI_PORTS] WEB=[$COI_PORT_WEB]"',
            ],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=workspace_dir,
        )
        assert result.returncode == 0, f"run {attempt} must succeed. stderr: {result.stderr}"
        assert "already in use" not in result.stderr, (
            f"run {attempt} collided with its own previous devices. stderr: {result.stderr}"
        )
        assert f"WEB=[{pin}]" in result.stdout, (
            f"run {attempt}: pinned port must stay {pin}. stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        m = re.search(r"POOL=\[(\d+ \d+)\]", result.stdout)
        assert m, f"run {attempt}: pool env missing. stdout: {result.stdout}"
        pools.append(m.group(1))

    # Pool numbers must not drift when the container is reused (the old bug:
    # the session's own stale devices held them, pushing the pool forward).
    assert pools[0] == pools[1], f"pool drifted across reuse: {pools[0]} -> {pools[1]}"

    # `coi list --format json` surfaces the published ports, parsed from the
    # same incus list payload (the persistent container keeps its devices
    # while stopped): pool ports as bare numbers, named entries as
    # name:host->container.
    listed = subprocess.run(
        [coi_binary, "list", "--format", "json"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workspace_dir,
    )
    assert listed.returncode == 0, f"coi list failed. stderr: {listed.stderr}"
    data = json.loads(listed.stdout)
    container_name = calculate_container_name(workspace_dir, 1)
    ours = [c for c in data["active_containers"] if c["name"] == container_name]
    assert ours, f"container {container_name} missing from coi list. Got: {data}"
    ports = ours[0]["published_ports"]
    assert f"web:{pin}->8000" in ports, f"pinned entry missing from coi list ports: {ports}"
    pool_numbers = pools[0].split(" ")
    for p in pool_numbers:
        assert p in ports, f"pool port {p} missing from coi list ports: {ports}"


def test_busy_pool_port_skips_forward(coi_binary, cleanup_containers, workspace_dir):
    """A pool port whose deterministic number is already taken on the host is
    skipped forward within the slot block (auto ports move; only pins abort)."""
    expected = expected_pool_port(workspace_dir)
    blocker = socket.socket()
    try:
        try:
            blocker.bind(("127.0.0.1", expected))
            blocker.listen(1)
        except OSError:
            # Another process already holds the deterministic port — equally
            # good for this test: it is busy either way.
            pass
        write_ports_config(
            workspace_dir,
            """
[ports]
pool = 1
""",
        )
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                'echo "POOL=[$COI_PORTS]"',
            ],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=workspace_dir,
        )
        assert result.returncode == 0, (
            f"a busy AUTO port must not abort the session. stderr: {result.stderr}"
        )
        m = re.search(r"POOL=\[(\d+)\]", result.stdout)
        assert m, f"pool env missing. stdout: {result.stdout}\nstderr: {result.stderr}"
        port = int(m.group(1))
        assert port != expected, f"busy port {expected} must be skipped, but was allocated anyway"
        assert expected < port < expected + 10, (
            f"skip must stay within this slot's block [{expected}, {expected + 9}], got {port}"
        )
    finally:
        blocker.close()


def test_pinned_port_conflict_aborts_before_launch(coi_binary, cleanup_containers, workspace_dir):
    """A taken pinned host port fails the preflight: clear error, no container."""
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    pin = blocker.getsockname()[1]
    try:
        write_ports_config(
            workspace_dir,
            f"""
[[ports.map]]
name = "web"
container = 8000
host = {pin}
""",
        )
        result = subprocess.run(
            [coi_binary, "run", "--workspace", workspace_dir, "--", "echo", "never"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=workspace_dir,
        )
        assert result.returncode != 0, "coi run must abort when the pinned port is taken"
        assert "already in use" in result.stderr, (
            f"error should name the conflict. stderr: {result.stderr}"
        )
        assert "port preflight failed" in result.stderr, (
            f"error should attribute the abort to the preflight. stderr: {result.stderr}"
        )
        # Preflight runs before launch: no container may exist for this workspace
        container_name = calculate_container_name(workspace_dir, 1)
        assert incus_status(container_name) == "", (
            "preflight failure must abort BEFORE the container is created"
        )
    finally:
        blocker.close()
