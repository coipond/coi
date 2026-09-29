"""
End-to-end tests for the egress-policy controls dns_servers (DNS resolver
pinning) and allowed_ports (destination-port allowlist), driving REAL traffic
from inside the container.

These run in CI's network lane against real Incus + nftables + internet, which is
what makes them the enforcing coverage for the feature — the Go
`*_integration_test.go` counterparts self-skip without Incus and are not run by
this lane.

Both keys are TRUSTED-SCOPE ONLY (a resolver pin is a DNS-redirect primitive; the
port cap is honored from trusted scope for a uniform rule), so every test supplies
them via `write_trusted_coi_config` (COI_CONFIG env), NOT a workspace
.coi/config.toml — a project-scope config would have them stripped at load.

Test targets are raw public IPs (no DNS needed for the probe itself), and each
"blocked" assertion is paired with an "allowed" assertion to the SAME host on a
different port (or the same port on a different host), so a block can never pass
for the wrong reason (host simply unreachable):

    1.1.1.1 — Cloudflare: listens on 80, 443 and 53
    8.8.8.8 — Google:     listens on 443 and 53
"""

import json
import re
import subprocess

from support.helpers import wait_for_firewall_rules, write_trusted_coi_config


def _container_ip(name):
    """Resolve a container's IPv4 address via incus."""
    result = subprocess.run(
        ["incus", "list", name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    info = json.loads(result.stdout)
    if not info:
        return None
    for addr in info[0].get("state", {}).get("network", {}).get("eth0", {}).get("addresses", []):
        if addr.get("family") == "inet":
            return addr["address"]
    return None


def _container_rule_lines(container_ip):
    """Return the ip coi forward-chain rule lines whose source is this container."""
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return []
    src_re = re.compile(r"ip saddr " + re.escape(container_ip) + r"\b")
    return [ln for ln in result.stdout.splitlines() if src_re.search(ln)]


def _lan_accept_lines(container_ip):
    """The container's RFC1918 (local-access) accept rules."""
    return [
        ln
        for ln in _container_rule_lines(container_ip)
        if "accept" in ln
        and any(c in ln for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    ]


def _host_accept_lines(container_ip, host_ip):
    """The container's targeted accept rule(s) for a specific [[network.hosts]]
    destination IP. Restricted mode inserts one at the head of the forward chain."""
    dst_re = re.compile(r"ip daddr " + re.escape(host_ip) + r"\b")
    return [
        ln for ln in _container_rule_lines(container_ip) if "accept" in ln and dst_re.search(ln)
    ]


def _start_background_shell(coi_binary, workspace_dir, env):
    """Start a background coi shell with the given (trusted) env and return the
    container name once its firewall rules are in place."""
    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background", "--debug"],
        capture_output=True,
        text=True,
        timeout=90,
        env=env,
    )
    assert result.returncode == 0, f"background shell should start. stderr: {result.stderr}"

    container_name = None
    for line in result.stderr.split("\n"):
        if "Container name:" in line:
            container_name = line.split("Container name:")[-1].strip()
            break
    assert container_name is not None, f"could not find container name. stderr: {result.stderr}"

    assert wait_for_firewall_rules(container_name), (
        f"firewall rules for {container_name} did not appear in time"
    )
    return container_name


def _can_connect(coi_binary, container_name, host, port):
    """True if a TCP connection to host:port succeeds from inside the container.
    Uses bash's /dev/tcp so no extra image tooling is needed; a rejected port
    fails fast (the rules use `reject`)."""
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "timeout",
            "6",
            "bash",
            "-c",
            f"exec 3<>/dev/tcp/{host}/{port}",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.returncode == 0


def _can_curl(coi_binary, container_name, url):
    """True if curl to url succeeds from inside the container (exercises the
    container's normal DNS + connectivity path)."""
    result = subprocess.run(
        [
            coi_binary,
            "container",
            "exec",
            container_name,
            "--",
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "--connect-timeout",
            "10",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=25,
    )
    return result.returncode == 0


def test_restricted_allowed_ports_blocks_other_ports(coi_binary, workspace_dir, cleanup_containers):
    """restricted + allowed_ports=[443]: 443 reachable, 80/22 rejected — to the
    SAME host, so the block is attributable to the port, not host reachability."""
    env = write_trusted_coi_config('[network]\nmode = "restricted"\nallowed_ports = [443]\n')
    name = _start_background_shell(coi_binary, workspace_dir, env)

    assert _can_connect(coi_binary, name, "1.1.1.1", 443), "allowed port 443 should be reachable"
    assert not _can_connect(coi_binary, name, "1.1.1.1", 80), (
        "port 80 is not in allowed_ports and must be blocked (same host as the working 443)"
    )
    assert not _can_connect(coi_binary, name, "1.1.1.1", 22), (
        "port 22 is not in allowed_ports and must be blocked"
    )


def test_restricted_dns_pin_blocks_unpinned_resolver(coi_binary, workspace_dir, cleanup_containers):
    """restricted + dns_servers=[1.1.1.1]: :53 to the pinned resolver is allowed,
    :53 to any other resolver is rejected, and non-53 traffic is unaffected."""
    env = write_trusted_coi_config('[network]\nmode = "restricted"\ndns_servers = ["1.1.1.1"]\n')
    name = _start_background_shell(coi_binary, workspace_dir, env)

    assert _can_connect(coi_binary, name, "1.1.1.1", 53), "pinned resolver must be reachable on :53"
    assert not _can_connect(coi_binary, name, "8.8.8.8", 53), (
        "an unpinned resolver must be BLOCKED on :53"
    )
    # Contrast: same unpinned host is reachable on 443, so the :53 block above is
    # attributable to the DNS pin, not to 8.8.8.8 being unreachable.
    assert _can_connect(coi_binary, name, "8.8.8.8", 443), (
        "non-53 traffic to the unpinned host must be unaffected by the DNS pin"
    )
    # The bridge resolver (the container's default DNS) must keep working — the pin
    # only touches the forward path, never the container's normal resolution.
    assert _can_curl(coi_binary, name, "https://example.com"), (
        "normal DNS resolution + HTTPS must keep working (bridge resolver untouched)"
    )


def test_allowlist_allowed_ports_constrains_host(coi_binary, workspace_dir, cleanup_containers):
    """allowlist + allowed_ports=[443]: an allowlisted host is reachable only on
    443; the same host on 80 is blocked, and a non-allowlisted host is blocked
    entirely. The allowlist entry is a literal /32 so no DNS resolution occurs."""
    env = write_trusted_coi_config(
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1/32"]\nallowed_ports = [443]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)

    assert _can_connect(coi_binary, name, "1.1.1.1", 443), (
        "allowlisted host on the allowed port must be reachable"
    )
    assert not _can_connect(coi_binary, name, "1.1.1.1", 80), (
        "allowlisted host on a non-allowed port must be blocked (port cap)"
    )
    assert not _can_connect(coi_binary, name, "8.8.8.8", 443), (
        "a non-allowlisted host must be blocked entirely"
    )


def test_allowlist_per_destination_ports(coi_binary, workspace_dir, cleanup_containers):
    """Phase 3: each allowed_domains entry carries its OWN ports. With
    ["1.1.1.1:443", "1.0.0.1:80"], 443 reaches 1.1.1.1 but NOT 1.0.0.1, and 80
    reaches 1.0.0.1 but NOT 1.1.1.1 — proving the port scope is per destination, not
    one global cap. Both are Cloudflare IPs that genuinely listen on 80 AND 443
    (each block is the firewall's doing, not the host being unreachable), and both
    are literal IPs so no DNS occurs. Port 53 is deliberately avoided: allowlist
    mode blocks all DNS, so it can never be granted to any destination."""
    env = write_trusted_coi_config(
        '[network]\nmode = "allowlist"\nallowed_domains = ["1.1.1.1:443", "1.0.0.1:80"]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)

    assert _can_connect(coi_binary, name, "1.1.1.1", 443), (
        "1.1.1.1 is allowlisted on 443 and must be reachable there"
    )
    assert not _can_connect(coi_binary, name, "1.1.1.1", 80), (
        "1.1.1.1 is scoped to 443, so port 80 must be blocked (it listens on 80)"
    )
    assert _can_connect(coi_binary, name, "1.0.0.1", 80), (
        "1.0.0.1 is allowlisted on 80 and must be reachable there"
    )
    assert not _can_connect(coi_binary, name, "1.0.0.1", 443), (
        "1.0.0.1 is scoped to 80, so 443 must be blocked even though 1.1.1.1:443 "
        "works — that contrast is the per-destination guarantee"
    )


def test_restricted_allow_local_respects_port_cap(coi_binary, workspace_dir, cleanup_containers):
    """allow_local_network_access + allowed_ports=[443]: the RFC1918 LAN allow
    rules must be port-scoped (carry a dport match), so local access does not
    reopen the LAN on all ports (SSH/DBs) — the port cap applies to the LAN too."""
    env = write_trusted_coi_config(
        '[network]\nmode = "restricted"\nallow_local_network_access = true\nallowed_ports = [443]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)
    ip = _container_ip(name)
    assert ip, f"should resolve container IP for {name}"

    lan_accepts = _lan_accept_lines(ip)
    assert lan_accepts, "expected RFC1918 local-access allow rules; found none"
    for ln in lan_accepts:
        assert "dport" in ln and re.search(r"\b443\b", ln), (
            f"LAN allow rule must be port-scoped to 443 (allowed_ports must apply to the LAN): {ln}"
        )


def test_restricted_allow_local_without_cap_is_blanket(
    coi_binary, workspace_dir, cleanup_containers
):
    """Parity guard: allow_local_network_access with NO allowed_ports keeps the
    historic all-ports blanket LAN accept (no dport match)."""
    env = write_trusted_coi_config(
        '[network]\nmode = "restricted"\nallow_local_network_access = true\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)
    ip = _container_ip(name)
    assert ip, f"should resolve container IP for {name}"

    lan_accepts = _lan_accept_lines(ip)
    assert lan_accepts, "expected RFC1918 local-access allow rules; found none"
    for ln in lan_accepts:
        assert "dport" not in ln, (
            f"LAN allow rule should be a blanket accept with no allowed_ports set: {ln}"
        )


def test_restricted_host_entry_respects_port_cap(coi_binary, workspace_dir, cleanup_containers):
    """restricted + allowed_ports=[443] + a private [[network.hosts]] entry: the
    targeted accept Coi inserts for that LAN host must be port-scoped (carry a
    dport match for 443), so a host entry cannot silently reopen the full port
    range (SSH/DBs/admin) on a LAN box — the guarantee allowed_ports makes for
    every other destination.

    Asserts on the emitted rule (the mechanism). Unlike the public-IP probes
    above, a private [[network.hosts]] target has no deterministic listener in CI
    to connect to, and the container's own bridge accept would mask a gateway
    probe; the live-traffic reject of a capped port is already proven by
    test_restricted_allowed_ports_blocks_other_ports."""
    host_ip = "192.168.77.10"
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "restricted"\n'
        "allowed_ports = [443]\n\n"
        "[[network.hosts]]\n"
        f'ip = "{host_ip}"\n'
        'hostnames = ["capped-host.internal"]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)
    ip = _container_ip(name)
    assert ip, f"should resolve container IP for {name}"

    host_accepts = _host_accept_lines(ip, host_ip)
    assert host_accepts, f"expected a targeted accept rule for host entry {host_ip}; found none"
    for ln in host_accepts:
        assert "dport" in ln and re.search(r"\b443\b", ln), (
            f"host-entry accept must be scoped to allowed_ports (443), not an all-ports hole: {ln}"
        )


def test_restricted_host_entry_without_cap_is_blanket(
    coi_binary, workspace_dir, cleanup_containers
):
    """Parity guard: a private [[network.hosts]] entry with NO allowed_ports keeps
    the historic all-ports targeted accept (no dport match), so existing configs
    are unchanged."""
    host_ip = "192.168.77.11"
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "restricted"\n\n'
        "[[network.hosts]]\n"
        f'ip = "{host_ip}"\n'
        'hostnames = ["blanket-host.internal"]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)
    ip = _container_ip(name)
    assert ip, f"should resolve container IP for {name}"

    host_accepts = _host_accept_lines(ip, host_ip)
    assert host_accepts, f"expected a targeted accept rule for host entry {host_ip}; found none"
    for ln in host_accepts:
        assert "dport" not in ln, (
            f"host-entry accept should be a blanket all-ports accept with no "
            f"allowed_ports set: {ln}"
        )


def test_restricted_host_entry_per_entry_ports_decouple(
    coi_binary, workspace_dir, cleanup_containers
):
    """Phase 4: a [[network.hosts]] entry with its OWN ports scopes just that host
    while the internet stays wide open — the decoupling the global allowed_ports
    can't do. This is the "internet open, on the LAN only redmine:443" posture.

    restricted + NO allowed_ports + a redmine-style entry with ports=[443]:
      - the LAN host's targeted allow is scoped to 443 (has a dport match), AND
      - the container still has a blanket internet accept (no daddr, no dport),
        proving per-entry ports did NOT cap the internet."""
    host_ip = "192.168.77.20"
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "restricted"\n\n'
        "[[network.hosts]]\n"
        f'ip = "{host_ip}"\n'
        'hostnames = ["redmine.susanoo.pl"]\n'
        "ports = [443]\n"
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)
    ip = _container_ip(name)
    assert ip, f"should resolve container IP for {name}"

    host_accepts = _host_accept_lines(ip, host_ip)
    assert host_accepts, f"expected a targeted accept rule for host entry {host_ip}; found none"
    for ln in host_accepts:
        assert "dport" in ln and re.search(r"\b443\b", ln), (
            f"per-entry ports must scope the LAN host to 443: {ln}"
        )

    # The internet egress must NOT be capped: a blanket accept for this container
    # (no daddr, no dport) must still be present alongside the scoped host rule.
    blanket = [
        ln
        for ln in _container_rule_lines(ip)
        if "accept" in ln and "daddr" not in ln and "dport" not in ln
    ]
    assert blanket, (
        "internet egress must stay all-ports open while the LAN host is scoped — "
        "per-entry ports must not cap the internet:\n" + "\n".join(_container_rule_lines(ip))
    )


def test_context_file_surfaces_network_limitations(coi_binary, workspace_dir, cleanup_containers):
    """The generated SANDBOX_CONTEXT.md (injected into the agent's context/system
    prompt) must state the active egress limits — the port cap and the pinned
    resolver — so the agent knows what it can and cannot reach instead of blindly
    dialing blocked ports/resolvers."""
    env = write_trusted_coi_config(
        '[network]\nmode = "restricted"\nallowed_ports = [443]\ndns_servers = ["1.1.1.1"]\n'
    )
    name = _start_background_shell(coi_binary, workspace_dir, env)

    result = subprocess.run(
        [coi_binary, "container", "exec", name, "--", "cat", "/home/code/SANDBOX_CONTEXT.md"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    # coi container exec writes command output to stderr.
    content = result.stdout + result.stderr
    assert result.returncode == 0, f"should read SANDBOX_CONTEXT.md. stderr: {result.stderr}"
    assert "destination port(s) 443" in content, (
        f"context file must state the egress port cap.\n{content}"
    )
    assert "DNS is pinned to 1.1.1.1" in content, (
        f"context file must state the pinned resolver.\n{content}"
    )


def test_dns_servers_rejected_in_allowlist_mode(coi_binary, workspace_dir, cleanup_containers):
    """dns_servers + allowlist mode is refused (fail closed): allowlist mode blocks
    all DNS by design, so re-opening :53 would defeat it. coi run must abort and
    never execute the command."""
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "allowlist"\n'
        'allowed_domains = ["1.1.1.1/32"]\n'
        'dns_servers = ["1.1.1.1"]\n'
    )
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", "echo SESSION_RAN"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )
    combined = (result.stdout + result.stderr).lower()

    assert result.returncode != 0, (
        "coi run must fail closed when dns_servers is combined with allowlist mode.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "SESSION_RAN" not in result.stdout, (
        "the command must not run on a fail-closed setup error"
    )
    assert "dns_servers" in combined and "allowlist" in combined, (
        "the failure must be attributable to the dns_servers/allowlist incompatibility.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_invalid_dns_server_fails_closed(coi_binary, workspace_dir, cleanup_containers):
    """An invalid dns_servers entry (not an IPv4 address) must fail the session
    closed rather than starting with a half-applied policy."""
    env = write_trusted_coi_config('[network]\nmode = "restricted"\ndns_servers = ["not-an-ip"]\n')
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", "echo SESSION_RAN"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )
    combined = (result.stdout + result.stderr).lower()

    assert result.returncode != 0, (
        "coi run must fail closed on an invalid dns_servers value.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "SESSION_RAN" not in result.stdout, (
        "the command must not run on a fail-closed setup error"
    )
    assert "dns_servers" in combined, (
        "the failure must be attributable to dns_servers validation.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
