"""
Integration tests for allowlist mode's deterministic name resolution.

Allowlist mode does not let the container resolve names itself. Coi resolves the
allowlisted hostnames on the host, installs those addresses in the firewall, and
writes the SAME addresses into the container's /etc/hosts. All DNS egress is then
blocked, so that hosts file is the container's only route from a name to an
address.

That equality is the point. The old design resolved on the host, pinned the
result, and left the container to resolve independently — and for any domain
behind a rotating pool of frontend addresses (every Google API endpoint) the
container routinely got a different member of the pool, one the firewall had
never seen. The packet hit the default reject and the agent died mid-task with
"Unable to connect", healing seconds later when a retry happened to land on an
address that had been pinned.

Nothing has to stay running for the new guarantee to hold: the hosts file and the
firewall are both already in place and they already agree. It survives `coi`
exiting, the user detaching from tmux, or the process being killed — which is
exactly what an in-process DNS proxy could not do, since `coi shell --background`
returns immediately and the container outlives it.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from support.helpers import extract_container_name, wait_for_firewall_rules

# A host behind a large, rotating pool of frontend addresses — the shape that
# broke the old design. It answers with several addresses at once, and the
# container may pick any of them, so every one must be in both the hosts file and
# the firewall.
ROTATING_HOST = "oauth2.googleapis.com"

ALLOWLIST_CONFIG = f"""
[network]
mode = "allowlist"
allowed_domains = [
    "{ROTATING_HOST}",
    "registry.npmjs.org",
]
allow_local_network_access = false
refresh_interval_minutes = 30
"""


def start_allowlist_container(coi_binary, workspace_dir, config_body):
    """Launch a background container with the given [network] config.

    Returns (container_name, launch_result). The caller asserts on the result when
    it expects a failure.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(config_body)
        config_file = f.name

    env = os.environ.copy()
    env["COI_CONFIG"] = config_file

    result = subprocess.run(
        [coi_binary, "shell", "--workspace", workspace_dir, "--background"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    return extract_container_name(result), result


def container_exec(coi_binary, container_name, command, timeout=30):
    """Run a shell command inside the container and return (returncode, output).

    `coi container exec` routes the command's stdout to ITS stderr (see
    IncusExecContext, which sets cmd.Stdout = os.Stderr), so a test that reads only
    .stdout sees nothing at all. Both streams are merged here — reading the wrong
    one makes every assertion below vacuous.
    """
    result = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def container_ip(container_name):
    """The container's IPv4 address, or None."""
    result = subprocess.run(
        ["incus", "list", container_name, "--format=json"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        return None
    for entry in json.loads(result.stdout):
        if entry.get("name") != container_name:
            continue
        for addr in entry.get("state", {}).get("network", {}).get("eth0", {}).get("addresses", []):
            if addr.get("family") == "inet":
                return addr.get("address")
    return None


def nft_coi_table():
    """The full `ip coi` table, including set elements."""
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "table", "ip", "coi"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


def resolve_in_container(coi_binary, container_name, name):
    """Resolve a name inside the container, as the agent's HTTP client would.

    Returns the addresses the container was handed (empty if it could not resolve).
    """
    rc, out = container_exec(coi_binary, container_name, f"getent ahostsv4 {name}")
    if rc != 0:
        return []
    ips = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].count(".") == 3 and parts[0] not in ips:
            ips.append(parts[0])
    return ips


def start_ready_container(coi_binary, workspace_dir, config=ALLOWLIST_CONFIG):
    """Launch a container and wait for its firewall rules. Returns the name."""
    name, result = start_allowlist_container(coi_binary, workspace_dir, config)
    assert result.returncode == 0, f"container failed to start: {result.stderr}"
    assert name, f"no container name in output: {result.stdout}{result.stderr}"
    assert wait_for_firewall_rules(name, timeout=40), "firewall rules were not applied in time"
    return name


def test_every_address_the_container_can_resolve_is_already_allowed(
    coi_binary, workspace_dir, cleanup_containers
):
    """The core invariant: the container cannot resolve to an address the firewall lacks.

    It resolves through /etc/hosts, which Coi wrote from the same answer it fed the
    firewall. There is no second source of addresses, so the two cannot disagree.
    """
    name = start_ready_container(coi_binary, workspace_dir)

    ips = resolve_in_container(coi_binary, name, ROTATING_HOST)
    assert ips, f"the container could not resolve the allowlisted host {ROTATING_HOST}"

    table = nft_coi_table()
    missing = [ip for ip in ips if ip not in table]
    assert not missing, (
        f"the container resolved {ROTATING_HOST} to {missing}, but those addresses are not in the "
        f"firewall — a connection to them would be rejected. This is the divergence the design "
        f"exists to make impossible.\n\n{table}"
    )


def test_hosts_file_holds_every_address_and_is_delimited(
    coi_binary, workspace_dir, cleanup_containers
):
    """Coi's managed block must carry every address, without clobbering the rest of /etc/hosts.

    A rotating frontend answers with several addresses and the container may pick
    any of them; writing only the first would leave it working until that one
    address went away.
    """
    name = start_ready_container(coi_binary, workspace_dir)

    rc, content = container_exec(coi_binary, name, "cat /etc/hosts")
    assert rc == 0, f"could not read /etc/hosts: {content}"

    assert "BEGIN coi allowlist" in content, f"Coi's managed block is missing:\n{content}"
    assert "END coi allowlist" in content, f"Coi's managed block is unterminated:\n{content}"

    # Everything outside the markers must survive — the container needs localhost.
    assert "localhost" in content, f"the pre-existing hosts entries were clobbered:\n{content}"

    for host in (ROTATING_HOST, "registry.npmjs.org"):
        assert host in content, f"{host} is allowlisted but absent from /etc/hosts:\n{content}"

    # Every address in the file must also be in the firewall.
    table = nft_coi_table()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == ROTATING_HOST:
            assert parts[0] in table, (
                f"/etc/hosts offers the container {parts[0]} for {ROTATING_HOST}, "
                f"but the firewall does not allow it\n{table}"
            )


def test_dns_is_blocked_entirely(coi_binary, workspace_dir, cleanup_containers):
    """The container must have no route to any nameserver.

    Leave it one and it can resolve a name to an address the firewall has never
    seen, which is the whole failure mode. Both directions have to be closed: an
    off-box resolver (forwarded, caught by the forward chain) and the bridge's own
    dnsmasq (addressed to the HOST, so it never traverses the forward chain and
    needs an input rule).
    """
    name = start_ready_container(coi_binary, workspace_dir)

    _, gateway_out = container_exec(coi_binary, name, "ip route | awk '/default/ {print $3}'")
    gateway = gateway_out.strip().splitlines()[-1] if gateway_out.strip() else ""
    assert gateway, f"could not determine the container's gateway: {gateway_out!r}"

    # The bridge's own resolver. This is the one that needs an INPUT rule: its
    # traffic is addressed to the host, so it never traverses the forward chain and
    # a forward-only block would leave it wide open.
    _, bridge_dns = container_exec(coi_binary, name, f"dig +time=2 +tries=1 @{gateway} example.com")
    assert "NOERROR" not in bridge_dns, (
        f"the container resolved a name via the bridge resolver at {gateway} — DNS is not blocked "
        f"and the allowlist can be bypassed\n{bridge_dns}"
    )

    # An off-box resolver, caught by the forward chain.
    _, public_dns = container_exec(coi_binary, name, "dig +time=2 +tries=1 @8.8.8.8 example.com")
    assert "NOERROR" not in public_dns, (
        f"the container resolved a name via 8.8.8.8 — DNS is not blocked\n{public_dns}"
    )


def test_hijacking_resolv_conf_gains_nothing(coi_binary, workspace_dir, cleanup_containers):
    """Root inside the container can rewrite resolv.conf, and it buys them nothing.

    DNS egress is blocked at the host, so pointing the resolver anywhere at all is
    inert. The allowlisted names still resolve (they come from /etc/hosts), and
    everything else still does not.
    """
    name = start_ready_container(coi_binary, workspace_dir)

    rc, out = container_exec(coi_binary, name, "echo 'nameserver 8.8.8.8' > /etc/resolv.conf")
    assert rc == 0, f"could not rewrite resolv.conf: {out}"

    # Allowlisted names keep working: they never needed DNS.
    allowed = resolve_in_container(coi_binary, name, ROTATING_HOST)
    assert allowed, "an allowlisted host should still resolve from /etc/hosts after the hijack"

    # Anything else still does not resolve.
    denied = resolve_in_container(coi_binary, name, "example.com")
    assert not denied, (
        f"example.com resolved to {denied} after resolv.conf was pointed at 8.8.8.8 — "
        "DNS is not actually blocked and the allowlist can be bypassed"
    )


def test_unlisted_domain_is_unreachable(coi_binary, workspace_dir, cleanup_containers):
    """A host outside the allowlist has no address and no route."""
    name = start_ready_container(coi_binary, workspace_dir)

    assert not resolve_in_container(coi_binary, name, "example.com"), (
        "example.com is not allowlisted"
    )

    rc, _ = container_exec(
        coi_binary, name, "curl -s --max-time 8 -o /dev/null -w '%{http_code}' https://example.com"
    )
    assert rc != 0, "a non-allowlisted host must not be reachable"


def test_allowlisted_domain_is_reachable(coi_binary, workspace_dir, cleanup_containers):
    """The allowlist has to actually work, not merely block."""
    name = start_ready_container(coi_binary, workspace_dir)

    rc, out = container_exec(
        coi_binary,
        name,
        "curl -s --max-time 20 -o /dev/null -w '%{http_code}' https://registry.npmjs.org",
        timeout=40,
    )
    assert rc == 0, f"an allowlisted host must be reachable: {out}"
    assert "200" in out or "30" in out, f"unexpected status from an allowlisted host: {out}"


def test_wildcard_fails_loudly(coi_binary, workspace_dir, cleanup_containers):
    """A wildcard cannot be honoured, so it must not start a container.

    Allowlist mode resolves each name up front and writes the answer into
    /etc/hosts. A wildcard has no answer to write — you cannot know which
    subdomains will be asked for. The old resolver pretended otherwise: it stripped
    the "*." and resolved the BASE domain, whose addresses have no overlap with the
    subdomains actually dialled, leaving a firewall that permitted addresses
    nothing would ever connect to.
    """
    bad_config = """
[network]
mode = "allowlist"
allowed_domains = [
    "*.googleapis.com",
]
"""
    name, result = start_allowlist_container(coi_binary, workspace_dir, bad_config)

    assert result.returncode != 0, (
        f"a wildcard cannot be enforced and must fail the launch, but the container started (name={name})"
    )
    output = result.stdout + result.stderr
    assert "exact hostnames" in output or "CIDR" in output, (
        f"the error must tell the user what to write instead:\n{output}"
    )


def test_literal_addresses_need_no_dns(coi_binary, workspace_dir, cleanup_containers):
    """Raw IPs and CIDRs go straight into the static set; no resolution involved."""
    config = """
[network]
mode = "allowlist"
allowed_domains = [
    "1.1.1.1",
    "8.8.4.0/24",
    "registry.npmjs.org",
]
"""
    name = start_ready_container(coi_binary, workspace_dir, config)

    ident = container_ip(name).replace(".", "_")
    result = subprocess.run(
        ["sudo", "-n", "nft", "list", "set", "ip", "coi", f"coi_s_{ident}"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, f"could not read the static set: {result.stderr}"
    for literal in ("1.1.1.1", "8.8.4.0/24"):
        assert literal in result.stdout, (
            f"literal entry {literal} should be in the static set\n{result.stdout}"
        )


def test_teardown_removes_rules_and_sets(coi_binary, workspace_dir, cleanup_containers):
    """Teardown must remove forward rules, the input-chain DNS block, and both sets.

    Order matters: the kernel refuses to drop a set a rule still references.
    """
    name = start_ready_container(coi_binary, workspace_dir)
    ip = container_ip(name)
    ident = ip.replace(".", "_")
    assert f"coi_d_{ident}" in nft_coi_table(), "the dynamic set should exist while running"

    delete_result = subprocess.run(
        [coi_binary, "container", "delete", name, "--force"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    # Teardown's nft cleanup runs inside `container delete`, but under heavy CI
    # load the sudo-nft operations can lag behind the command returning, so a
    # 30s window occasionally misread a slow-but-eventual cleanup as a leak. Poll
    # generously; a genuine leak (rules never removed) still fails red after the
    # budget, and the delete result is surfaced so a real failure is diagnosable.
    deadline = time.time() + 75
    while time.time() < deadline:
        table = nft_coi_table()
        input_chain = subprocess.run(
            ["sudo", "-n", "nft", "list", "chain", "ip", "coi", "input"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout
        # Boundary-anchored matching: a plain substring check made this test
        # the victim of ANY same-prefix leak — "coi_s_10_47_62_2" is a prefix
        # of "coi_s_10_47_62_232", so another container's leaked sets failed
        # THIS container's (successful) teardown assertion.
        if (
            not re.search(rf"coi_s_{ident}\b", table)
            and not re.search(rf"coi_d_{ident}\b", table)
            and not re.search(rf"{re.escape(ip)}\b", input_chain)
        ):
            return
        time.sleep(1)

    raise AssertionError(
        f"allowlist rules or sets for {ip} survived teardown after 75s "
        f"(container delete rc={delete_result.returncode}, stderr={delete_result.stderr!r})\n"
        f"coi table:\n{nft_coi_table()}"
    )


def test_allowlist_metadata_literal_stays_blocked_and_ordered_first(
    coi_binary, workspace_dir, cleanup_containers
):
    """A cloud-metadata literal in allowed_domains does not become reachable.

    policy.go puts ANY IPv4 literal — including 169.254.169.254 — into the static
    accept set, so the 169.254.0.0/16 reject MUST be ordered BEFORE that set-accept
    or the literal slips straight through (a real, previously-shipped SSRF ordering
    bug — a name→metadata rebind would then reach the credential endpoint). A real
    allowlisted host still works, proving the allowlist is functional, not just
    blocking everything.
    """
    config = (
        "[network]\n"
        'mode = "allowlist"\n'
        'allowed_domains = ["registry.npmjs.org", "169.254.169.254"]\n'
        "allow_local_network_access = false\n"
    )
    name = start_ready_container(coi_binary, workspace_dir, config)

    # The allowlist is FUNCTIONAL: a real allowlisted host is reachable.
    rc, out = container_exec(
        coi_binary,
        name,
        "curl -s --max-time 20 -o /dev/null -w '%{http_code}' https://registry.npmjs.org",
        timeout=40,
    )
    assert rc == 0, f"an allowlisted host must be reachable: {out}"

    # ...but the metadata literal is blocked despite being in allowed_domains.
    rc, out = container_exec(
        coi_binary,
        name,
        "curl -s --max-time 8 -o /dev/null -w '%{http_code}' http://169.254.169.254/",
    )
    assert rc != 0, f"the metadata endpoint must be blocked even when in allowed_domains: {out}"

    # The load-bearing guard: in the container's forward chain the 169.254.0.0/16
    # reject must PRECEDE the allowlist set-accept, so a set member in that range is
    # rejected before the accept is reached. (nft evaluates rules top to bottom;
    # `sudo -n nft` matches the pattern the other network tests use.)
    cip = container_ip(name)
    assert cip, "could not determine container IP"
    chain = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", "ip", "coi", "forward"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    ).stdout
    rules = [ln for ln in chain.splitlines() if cip in ln]
    reject_idx = next(
        (i for i, ln in enumerate(rules) if "169.254.0.0/16" in ln and "reject" in ln), None
    )
    accept_idx = next((i for i, ln in enumerate(rules) if "@" in ln and "accept" in ln), None)
    assert reject_idx is not None, f"169.254.0.0/16 reject rule not found for {cip}:\n{chain}"
    assert accept_idx is not None, f"allowlist set-accept rule not found for {cip}:\n{chain}"
    assert reject_idx < accept_idx, (
        "the 169.254.0.0/16 reject must precede the allowlist set-accept (SSRF ordering "
        f"guard); got reject@{reject_idx}, set-accept@{accept_idx}:\n{chain}"
    )


def test_allowlist_etc_hosts_overwrite_is_rejected_by_firewall(
    coi_binary, workspace_dir, cleanup_containers
):
    """Repointing an allowlisted name in /etc/hosts at a non-set address gains nothing.

    An agent with root inside the container can overwrite /etc/hosts, but the nft set
    is the boundary: "an address it invents is an address the firewall rejects; the
    failure is closed and self-inflicted" (internal/network/hosts.go). We repoint an
    allowlisted name at 1.1.1.1 — a LIVE public IP that is not in the set — so a
    bypassable firewall WOULD connect; the firewall must reject it despite the name
    resolving. (HTTP, not HTTPS: a TLS cert mismatch against 1.1.1.1 would make curl
    fail regardless of the firewall and defeat the distinguisher.)
    """
    config = (
        "[network]\n"
        'mode = "allowlist"\n'
        'allowed_domains = ["registry.npmjs.org"]\n'
        "allow_local_network_access = false\n"
    )
    name = start_ready_container(coi_binary, workspace_dir, config)

    # Baseline: the allowlisted name is reachable via Coi's /etc/hosts -> set IP.
    rc, out = container_exec(
        coi_binary,
        name,
        "curl -s --max-time 20 -o /dev/null -w '%{http_code}' https://registry.npmjs.org",
        timeout=40,
    )
    assert rc == 0, f"the allowlisted host should be reachable before the hijack: {out}"

    # Hijack: OVERWRITE /etc/hosts so the name resolves ONLY to 1.1.1.1 (live, not in
    # the set). Overwriting — not prepending — is essential: getaddrinfo (what curl
    # uses) returns EVERY matching entry, so leaving Coi's managed entry in place lets
    # curl try 1.1.1.1, get rejected, and then FALL BACK to the still-listed real IP
    # (which IS in the set) and succeed. getent ahostsv4 shows what curl will try.
    rc, out = container_exec(
        coi_binary,
        name,
        "printf '127.0.0.1 localhost\\n1.1.1.1 registry.npmjs.org\\n' | sudo tee /etc/hosts "
        ">/dev/null && getent ahostsv4 registry.npmjs.org",
    )
    assert rc == 0 and "1.1.1.1" in out and "104.16" not in out, (
        f"the hijack must leave ONLY 1.1.1.1 for the name (no fall-back IP): {out}"
    )

    # The connection must now be REJECTED: 1.1.1.1 is live (a bypassable firewall
    # would connect), but it is not in the allowlist set.
    rc, out = container_exec(
        coi_binary,
        name,
        "curl -s --max-time 8 -o /dev/null -w '%{http_code}' http://registry.npmjs.org",
    )
    assert rc != 0, (
        "repointing an allowlisted name at a non-set address must be rejected by the "
        f"firewall — /etc/hosts is not the security boundary. Got rc={rc}, out={out}"
    )
