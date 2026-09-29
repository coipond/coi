"""
Integration tests for [[network.hosts]] and `coi hosts` (#605).

Static host entries are written into the container's /etc/hosts with firewall
reachability matched to the network mode. These tests exercise the observable
name-resolution behavior (the firewall classification is unit-tested in
internal/network). Public IPs are used so no mode-specific firewall setup is
required for the CLI round-trip.
"""

import os
import subprocess

from support.helpers import calculate_container_name, write_trusted_coi_config


def test_network_hosts_config_resolves_in_container(coi_binary, cleanup_containers, workspace_dir):
    """A trusted [[network.hosts]] entry resolves inside the container."""
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "open"\n\n'
        "[[network.hosts]]\n"
        'ip = "10.11.12.13"\n'
        'hostnames = ["db.internal", "cache.internal"]\n'
    )
    for name in ("db.internal", "cache.internal"):
        result = subprocess.run(
            [coi_binary, "run", "--workspace", workspace_dir, "--", "getent", "hosts", name],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=workspace_dir,
            env=env,
        )
        combined = result.stdout + result.stderr
        assert "10.11.12.13" in combined, (
            f"{name} should resolve to 10.11.12.13 via /etc/hosts. Got:\n{combined}"
        )


def test_coi_hosts_add_list_remove_roundtrip(coi_binary, cleanup_containers, workspace_dir):
    """`coi hosts add/list/remove` manages a running container's /etc/hosts."""
    container_name = calculate_container_name(workspace_dir, 1)

    launch = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert launch.returncode == 0, f"launch should succeed. stderr: {launch.stderr}"

    # add (public IP → no mode-specific firewall rule needed)
    added = subprocess.run(
        [coi_binary, "hosts", "add", container_name, "8.8.8.8", "dns.test", "resolver.test"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert added.returncode == 0, f"hosts add should succeed. stderr: {added.stderr}"

    # list shows it
    listed = subprocess.run(
        [coi_binary, "hosts", "list", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    list_out = listed.stdout + listed.stderr
    assert "8.8.8.8" in list_out and "dns.test" in list_out, (
        f"hosts list should show the entry. Got:\n{list_out}"
    )

    # it resolves in the container
    resolved = subprocess.run(
        [coi_binary, "container", "exec", container_name, "--", "getent", "hosts", "dns.test"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "8.8.8.8" in (resolved.stdout + resolved.stderr), (
        f"dns.test should resolve to 8.8.8.8 in the container. Got:\n{resolved.stdout}{resolved.stderr}"
    )

    # remove drops it
    removed = subprocess.run(
        [coi_binary, "hosts", "remove", container_name, "dns.test", "resolver.test"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert removed.returncode == 0, f"hosts remove should succeed. stderr: {removed.stderr}"

    listed2 = subprocess.run(
        [coi_binary, "hosts", "list", container_name],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert "dns.test" not in (listed2.stdout + listed2.stderr), (
        f"removed entry must be gone. Got:\n{listed2.stdout}{listed2.stderr}"
    )

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_network_hosts_restricted_private_entry_applies(
    coi_binary, cleanup_containers, workspace_dir
):
    """In restricted mode, a private [[network.hosts]] entry resolves — exercising
    the targeted-allow insert path (setup would fail if the nft insert errored)."""
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "restricted"\n\n'
        "[[network.hosts]]\n"
        'ip = "10.20.30.40"\n'
        'hostnames = ["db.private"]\n'
    )
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "getent", "hosts", "db.private"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )
    combined = result.stdout + result.stderr
    assert "10.20.30.40" in combined, (
        f"db.private should resolve to 10.20.30.40 in restricted mode. Got:\n{combined}"
    )


def test_network_hosts_allowlist_with_local_access_private_entry_applies(
    coi_binary, cleanup_containers, workspace_dir
):
    """In allowlist mode with allow_local_network_access=true, a private
    [[network.hosts]] entry must be accepted and resolve.

    Regression for mensfeld/coi#605 (reported by pbarnes-tibco): setup
    aborted with "... is a private (RFC1918) address, which allowlist mode always
    blocks" even though allow_local_network_access=true installs RFC1918 accept
    rules, so the private target is in fact reachable (adding the /etc/hosts entry
    by hand worked). checkHostReachable now honors allow_local_network_access.
    """
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "allowlist"\n'
        "allow_local_network_access = true\n"
        'allowed_domains = ["github.com"]\n\n'
        "[[network.hosts]]\n"
        'ip = "192.168.1.50"\n'
        'hostnames = ["db.local"]\n'
    )
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "getent", "hosts", "db.local"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )
    combined = result.stdout + result.stderr
    # Assert on the HOSTNAME, not the IP. The pre-fix RFC1918 rejection error
    # ("network.hosts: 192.168.1.50 is a private (RFC1918) address ...") contains
    # the IP itself, so asserting the IP would false-pass while the bug is present.
    # "db.local" appears only in successful `getent hosts` output (IP + name), never
    # in the IP-only rejection error — so it is the unambiguous proof that setup
    # accepted and wrote the private entry rather than aborting.
    assert "db.local" in combined and "192.168.1.50" in combined, (
        "getent must resolve db.local -> 192.168.1.50 in allowlist mode with "
        "allow_local_network_access=true; before the fix, setup aborted and only the "
        "IP (never the hostname) appeared in the RFC1918 rejection error "
        f"(regression mensfeld/coi#605). Got:\n{combined}"
    )


def test_network_hosts_untrusted_project_config_ignored(
    coi_binary, cleanup_containers, workspace_dir
):
    """A project ./.coi/config.toml's [[network.hosts]] is stripped (trusted-scope only)."""
    coi_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(coi_dir, exist_ok=True)
    with open(os.path.join(coi_dir, "config.toml"), "w") as f:
        f.write('[[network.hosts]]\nip = "6.6.6.6"\nhostnames = ["evil.untrusted"]\n')

    # Trusted config: open mode, no hosts of its own.
    env = write_trusted_coi_config('[network]\nmode = "open"\n')
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "--",
            "getent",
            "hosts",
            "evil.untrusted",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=workspace_dir,
        env=env,
    )
    combined = result.stdout + result.stderr
    assert "6.6.6.6" not in combined, (
        f"an untrusted project [[network.hosts]] must NOT be applied (spoofing guard). Got:\n{combined}"
    )
    assert "ignoring" in combined.lower() and "network.hosts" in combined, (
        f"the untrusted network.hosts should be reported as ignored. Got:\n{combined}"
    )


def test_coi_hosts_add_refuses_metadata_ip(coi_binary, cleanup_containers, workspace_dir):
    """`coi hosts add` refuses a link-local/metadata IP in an enforcing mode (SSRF guard)."""
    container_name = calculate_container_name(workspace_dir, 1)
    launch = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert launch.returncode == 0, f"launch should succeed. stderr: {launch.stderr}"

    env = write_trusted_coi_config('[network]\nmode = "restricted"\n')
    result = subprocess.run(
        [coi_binary, "hosts", "add", container_name, "169.254.169.254", "metadata.evil"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, f"a metadata IP must be refused. Got:\n{combined}"
    assert "metadata" in combined.lower() or "169.254" in combined, (
        f"the error should explain the metadata refusal. Got:\n{combined}"
    )

    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )
