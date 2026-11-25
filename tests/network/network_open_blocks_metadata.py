"""
Test for network isolation - open mode rejects the cloud metadata endpoint
under block_metadata_endpoint (the default).

Tests that:
1. The 169.254.0.0/16 reject comes before open mode's accept
2. A request to 169.254.169.254 fails and hits that reject
"""

from support.helpers import (
    container_forward_rules,
    container_ipv4,
    count_forward_rules,
    exec_in,
    forward_rule_packets,
    start_background_shell,
    wait_for_firewall_rules,
    write_trusted_coi_config,
)

METADATA_RANGE = "ip daddr 169.254.0.0/16"


def test_open_blocks_metadata(coi_binary, workspace_dir, cleanup_containers):
    """
    Flow:
    1. Start open mode (block_metadata_endpoint defaults to true)
    2. Check the metadata reject precedes the accept; count its packets
    3. curl 169.254.169.254: it fails and the reject counter is > 0
    """
    env = write_trusted_coi_config('[network]\nmode = "open"\n')
    name, _ = start_background_shell(coi_binary, workspace_dir, env, timeout=90)
    ip = container_ipv4(name)
    assert ip, f"no IPv4 address for {name}"
    accept = f"ip saddr {ip} accept"
    assert wait_for_firewall_rules(name, match=accept), (
        f"open mode rules for {name} did not appear: {container_forward_rules(ip)}"
    )

    rules = [text for _, text in container_forward_rules(ip)]
    reject = next((i for i, t in enumerate(rules) if METADATA_RANGE in t and "reject" in t), -1)
    accept_at = next(i for i, t in enumerate(rules) if t.startswith(accept))
    assert 0 <= reject < accept_at, f"metadata reject must precede the accept: {rules}"

    assert count_forward_rules(ip, METADATA_RANGE) > 0

    code, output = exec_in(
        coi_binary,
        name,
        "curl -s -o /dev/null --connect-timeout 5 http://169.254.169.254/",
        timeout=30,
    )
    assert code != 0, f"169.254.169.254 must be unreachable, got exit 0: {output}"
    assert forward_rule_packets(ip, METADATA_RANGE) > 0, (
        f"the metadata reject took no packets: {container_forward_rules(ip)}"
    )
