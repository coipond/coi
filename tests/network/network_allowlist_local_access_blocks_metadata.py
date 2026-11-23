"""
Test for network isolation - allowlist mode with allow_local_network_access
still rejects the cloud metadata endpoint under block_metadata_endpoint.

Tests that:
1. The 169.254.0.0/16 reject comes before the allowlist set accepts
2. A request to an allowlisted 169.254.169.254 fails and hits that reject
3. With block_metadata_endpoint = false, coi accepts the same request

Both settings are trusted-scope only, so the config goes through COI_CONFIG.
"""

from support.helpers import (
    container_forward_rules,
    container_ipv4,
    count_forward_rules,
    exec_in,
    forward_rule_packets,
    start_background_shell,
    wait_for_forward_rule,
    write_trusted_coi_config,
)

METADATA_RANGE = "ip daddr 169.254.0.0/16"
STATIC_PORT_SET = "@coi_sp_"
CURL_METADATA = "curl -s -o /dev/null --connect-timeout 5 http://169.254.169.254/"


def _start(coi_binary, workspace_dir, block_metadata):
    env = write_trusted_coi_config(
        "[network]\n"
        'mode = "allowlist"\n'
        'allowed_domains = ["169.254.169.254:80"]\n'
        "allow_local_network_access = true\n"
        f"block_metadata_endpoint = {str(block_metadata).lower()}\n"
    )
    name, _ = start_background_shell(coi_binary, workspace_dir, env, timeout=90)
    ip = container_ipv4(name)
    assert ip, f"no IPv4 address for {name}"
    # The allowlist rules apply as one batch: once the set accept is there,
    # so is everything before it.
    assert wait_for_forward_rule(ip, STATIC_PORT_SET) >= 0, (
        f"allowlist rules for {name} did not appear: {container_forward_rules(ip)}"
    )
    return name, ip


def test_allowlist_local_access_blocks_metadata(coi_binary, workspace_dir, cleanup_containers):
    """
    Flow:
    1. Start allowlist mode with local access, block_metadata_endpoint = true
       and 169.254.169.254:80 allowlisted
    2. Check the metadata reject precedes the set accepts; count its packets
    3. curl 169.254.169.254: it fails and the reject counter is > 0
    """
    name, ip = _start(coi_binary, workspace_dir, block_metadata=True)

    rules = [text for _, text in container_forward_rules(ip)]
    reject = next((i for i, t in enumerate(rules) if METADATA_RANGE in t and "reject" in t), -1)
    accept = next(i for i, t in enumerate(rules) if STATIC_PORT_SET in t)
    assert 0 <= reject < accept, f"metadata reject must precede the set accepts: {rules}"

    assert count_forward_rules(ip, METADATA_RANGE) > 0

    code, output = exec_in(coi_binary, name, CURL_METADATA, timeout=30)
    assert code != 0, f"169.254.169.254 must be unreachable, got exit 0: {output}"
    assert forward_rule_packets(ip, METADATA_RANGE) > 0, (
        f"the metadata reject took no packets: {container_forward_rules(ip)}"
    )


def test_allowlist_local_access_metadata_not_blocked(coi_binary, workspace_dir, cleanup_containers):
    """
    Flow:
    1. Same setup with block_metadata_endpoint = false
    2. No metadata reject; count the set accept's packets
    3. curl 169.254.169.254: the set accept takes it (coi does not reject it)
    """
    name, ip = _start(coi_binary, workspace_dir, block_metadata=False)

    rules = [text for _, text in container_forward_rules(ip)]
    assert not any(METADATA_RANGE in t for t in rules), f"unexpected metadata rule: {rules}"

    assert count_forward_rules(ip, STATIC_PORT_SET) > 0

    exec_in(coi_binary, name, CURL_METADATA, timeout=30)
    assert forward_rule_packets(ip, STATIC_PORT_SET) > 0, (
        f"the allowlist accept took no packets: {container_forward_rules(ip)}"
    )
