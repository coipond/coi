"""
The coi image ships with cloud-init disabled by default.

cloud-init runs on every boot of the Ubuntu cloud base, ordered before the
network comes up, so it delayed every container start (and the DHCP lease
coi's network setup waits for). build.sh's configure_boot writes coi's own
eth0 DHCP config and disables cloud-init unless [container.build]
cloud_init = true. The CI image cache key includes internal/image/**, so the
built image carries this — the test runs for real.

That this `coi run` succeeds at all also proves the container still gets its
DHCP lease without cloud-init (network setup waits for it).
"""

import subprocess


def test_cloud_init_disabled_and_network_up(coi_binary, cleanup_containers, workspace_dir):
    result = subprocess.run(
        [
            coi_binary,
            "run",
            "--workspace",
            workspace_dir,
            "sh",
            "-c",
            "test -f /etc/cloud/cloud-init.disabled && echo CI_DISABLED; "
            "test -f /etc/netplan/01-coi-dhcp.yaml && echo NETPLAN_OK; "
            "ip -4 -o addr show eth0 | grep -q inet && echo HAS_IPV4",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"coi run failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    for marker in ("CI_DISABLED", "NETPLAN_OK", "HAS_IPV4"):
        assert marker in result.stdout, (
            f"expected {marker} in container output.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
