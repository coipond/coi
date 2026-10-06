"""
The coi image never boots with cloud-init running (unless opted in).

On Canonical's Ubuntu cloud base (what `coi build` downloads), cloud-init runs
on every boot ordered before the network, delaying each container start and
the DHCP lease coi's network setup waits for. build.sh's configure_boot writes
coi's own eth0 DHCP config and disables cloud-init unless [container.build]
cloud_init = true. (CI imports images:ubuntu/24.04, which ships without
cloud-init — so here the check is "absent or disabled"; the disable logic
itself is unit-tested in internal/image/build_sh_boot_test.go.) The CI image
cache key includes internal/image/**, so the built image carries the change.

The container must still bring eth0 up via coi's DHCP config.
"""

import subprocess

CHECK = (
    "if [ -d /etc/cloud ] || command -v cloud-init >/dev/null 2>&1; then "
    "  test -f /etc/cloud/cloud-init.disabled && echo CI_OFF; "
    "else echo CI_OFF; fi; "
    "test -f /etc/netplan/01-coi-dhcp.yaml && echo NETPLAN_OK; "
    # The command can start before the lease lands (open mode doesn't wait
    # for it), so poll briefly rather than check once.
    "i=0; while [ $i -lt 150 ]; do "
    "  ip -4 -o addr show eth0 | grep -q inet && { echo HAS_IPV4; break; }; "
    "  sleep 0.2; i=$((i+1)); "
    "done; true"
)


def test_cloud_init_off_and_network_up(coi_binary, cleanup_containers, workspace_dir):
    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "sh", "-c", CHECK],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"coi run failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    for marker in ("CI_OFF", "NETPLAN_OK", "HAS_IPV4"):
        assert marker in result.stdout, (
            f"expected {marker} in container output.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
