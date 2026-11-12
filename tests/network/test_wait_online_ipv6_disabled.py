"""
Regression test for issue #548 — systemd-networkd-wait-online must not hang
when coi disables IPv6 in the container.

In restricted/allowlist mode coi disables IPv6 (DisableIPv6AtBoot pre-start +
the network manager's prepareContainer post-start). With IPv6 kernel-disabled, systemd-networkd
otherwise keeps failing to add the IPv6 link-local address, so eth0 never leaves
the "configuring" setup state and systemd-networkd-wait-online — hence
network-online.target and everything ordered after it (docker.service, and the
reporter's ollama.service) — hangs indefinitely.

The fix pre-seeds an IPv4-only networkd config (05-coi-ipv4-only.network) so the
link reaches "configured" and wait-online completes. This test drives `coi run`
(the session-setup path, not `coi container launch`) in restricted mode on the
systemd coi-default image and asserts the boot transaction settles with
wait-online no longer queued. It runs a few times because the pre-fix hang was
an intermittent race between the IPv6 disable and networkd's boot config.

Lives in the `network` CI group (`tests/network`), which stands up the
restricted-mode nft/firewall environment.
"""

import os
import subprocess

import pytest

# Runs inside the coi container. Polls until the boot transaction is TERMINAL
# (running/degraded) rather than using a fixed sleep. The #548 hang is precisely
# "boot never becomes terminal because systemd-networkd-wait-online is wedged",
# so reaching a terminal state IS the proof the fix worked. We deliberately do
# NOT break early on eth0 reaching "(configured)": networkd can finish a few
# seconds before the rest of the boot transaction, and sampling then would see a
# still-"starting" system that is perfectly healthy (a false failure).
_BOOT_INSPECT = r"""
set +e
for _ in $(seq 1 60); do
  s=$(systemctl is-system-running 2>/dev/null)
  case "$s" in running|degraded) break;; esac
  sleep 1
done
echo "SYSTEM_STATE=$(systemctl is-system-running 2>/dev/null)"
# Prove wait-online is actually part of the boot path — otherwise a green result
# would be meaningless ("nothing to hang on" rather than "fix works").
echo "WAIT_ONLINE_ENABLED=$(systemctl is-enabled systemd-networkd-wait-online.service 2>/dev/null)"
echo "=== list-jobs ==="
systemctl list-jobs --no-legend 2>/dev/null
echo "=== networkctl eth0 ==="
networkctl status eth0 --no-pager 2>/dev/null | sed -n '1,12p'
"""


def _set_restricted(workspace_dir):
    coi_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(coi_dir, exist_ok=True)
    with open(os.path.join(coi_dir, "config.toml"), "a") as f:
        f.write('\n[network]\nmode = "restricted"\n')


@pytest.mark.parametrize("attempt", range(1, 4))
def test_wait_online_not_stuck_when_ipv6_disabled(
    coi_binary, cleanup_containers, workspace_dir, attempt
):
    _set_restricted(workspace_dir)

    result = subprocess.run(
        [coi_binary, "run", "--workspace", workspace_dir, "--", "bash", "-lc", _BOOT_INSPECT],
        capture_output=True,
        text=True,
        timeout=150,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, f"coi run failed (attempt {attempt}):\n{out}"

    # Guard against a false pass: if the image ever stops shipping wait-online in
    # the boot path, "not queued" would be trivially true. Require it to be a real
    # unit so this test keeps exercising the #548 mechanism.
    assert "WAIT_ONLINE_ENABLED=" in out, f"probe did not run:\n{out}"
    wait_online_status = out.split("WAIT_ONLINE_ENABLED=", 1)[1].splitlines()[0].strip()
    assert wait_online_status not in ("", "not-found", "masked"), (
        f"systemd-networkd-wait-online is not in the boot path ({wait_online_status!r}); "
        f"this test no longer exercises #548.\n{out}"
    )

    # Direct proof of the fix: the bug left eth0 stuck at "routable (configuring)".
    # The fix makes it reach "configured". This assertion holds even if wait-online
    # weren't pulled in, so it cannot false-pass on the wedge.
    networkctl_out = out.split("=== networkctl eth0 ===", 1)[-1]
    boot_jobs = out.split("=== list-jobs ===", 1)[1].split("=== networkctl", 1)[0]
    stuck_configuring = "(configuring)" in networkctl_out
    wait_online_queued = "systemd-networkd-wait-online" in boot_jobs
    settled = "SYSTEM_STATE=running" in out or "SYSTEM_STATE=degraded" in out

    assert settled and not stuck_configuring and not wait_online_queued, (
        f"#548 regression (attempt {attempt}): eth0 stuck configuring="
        f"{stuck_configuring}, wait-online queued={wait_online_queued}, settled={settled}.\n{out}"
    )
