"""
Tests that the coi image's masked guest apparmor.service breaks nothing.

The image masks apparmor.service, which on every boot loaded ~120 profiles
into the container's own AppArmor namespace. These tests pin down that:

1. apparmor.service is masked and the guest's profile set is not loaded
2. Docker still runs containers, still confined by its own docker-default
   AppArmor profile (Docker loads that itself, not via apparmor.service)
3. Playwright still launches headless Chromium (its default no-sandbox mode,
   which is also the only mode that worked with the guest profiles loaded)
"""

import re
import subprocess
import time
from pathlib import Path

import pytest

from support.helpers import calculate_container_name, exec_in

# One line of /sys/kernel/security/apparmor/profiles, e.g. "docker-default (enforce)".
PROFILE_LINE = re.compile(r"^\S.* \((?:enforce|complain|kill|unconfined|prompt)\)$", re.MULTILINE)


def host_apparmor_enabled():
    try:
        return Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    except OSError:
        return False


def launch(coi_binary, workspace_dir):
    container_name = calculate_container_name(workspace_dir, 1)
    result = subprocess.run(
        [coi_binary, "container", "launch", "coi-default", container_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"Container launch should succeed. stderr: {result.stderr}"
    time.sleep(5)
    return container_name


def delete(coi_binary, container_name):
    subprocess.run(
        [coi_binary, "container", "delete", container_name, "--force"],
        capture_output=True,
        timeout=30,
    )


def test_guest_apparmor_masked_and_docker_confined(coi_binary, cleanup_containers, workspace_dir):
    """apparmor.service is masked, yet Docker works and is still AppArmor-confined."""
    container_name = launch(coi_binary, workspace_dir)

    # === Phase 1: the guest does not load its profile set ===

    # is-enabled exits non-zero for a masked unit, so only its output matters.
    _, output = exec_in(coi_binary, container_name, "systemctl is-enabled apparmor.service")
    assert re.search(r"^masked$", output, re.MULTILINE), (
        f"apparmor.service should be masked in the image. output: {output}"
    )

    if host_apparmor_enabled():
        # Ubuntu's set has ~120 profiles, unprivileged_userns among them. With
        # the service masked, only profiles other tools load themselves (e.g.
        # docker-default) may be present.
        rc, output = exec_in(
            coi_binary, container_name, "cat /sys/kernel/security/apparmor/profiles"
        )
        assert rc == 0, f"Reading loaded profiles failed. output: {output}"
        profiles = PROFILE_LINE.findall(output)
        assert len(profiles) < 10, f"Guest profile set should not be loaded, got: {profiles}"
        assert not any(p.startswith("unprivileged_userns ") for p in profiles), (
            f"unprivileged_userns should not be loaded, got: {profiles}"
        )

    # === Phase 2: Docker runs containers, as root and as the code user ===

    exec_in(coi_binary, container_name, "systemctl start docker")
    rc, output = exec_in(
        coi_binary,
        container_name,
        "for i in $(seq 30); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1",
        timeout=60,
    )
    assert rc == 0, f"Docker daemon should come up. output: {output}"

    rc, output = exec_in(
        coi_binary,
        container_name,
        "docker run --rm ghcr.io/coipond/alpine:latest echo 'Docker works!'",
        timeout=120,
    )
    assert rc == 0 and "Docker works!" in output, f"docker run should succeed. output: {output}"

    rc, output = exec_in(
        coi_binary,
        container_name,
        "docker run --rm ghcr.io/coipond/alpine:latest echo 'Docker without sudo works!'",
        user=1000,
        timeout=120,
    )
    assert rc == 0 and "Docker without sudo works!" in output, (
        f"docker run as the code user should succeed. output: {output}"
    )

    # === Phase 3: Docker's own AppArmor confinement still applies ===

    if host_apparmor_enabled():
        rc, output = exec_in(
            coi_binary,
            container_name,
            "docker run --rm ghcr.io/coipond/alpine:latest cat /proc/self/attr/current",
            timeout=60,
        )
        assert rc == 0, f"docker run should succeed. output: {output}"
        assert "docker-default (enforce)" in output, (
            f"Docker containers should still run under docker-default. output: {output}"
        )

    delete(coi_binary, container_name)


# Pinned so a new Playwright release can't break this test. The setup downloads
# Chromium's headless shell and its apt dependencies, so it needs network; it
# takes ~35s in CI.
PLAYWRIGHT_VERSION = "1.64.0"

# Each download attempt is capped inside the container, so a stalled one stops
# there instead of running on under the next attempt.
PLAYWRIGHT_SETUP_TIMEOUT_SEC = 120
PLAYWRIGHT_SETUP_ATTEMPTS = 2

# A timed-out install-deps can leave dpkg running and holding apt's lock, so an
# attempt first waits for it and finishes its half-done work.
PLAYWRIGHT_SETUP_SCRIPT = r"""
while pgrep -x dpkg >/dev/null; do sleep 1; done
sudo dpkg --configure -a
timeout --kill-after=10 SETUP_TIMEOUT_SEC bash -ec '
mkdir -p ~/pw && cd ~/pw
npm init -y >/dev/null
npm install --silent playwright@PLAYWRIGHT_VERSION >/dev/null
sudo -E env "PATH=$PATH" npx playwright install-deps chromium >/dev/null
npx playwright install --only-shell chromium >/dev/null
'
""".replace("PLAYWRIGHT_VERSION", PLAYWRIGHT_VERSION).replace(
    "SETUP_TIMEOUT_SEC", str(PLAYWRIGHT_SETUP_TIMEOUT_SEC)
)

PLAYWRIGHT_CHECK_SCRIPT = r"""
set -e
cd ~/pw
cat > check.js <<'EOF'
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.setContent('<h1 id="t">Playwright works!</h1>');
  console.log(await page.textContent('#t'));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
EOF
node check.js
"""


# No reruns: a failed download skips, so only a Chromium launch failure fails
# the test, and a retry would only hide it.
@pytest.mark.flaky(reruns=0)
def test_playwright_headless_chromium_works(coi_binary, cleanup_containers, workspace_dir):
    """Playwright launches headless Chromium as the code user, with default options.

    Skips when the npm, apt or Playwright CDN downloads fail on every attempt.
    """
    container_name = launch(coi_binary, workspace_dir)

    for _ in range(PLAYWRIGHT_SETUP_ATTEMPTS):
        try:
            rc, output = exec_in(
                coi_binary,
                container_name,
                PLAYWRIGHT_SETUP_SCRIPT,
                user=1000,
                timeout=PLAYWRIGHT_SETUP_TIMEOUT_SEC + 60,
            )
        except subprocess.TimeoutExpired as e:
            rc, output = 124, str(e)
        if rc == 0:
            break
    else:
        delete(coi_binary, container_name)
        pytest.skip(
            f"Playwright download failed {PLAYWRIGHT_SETUP_ATTEMPTS} times "
            f"(last rc {rc}, 124 = timed out). output: {output[-1000:]}"
        )

    rc, output = exec_in(coi_binary, container_name, PLAYWRIGHT_CHECK_SCRIPT, user=1000)
    assert rc == 0 and "Playwright works!" in output, (
        f"Playwright should launch headless Chromium. output: {output[-3000:]}"
    )

    delete(coi_binary, container_name)
