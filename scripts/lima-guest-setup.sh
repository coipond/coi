#!/usr/bin/env bash
# Provision the Lima guest for the CI lima-smoke lane (issue #543).
#
# Runs INSIDE the guest (via `limactl shell`) as the Lima guest user — same
# name/uid as the host runner user (uid 1001), passwordless sudo. The guest's
# own $HOME is native fs (/home/<user>.guest); the host $HOME is virtiofs-
# mounted at the host path, which is how this script, the repo, and the staged
# image tarballs are visible here.
#
# Mirrors the runner-side setup in .github/workflows/ci.yml (Zabbly install
# block, incus preseed, Coi open-mode config, image import-or-build) so the
# guest environment cannot drift from what the native lanes test.
#
# Args:
#   $1  repo dir (host path == guest path via the virtiofs mount)
#   $2  coi image tarball path (may not exist => build in-guest)
#   $3  ubuntu base image tarball path (may not exist => skip, tests don't need it)
set -euo pipefail

REPO_DIR="${1:?usage: lima-guest-setup.sh <repo-dir> <coi-tarball> <base-tarball>}"
COI_TARBALL="${2:-}"
BASE_TARBALL="${3:-}"

echo "=== preconditions: the exact environment this lane exists to exercise ==="
# The literal predicate isColimaOrLimaEnvironment() evaluates
# (internal/session/setup_helpers.go): virtiofs present in /proc/mounts.
grep -q virtiofs /proc/mounts || {
    echo "FATAL: no virtiofs mount in guest /proc/mounts — Colima/Lima detection would be false"
    exit 1
}
[ -d "$REPO_DIR" ] || {
    echo "FATAL: repo dir $REPO_DIR not visible in guest (virtiofs mount broken?)"
    exit 1
}
if [ "$(id -u)" -eq 1000 ]; then
    echo "WARNING: guest uid is 1000 — the #530 uid-mismatch/raw.idmap path will not be exercised"
fi
if ! touch "$REPO_DIR/.virtiofs-write-probe"; then
    echo "FATAL: virtiofs mount is not writable (pytest needs to write caches into the checkout)"
    exit 1
fi
rm -f "$REPO_DIR/.virtiofs-write-probe"
echo "guest uid=$(id -u) HOME=$HOME (guest-native) repo=$REPO_DIR"
grep virtiofs /proc/mounts | head -3

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
# tmux is mandatory: the pytest cleanup_containers fixture runs `tmux kill-server`
# unconditionally (tests/conftest.py) and a missing binary raises FileNotFoundError.
sudo apt-get install -y btrfs-progs tmux nftables python3-venv curl ca-certificates

echo "=== Incus: Zabbly stable with Ubuntu-archive fallback (mirrors ci.yml) ==="
sudo mkdir -p /etc/apt/keyrings/
ZABBLY_SOURCES=/etc/apt/sources.list.d/zabbly-incus-stable.sources
if sudo curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 5 \
    https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc 2>/dev/null; then
    CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME}")
    ARCH=$(dpkg --print-architecture)
    sudo tee "$ZABBLY_SOURCES" >/dev/null <<SOURCES
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${CODENAME}
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/zabbly.asc
SOURCES
    echo "Zabbly repo configured"
else
    echo "WARNING: Zabbly repo unreachable, will use Ubuntu-archive incus"
fi
sudo apt-get update
if ! sudo apt-get install -y incus; then
    echo "WARNING: install failed, removing Zabbly repo and falling back to Ubuntu-archive incus"
    sudo rm -f "$ZABBLY_SOURCES"
    sudo apt-get update
    sudo apt-get install -y incus
fi
incus version || incus --version || true

echo "=== subuid/subgid for raw.idmap (mirrors ci.yml, uid parametrized) ==="
sudo systemctl start incus.socket || true
sleep 3
echo "root:$(id -u):1" | sudo tee -a /etc/subuid
echo "root:$(id -g):1" | sudo tee -a /etc/subgid
# The Zabbly package grants root a wide range on install; the Ubuntu-archive
# fallback may not — unprivileged containers need one, so add it guardedly.
grep -q '^root:1000000:' /etc/subuid || echo 'root:1000000:1000000000' | sudo tee -a /etc/subuid
grep -q '^root:1000000:' /etc/subgid || echo 'root:1000000:1000000000' | sudo tee -a /etc/subgid
sudo systemctl restart incus || true
sleep 5

echo "=== incus admin init (ci.yml preseed; btrfs pool shrunk 25->12GiB for the 30GiB guest disk) ==="
sudo incus admin init --preseed <<'EOF'
config:
  images.compression_algorithm: none
networks:
- config:
    ipv4.address: 10.47.62.1/24
    ipv4.nat: "true"
    ipv6.address: none
  name: incusbr0
  type: bridge
storage_pools:
- config:
    size: 12GiB
  name: default
  driver: btrfs
profiles:
- config: {}
  devices:
    eth0:
      name: eth0
      network: incusbr0
      type: nic
    root:
      path: /
      pool: default
      type: disk
  name: default
EOF

# Allow incus access from this and any later `limactl shell` session without
# re-login (group membership does not refresh over Lima's SSH ControlMaster) —
# same socket-permission pattern the native lanes use (ci.yml).
sudo chmod 666 /var/lib/incus/unix.socket
sudo usermod -aG incus-admin "$USER"
incus network list

# Open mode still adds nft ACCEPT rules (internal/network); mirror the native
# lanes' passwordless nft sudo rule (visudo-validated, atomic install).
bash "$REPO_DIR/scripts/install-sudoers-dropin.sh" "#$(id -u) ALL=(ALL) NOPASSWD: /usr/sbin/nft *" /etc/sudoers.d/coi-nft
# Container internet for the cache-miss `coi build` path.
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null

echo "=== coi binary -> guest-native path; setcap there (virtiofs xattrs are unreliable) ==="
sudo install -m 0755 "$REPO_DIR/coi" /usr/local/bin/coi
sudo setcap cap_linux_immutable=ep /usr/local/bin/coi || echo "WARNING: setcap failed (non-fatal for the smoke set)"
getcap /usr/local/bin/coi || true
/usr/local/bin/coi version

echo "=== Coi config + python venv in the guest-native \$HOME (not the mount) ==="
mkdir -p "$HOME/.coi"
printf '[network]\nmode = "open"\n' > "$HOME/.coi/config.toml"
python3 -m venv "$HOME/venv"
"$HOME/venv/bin/pip" install -q --upgrade pip
# Same requirements file the runner-side lanes install => zero dependency drift.
"$HOME/venv/bin/pip" install -q -r "$REPO_DIR/tests/support/requirements.txt"

echo "=== images: import staged cache tarballs, else build in-guest with retries (mirrors ci.yml) ==="
if [ -n "$BASE_TARBALL" ] && [ -f "$BASE_TARBALL" ]; then
    incus image import "$BASE_TARBALL" --alias coi-ubuntu-24.04 || echo "WARNING: base image import failed (smoke tests don't need it)"
else
    echo "no staged base image tarball (smoke tests don't need it)"
fi
if [ -n "$COI_TARBALL" ] && [ -f "$COI_TARBALL" ]; then
    incus image import "$COI_TARBALL" --alias coi-default
else
    echo "coi image cache miss: building inside the guest"
    cd "$REPO_DIR"
    # 15-minute cap per attempt (the pattern the old macOS Colima lane used):
    # a wedged build/publish must fail the attempt, not hang until job timeout.
    for attempt in 1 2 3; do
        if timeout 900 /usr/local/bin/coi build; then
            echo "image built on attempt $attempt"
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            echo "FATAL: coi build failed after 3 attempts"
            exit 1
        fi
        echo "build failed or timed out (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done
fi
incus image list

echo "=== guest provisioning complete ==="
