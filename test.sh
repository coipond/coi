#!/usr/bin/env bash
set -euo pipefail

NAME=incus-lab
INSTALL_URL=https://raw.githubusercontent.com/coipond/coi/refs/heads/feat/storage-pool-sizing/install.sh

incus delete -f "$NAME" 2>/dev/null || true

incus launch images:ubuntu/24.04/cloud "$NAME" --vm \
  -c limits.cpu=4 -c limits.memory=8GiB -d root,size=40GiB

until incus exec "$NAME" -- true 2>/dev/null; do sleep 2; done
incus exec "$NAME" -- cloud-init status --wait || true

#incus exec "$NAME" -- su -l ubuntu -c "curl -fsSL $INSTALL_URL | bash"

echo "Done. Shell: incus exec $NAME -- su -l ubuntu"
