#!/bin/bash
# Install a sudoers drop-in safely: write the rule to a dot-named temp file in
# the target's directory (sudo's includedir skips names containing '.'),
# validate it with visudo, then rename it into place. An unchecked in-place
# write with a syntax error breaks every sudo on the host — including the one
# needed to repair it — so a rejected rule leaves any existing drop-in untouched.
#
# Mirrors install_sudoers_dropin (install.sh) and sudoersDropinScript
# (internal/health/remediation.go).
#
# Usage: install-sudoers-dropin.sh <rule> <target>
#   e.g. install-sudoers-dropin.sh "#$(id -u) ALL=(ALL) NOPASSWD: /usr/sbin/nft" /etc/sudoers.d/coi-nft
#
# Name users by numeric UID (#1000) or group (%group): a username containing a
# space (AD/SSSD "John Doe") is a sudoers syntax error.

set -euo pipefail

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: $(basename "$0") <rule> <target>" >&2
    exit 2
fi

SUDO="sudo"
[ "$(id -u)" -eq 0 ] && SUDO=""

# The rule and target are positional args to the inner shell, never spliced
# into its script.
# shellcheck disable=SC2016 # expanded by the inner sh, on purpose
$SUDO sh -c '
    tmp="$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX")" || exit 1
    if printf "%s\n" "$1" > "$tmp" && chmod 0440 "$tmp" && visudo -cf "$tmp" >/dev/null; then
        mv -f "$tmp" "$2"
    else
        rm -f "$tmp"
        echo "refusing to install an invalid sudoers rule: $1" >&2
        exit 1
    fi' sh "$1" "$2"
