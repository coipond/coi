#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="coipond/coi"
BINARY_NAME="coi"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

# Detect non-interactive mode (CI, explicit opt-in, or no usable controlling terminal)
if [ "${NONINTERACTIVE:-0}" = "1" ] || [ "${CI:-}" = "true" ] || ! { true </dev/tty; } 2>/dev/null; then
    NONINTERACTIVE=1
else
    NONINTERACTIVE=0
fi

# Prompt user for yes/no confirmation.
# In non-interactive mode (curl|bash, CI), exits with error since we can't ask.
# In interactive mode, reads from /dev/tty so it works even when script is piped.
prompt_continue() {
    local message="${1:-Continue anyway?}"
    if [ "$NONINTERACTIVE" = "1" ]; then
        echo -e "${YELLOW}⚠ Non-interactive mode: cannot prompt. Aborting.${NC}"
        echo "  Re-run the script directly (not piped) or fix the issue above."
        exit 1
    fi
    # Read a FULL line (not a single char). A single-char read leaves the rest
    # of what the user typed (e.g. the "es" of "yes") in the tty buffer, which
    # the NEXT prompt then mis-reads as its answer. Line reads keep prompts from
    # cross-contaminating.
    read -r -p "$message [y/N] " REPLY </dev/tty || REPLY=""
    if [[ ! $REPLY =~ ^[Yy]([Ee][Ss])?$ ]]; then
        exit 1
    fi
}

# Prompt user for a choice, returning it in REPLY.
# In non-interactive mode, returns the default value.
# In interactive mode, reads a full line from /dev/tty (see prompt_continue for
# why a full line rather than a single char — leftover input corrupts the next
# prompt). Empty input falls back to the default.
prompt_choice() {
    local message="$1"
    local default="$2"
    if [ "$NONINTERACTIVE" = "1" ]; then
        echo -e "${BLUE}→ Non-interactive mode: using default ($default)${NC}"
        REPLY="$default"
        return
    fi
    read -r -p "$message" REPLY </dev/tty || REPLY=""
    if [ -z "$REPLY" ]; then
        REPLY="$default"
    fi
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v zypper &> /dev/null; then
        PKG_MANAGER="zypper"
    else
        PKG_MANAGER="unknown"
    fi
}

# Refresh apt package lists once per run. Fresh container/minimal images ship
# with empty lists, so a bare `apt-get install` fails "Unable to locate package".
# Best-effort: a failed refresh still lets the install try with what's cached.
apt_update_once() {
    [ -n "${APT_LISTS_UPDATED:-}" ] && return 0
    sudo apt-get update -qq || true
    APT_LISTS_UPDATED=1
}

# Install a package using the detected package manager
# Usage: pkg_install <apt-name> [pacman-name] [dnf-name] [zypper-name]
# If a distro-specific name is omitted, the apt name is used as fallback.
pkg_install() {
    local apt_name="$1"
    local pacman_name="${2:-$apt_name}"
    local dnf_name="${3:-$apt_name}"
    local zypper_name="${4:-$apt_name}"

    case "$PKG_MANAGER" in
        apt)    apt_update_once; sudo apt-get install -y "$apt_name" ;;
        pacman) sudo pacman -S --noconfirm "$pacman_name" ;;
        dnf)    sudo dnf install -y "$dnf_name" ;;
        zypper) sudo zypper install -y "$zypper_name" ;;
        *)
            echo -e "${RED}✗ Unknown package manager — install '$apt_name' manually${NC}"
            return 1
            ;;
    esac
}

# Detect OS and architecture
detect_platform() {
    local os
    local arch

    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux*)
            OS="linux"
            ;;
        *)
            echo -e "${RED}✗ Unsupported OS: $os${NC}"
            echo "  Coi requires Linux (Incus is Linux-only)"
            echo "  On macOS: Run inside a Colima or Lima VM"
            echo "  See: https://github.com/coipond/coi/wiki/macOS-Setup-Guide"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}✗ Unsupported architecture: $arch${NC}"
            exit 1
            ;;
    esac

    echo -e "${BLUE}→ Detected platform: ${OS}/${ARCH}${NC}"
}

# Install Incus from the Zabbly stable repository (apt only).
#
# Ubuntu ships Incus 6.0.x, which is below coi's 6.1 minimum, so a plain
# `apt install incus` is a trap on Ubuntu — Zabbly provides a current Incus.
# Also used to UPGRADE an existing too-old Incus (apt-get install pulls the
# newer Zabbly build). Returns non-zero if Incus could not be installed.
install_incus_zabbly() {
    echo -e "${BLUE}→ Adding the Zabbly stable repository and installing Incus...${NC}"

    sudo mkdir -p /etc/apt/keyrings
    if ! sudo curl -fsSL --connect-timeout 10 --retry 3 --retry-delay 5 \
            https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc; then
        echo -e "${YELLOW}⚠ Could not download the Zabbly signing key${NC}"
        return 1
    fi

    local codename arch
    # shellcheck source=/dev/null  # /etc/os-release is a system file, not in-repo
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"

    if ! sudo tee /etc/apt/sources.list.d/zabbly-incus-stable.sources >/dev/null <<SOURCES
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${codename}
Components: main
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/zabbly.asc
SOURCES
    then
        echo -e "${YELLOW}⚠ Could not write the Zabbly apt source${NC}"
        return 1
    fi

    sudo apt-get update -qq || return 1
    APT_LISTS_UPDATED=1
    sudo apt-get install -y incus || return 1
    return 0
}

# Decide whether the user agrees to a system-changing step (install Incus, add
# to a group, ...). Interactive: ask (default yes). Non-interactive: only
# proceed when explicitly authorised via COI_ASSUME_YES=1, so an unattended run
# never silently modifies the system without consent.
user_agrees() {
    local prompt="$1"
    if [ "$NONINTERACTIVE" = "1" ]; then
        [ "${COI_ASSUME_YES:-0}" = "1" ]
        return
    fi
    # Read a FULL line (not a single char) from the terminal. With several
    # prompts in one `curl | bash` run, single-char reads leave the trailing
    # newline in the tty buffer, which the next prompt then consumes as a stray
    # answer — so a later prompt (e.g. nft) could be silently "declined". A
    # line-oriented read avoids that. Empty (just Enter) defaults to yes.
    local reply
    # EOF / no readable tty must NOT be read as consent — treat it as a decline
    # so a closed terminal can't silently approve a system-changing step.
    if ! read -r -p "$prompt" reply </dev/tty; then
        return 1
    fi
    reply="${reply:-y}" # a bare Enter defaults to yes
    [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

# Check if Incus is installed
check_incus() {
    echo -e "${BLUE}→ Checking Incus installation...${NC}"

    if ! command -v incus &> /dev/null; then
        echo -e "${YELLOW}⚠ Incus is not installed${NC}"

        # On apt-based systems (Ubuntu/Debian) we can install it directly so a
        # `curl | bash` on an empty machine works end-to-end. Other distros keep
        # the guided path below (Incus setup there is out of scope for now).
        if [ "$PKG_MANAGER" = "apt" ] && user_agrees "  Install Incus now from the Zabbly repo (recommended)? [Y/n]: "; then
            if install_incus_zabbly && command -v incus &> /dev/null; then
                echo -e "${GREEN}✓ Incus installed${NC}"
                sudo systemctl enable --now incus 2>/dev/null || true
                sudo incus admin waitready --timeout=60 2>/dev/null || true
                return 0
            fi
            echo -e "${YELLOW}⚠ Automatic Incus install did not complete${NC}"
        fi

        echo ""
        echo "  Coi requires Incus (>= 6.1) to be installed."
        echo "  Install Incus: https://linuxcontainers.org/incus/docs/main/installing/"
        echo ""
        echo "  Quick install examples:"
        echo "    Ubuntu/Debian: from the Zabbly repo (https://github.com/zabbly/incus)"
        echo "    Arch Linux:    sudo pacman -S incus"
        echo "    Fedora:        sudo dnf install incus"
        echo ""
        echo "  Then: sudo incus admin init --auto"
        echo "        sudo usermod -aG incus-admin \$USER"
        echo ""
        prompt_continue "Continue installation anyway?"
    else
        # Use sudo: a non-root user who isn't in incus-admin yet (or whose
        # current session predates the membership) cannot reach the daemon
        # socket, so a plain `incus version` returns non-zero and — under
        # `set -e` — would abort the whole installer here. root always can.
        local incus_version_output
        incus_version_output="$(sudo incus version 2>/dev/null || true)"
        echo -e "${GREEN}✓ Incus found: ${incus_version_output}${NC}"

        # Check minimum version (>= 6.1)
        local server_version
        server_version="$(echo "$incus_version_output" | grep '^Server version:' | cut -d: -f2 | tr -d ' ')"
        if [ -z "$server_version" ]; then
            # Fallback: single-line output (older Incus)
            server_version="$(echo "$incus_version_output" | head -n1 | tr -d ' ')"
        fi

        if [ -n "$server_version" ]; then
            local ver_major ver_minor
            ver_major="$(echo "$server_version" | cut -d. -f1)"
            ver_minor="$(echo "$server_version" | cut -d. -f2)"

            if [ -n "$ver_major" ] && [ -n "$ver_minor" ]; then
                if [ "$ver_major" -lt 6 ] || { [ "$ver_major" -eq 6 ] && [ "$ver_minor" -lt 1 ]; }; then
                    echo ""
                    echo -e "${YELLOW}⚠ Incus version ${server_version} is below the minimum required 6.1${NC}"
                    echo ""
                    echo "  Ubuntu ships Incus 6.0.x which lacks required idmapping support."
                    echo "  You may see errors like:"
                    echo "    'Failed to setup device mount: idmapping abilities are required'"
                    echo ""

                    # On apt we can upgrade in place from Zabbly; elsewhere, guide.
                    if [ "$PKG_MANAGER" = "apt" ] && user_agrees "  Upgrade Incus from the Zabbly repo now? [Y/n]: "; then
                        if install_incus_zabbly; then
                            sudo systemctl restart incus 2>/dev/null || true
                            sudo incus admin waitready --timeout=60 2>/dev/null || true
                            echo -e "${GREEN}✓ Incus upgraded ($(sudo incus version 2>/dev/null | grep -i '^Server version:' | cut -d: -f2 | tr -d ' '))${NC}"
                        else
                            echo -e "${YELLOW}⚠ Incus upgrade did not complete${NC}"
                            prompt_continue "Continue with the current Incus anyway?"
                        fi
                    else
                        echo "  Install Incus >= 6.1 from the Zabbly repository:"
                        echo "    https://github.com/zabbly/incus"
                        echo ""
                        prompt_continue "Continue installation anyway?"
                    fi
                fi
            fi
        fi
    fi
}

# Check if user is in incus-admin group
check_group() {
    local user="${USER:-$(id -un)}"

    if groups | grep -qw incus-admin; then
        echo -e "${GREEN}✓ User is in incus-admin group${NC}"
        return
    fi

    # Not in the group yet. Add the user (with consent) so `coi` works without a
    # manual step. Group membership only takes effect in a NEW login session, so
    # we still tell them to re-login — but the installer's own Incus setup uses
    # sudo and does not depend on this session's groups, so setup still completes.
    if user_agrees "  Add '$user' to the incus-admin group now (needed to run coi)? [Y/n]: "; then
        if sudo usermod -aG incus-admin "$user"; then
            echo -e "${GREEN}✓ Added '$user' to the incus-admin group${NC}"
            echo -e "${YELLOW}  Log out and back in (or run: newgrp incus-admin) for it to take effect.${NC}"
            return
        fi
        echo -e "${YELLOW}⚠ Could not add '$user' to incus-admin${NC}"
    fi

    echo -e "${YELLOW}⚠ Not in the incus-admin group${NC}"
    echo "  Add yourself with: sudo usermod -aG incus-admin $user"
    echo "  Then log out and back in for changes to take effect."
}

# Install a sudoers drop-in safely: write the rule to a dot-named temp file in
# /etc/sudoers.d (sudo's includedir skips names containing '.'), validate it
# with visudo, then rename it into place. An unchecked in-place write with a
# syntax error breaks every sudo on the host, including the one to repair it.
# Mirrors nftSudoersScript in internal/health/remediation.go.
# Usage: install_sudoers_dropin <rule> <target>
install_sudoers_dropin() {
    sudo sh -c '
        PATH="$PATH:/usr/sbin:/sbin"
        if ! command -v visudo >/dev/null 2>&1; then
            echo "visudo not found - cannot validate the sudoers rule, so not installing it" >&2
            exit 1
        fi
        tmp="$(mktemp "$(dirname "$2")/.$(basename "$2").XXXXXX")" || exit 1
        if printf "%s\n" "$1" > "$tmp" && chmod 0440 "$tmp" && visudo -cf "$tmp" >/dev/null; then
            mv -f "$tmp" "$2"
        else
            rm -f "$tmp"
            exit 1
        fi' sh "$1" "$2"
}

# Set up passwordless sudo for nft (required for network isolation)
setup_nft_sudoers() {
    local nft_path user
    nft_path="$(command -v nft 2>/dev/null)"
    if [ -z "$nft_path" ]; then
        return
    fi
    # Name the user by numeric UID (#1000), not $USER: an empty $USER, or a
    # directory-service name with a space ("John Doe"), is a sudoers syntax
    # error that makes sudo reject the whole drop-in — and every sudo after it.
    user="#$(id -u)"

    # Already configured? Check for the sudoers drop-in directly so we don't
    # get a false positive from a cached sudo timestamp.
    if [ -f /etc/sudoers.d/coi-nft ]; then
        echo -e "${GREEN}✓ Passwordless sudo for nft already configured${NC}"
        return
    fi

    # Ask before adding a passwordless-sudo rule (a security-relevant change).
    # It is what lets Coi apply network isolation (restricted/allowlist modes)
    # without a password prompt; declining leaves open mode working.
    if ! user_agrees "  Configure passwordless sudo for nft — needed for network isolation? [Y/n]: "; then
        echo -e "${YELLOW}⚠ Skipped: without passwordless nft, restricted/allowlist network modes won't work (open mode still does).${NC}"
        echo -e "   Enable later: ${BLUE}coi health --fix${NC}"
        return
    fi

    echo -e "${BLUE}→ Configuring passwordless sudo for nft...${NC}"
    if install_sudoers_dropin "$user ALL=(ALL) NOPASSWD: $nft_path" /etc/sudoers.d/coi-nft; then
        echo -e "${GREEN}✓ Passwordless sudo configured for nft${NC}"
    else
        echo -e "${YELLOW}⚠ Could not configure passwordless sudo for nft (see the error above).${NC}"
        echo -e "   Retry later: ${BLUE}coi health --fix${NC}"
    fi
}

# Check nftables availability for network isolation
check_nft() {
    echo -e "${BLUE}→ Checking nftables (for network isolation)...${NC}"

    if ! command -v nft &> /dev/null; then
        echo -e "${YELLOW}⚠ nft not found${NC}"
        echo ""
        echo "  Network isolation (restricted/allowlist modes) requires nftables."
        echo "  Without it, you can still use open mode."
        echo ""

        if [ "$NONINTERACTIVE" = "1" ]; then
            echo -e "${BLUE}→ Non-interactive mode: installing nftables...${NC}"
            pkg_install nftables
        elif user_agrees "  Install nftables now? [Y/n]: "; then
            echo -e "${BLUE}→ Installing nftables...${NC}"
            pkg_install nftables
        fi
    else
        echo -e "${GREEN}✓ nft is installed${NC}"
    fi

    setup_nft_sudoers
}

# Copy a built/downloaded binary into INSTALL_DIR (sudo only when needed) and
# remove any leftover legacy claude-on-incus symlink from pre-0.10 installs —
# 0.10 retired the name, so upgrades should not keep the alias alive.
install_binary() {
    local src="$1"
    if [ -w "$INSTALL_DIR" ]; then
        cp "$src" "${INSTALL_DIR}/${BINARY_NAME}"
        rm -f "${INSTALL_DIR}/claude-on-incus"
    else
        sudo cp "$src" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo rm -f "${INSTALL_DIR}/claude-on-incus"
    fi
}

# Download binary from GitHub releases
download_binary() {
    local download_url
    local tmp_dir
    local binary_path

    echo -e "${BLUE}→ Downloading Coi...${NC}"

    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    if [ "$VERSION" = "latest" ]; then
        download_url="https://github.com/${REPO}/releases/latest/download/coi-${OS}-${ARCH}"
    else
        download_url="https://github.com/${REPO}/releases/download/${VERSION}/coi-${OS}-${ARCH}"
    fi

    binary_path="${tmp_dir}/${BINARY_NAME}"

    if command -v curl &> /dev/null; then
        curl -fsSL "$download_url" -o "$binary_path"
    elif command -v wget &> /dev/null; then
        wget -q -O "$binary_path" "$download_url"
    else
        echo -e "${RED}✗ Neither curl nor wget found${NC}"
        echo "  Please install curl or wget and try again."
        exit 1
    fi

    chmod +x "$binary_path"

    # Install to system
    echo -e "${BLUE}→ Installing to ${INSTALL_DIR}...${NC}"

    install_binary "$binary_path"

    echo -e "${GREEN}✓ Installed to ${INSTALL_DIR}/${BINARY_NAME}${NC}"

    # Grant immutable-attribute capability for host-side protected path hardening
    grant_immutable_capability
}

# Build from source
# Ensure the tools needed to build from source that `make build`'s own
# check-deps does NOT cover: git (to clone, before make ever runs) and a C
# toolchain + make (cgo compile). Their absence otherwise fails cryptically
# ("git: command not found" / "make: command not found"). Go and the systemd
# headers are left to check-deps, which reports them with actionable messages.
ensure_build_deps() {
    local need=""
    command -v git  &> /dev/null || need="$need git"
    command -v make &> /dev/null || need="$need make"
    { command -v cc &> /dev/null || command -v gcc &> /dev/null; } || need="$need gcc"
    [ -z "$need" ] && return 0

    # Ask before installing (consistent with the installer's other system
    # changes). Building from source genuinely can't proceed without these, so a
    # decline stops here with a pointer to the pre-built binary.
    if ! user_agrees "  Building from source needs:${need} — install now? [Y/n]: "; then
        echo -e "${RED}✗ Can't build from source without:${need}${NC}"
        echo "  Install them and re-run, or choose the pre-built binary instead."
        exit 1
    fi

    echo -e "${BLUE}→ Installing build dependencies:${need}${NC}"
    # `|| true`: a failed install must reach the verification below (and its
    # actionable message) instead of tripping set -e / the generic ERR trap.
    case "$PKG_MANAGER" in
        apt)    apt_update_once; sudo apt-get install -y git build-essential ;;
        pacman) sudo pacman -S --noconfirm --needed git base-devel ;;
        dnf)    sudo dnf install -y git make gcc ;;
        zypper) sudo zypper install -y git make gcc ;;
        *)      : ;;
    esac || true

    # Verify the essentials the build genuinely cannot proceed without.
    local missing=""
    command -v git  &> /dev/null || missing="$missing git"
    command -v make &> /dev/null || missing="$missing make"
    if [ -n "$missing" ]; then
        echo -e "${RED}✗ Building from source needs:${missing}${NC}"
        echo "  Install them and re-run, or choose the pre-built binary instead."
        exit 1
    fi
}

build_from_source() {
    local tmp_dir

    echo -e "${BLUE}→ Building from source...${NC}"

    # Install git + C toolchain first (see ensure_build_deps).
    ensure_build_deps

    # Check for Go
    if ! command -v go &> /dev/null; then
        echo -e "${RED}✗ Go not found${NC}"
        echo "  Install Go: https://go.dev/doc/install"
        exit 1
    fi

    echo -e "${BLUE}→ Go version: $(go version)${NC}"

    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    # Clone repository
    echo -e "${BLUE}→ Cloning repository...${NC}"
    git clone --depth 1 "https://github.com/${REPO}.git" "$tmp_dir"

    # Build (as the current user — never under sudo, because sudo strips PATH
    # and user-scoped Go toolchains like mise/asdf/$HOME/go/bin would disappear).
    cd "$tmp_dir"
    echo -e "${BLUE}→ Building binary...${NC}"
    make build

    # Install the freshly-built binary. We intentionally do NOT run
    # `sudo make install` here: that would re-invoke the `build` prerequisite
    # under sudo, strip PATH, and crash on systems where Go is user-scoped.
    # Mirror download_binary and copy the binary directly, only sudo-ing when
    # $INSTALL_DIR is not writable.
    echo -e "${BLUE}→ Installing to ${INSTALL_DIR}...${NC}"
    local built_binary="${tmp_dir}/${BINARY_NAME}"
    install_binary "$built_binary"

    echo -e "${GREEN}✓ Built and installed${NC}"

    # Grant immutable-attribute capability for host-side protected path hardening
    grant_immutable_capability
}

# Grant CAP_LINUX_IMMUTABLE on the installed binary so Coi can apply
# chattr +i on host-side protected paths (defense-in-depth against
# unshare+umount bypass of read-only bind mounts).
grant_immutable_capability() {
    if command -v setcap &> /dev/null; then
        if sudo setcap cap_linux_immutable=ep "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null; then
            echo -e "${GREEN}✓ Granted cap_linux_immutable capability (host-side path protection)${NC}"
        else
            echo -e "${YELLOW}⚠ Could not set cap_linux_immutable on binary${NC}"
            echo "  Host-side immutable protection will be unavailable."
            echo "  To enable: sudo setcap cap_linux_immutable=ep ${INSTALL_DIR}/${BINARY_NAME}"
        fi
    else
        echo -e "${YELLOW}⚠ setcap not found (install libcap2-bin)${NC}"
        echo "  Host-side immutable protection will be unavailable."
    fi
}

# Ensure the Incus systemd service is enabled and running
ensure_incus_service() {
    if ! command -v incus &> /dev/null; then
        return
    fi

    # Check if incus service (or socket) is active
    if systemctl is-active --quiet incus.service 2>/dev/null || systemctl is-active --quiet incus.socket 2>/dev/null; then
        echo -e "${GREEN}✓ Incus service is running${NC}"
        return
    fi

    echo -e "${BLUE}→ Enabling and starting Incus service...${NC}"
    if sudo systemctl enable --now incus.service 2>/dev/null; then
        echo -e "${GREEN}✓ Incus service enabled and started${NC}"
    elif sudo systemctl enable --now incus.socket 2>/dev/null; then
        echo -e "${GREEN}✓ Incus socket enabled and started${NC}"
    else
        echo -e "${YELLOW}⚠ Could not start Incus service${NC}"
        echo "  Try manually: sudo systemctl enable --now incus.service"
    fi
}

# Ensure subordinate UID/GID ranges are configured for unprivileged containers
ensure_idmap() {
    if ! command -v incus &> /dev/null; then
        return
    fi

    echo -e "${BLUE}→ Checking subordinate UID/GID mapping...${NC}"

    local needs_fix=0

    # Check if root has a subuid range with at least 65536 UIDs
    if [ -f /etc/subuid ] && grep -qE '^root:[0-9]+:[0-9]{5,}' /etc/subuid; then
        echo -e "${GREEN}✓ /etc/subuid has root mapping${NC}"
    else
        echo -e "${YELLOW}⚠ /etc/subuid missing root subordinate range${NC}"
        needs_fix=1
    fi

    if [ -f /etc/subgid ] && grep -qE '^root:[0-9]+:[0-9]{5,}' /etc/subgid; then
        echo -e "${GREEN}✓ /etc/subgid has root mapping${NC}"
    else
        echo -e "${YELLOW}⚠ /etc/subgid missing root subordinate range${NC}"
        needs_fix=1
    fi

    if [ "$needs_fix" = "0" ]; then
        return
    fi

    echo ""
    echo "  Incus needs subordinate UID/GID ranges for unprivileged containers."
    echo "  Without this, container launches will fail with:"
    echo "    \"System doesn't have a functional idmap setup\""
    echo ""

    if [ "$NONINTERACTIVE" = "1" ]; then
        echo -e "${BLUE}→ Non-interactive mode: configuring idmap...${NC}"
    else
        if ! user_agrees "  Configure subordinate UID/GID ranges now? [Y/n]: "; then
            return
        fi
    fi

    if ! grep -qE '^root:[0-9]+:[0-9]{5,}' /etc/subuid 2>/dev/null; then
        echo "root:1000000:1000000000" | sudo tee -a /etc/subuid > /dev/null
        echo -e "${GREEN}✓ Added root range to /etc/subuid${NC}"
    fi
    if ! grep -qE '^root:[0-9]+:[0-9]{5,}' /etc/subgid 2>/dev/null; then
        echo "root:1000000:1000000000" | sudo tee -a /etc/subgid > /dev/null
        echo -e "${GREEN}✓ Added root range to /etc/subgid${NC}"
    fi

    # Restart Incus to pick up new mappings
    if systemctl is-active --quiet incus.service 2>/dev/null; then
        echo -e "${BLUE}→ Restarting Incus to apply idmap changes...${NC}"
        restart_incus
        echo -e "${GREEN}✓ Incus restarted${NC}"
    fi
}

# Ensure Incus has been initialized (creates default network, profile devices, etc.)
ensure_incus_initialized() {
    # Skip if Incus is not installed
    if ! command -v incus &> /dev/null; then
        return
    fi

    # Wait for the daemon to accept the API before probing. A just-installed or
    # just-restarted Incus may not be ready yet; without this, the detection
    # queries below fail, look like "cannot determine", and init is silently
    # skipped — the half-configured-host failure (#823) this function guards
    # against. Bounded and best-effort.
    sudo incus admin waitready --timeout=90 2>/dev/null || true

    # Decide whether Incus has been initialized without being fooled by the
    # unmanaged physical/loopback interfaces that appear on every real host: a
    # bare "is the network list non-empty?" check is never empty and falsely
    # skips init (#703). `incus admin init --auto` creates both a MANAGED network
    # (incusbr0) and a storage pool, so treat either as proof of initialization -
    # a host set up with an existing/custom network and no managed bridge still
    # has a pool, which is the reliable signal.
    # If the network query itself fails (daemon down), warn and bail out rather
    # than incorrectly triggering init.
    #
    # Use `sudo incus` for these queries: during a fresh install the user was
    # only just added to incus-admin and this same shell is not in the group
    # yet, so a non-sudo `incus network list` would fail with a permission error
    # — which the old code mistook for "cannot determine" and skipped init,
    # leaving a half-configured host (#823). root can always reach the socket,
    # so sudo gives a reliable answer regardless of the current session's groups.
    local networks pools
    if ! networks="$(sudo incus network list --format=csv 2>/dev/null)"; then
        echo -e "${YELLOW}⚠ Unable to determine whether Incus has been initialized${NC}"
        echo "  Could not query Incus networks. Ensure the Incus daemon is running."
        return 1
    fi
    pools="$(sudo incus storage list --format=csv 2>/dev/null)"
    # MANAGED is CSV column 3 (YES/NO); awk avoids the cut|grep -q pipe whose
    # early exit trips `set -o pipefail`.
    if printf '%s\n' "$networks" | awk -F, '$3 == "YES" { found=1 } END { exit !found }' \
        || [ -n "$pools" ]; then
        return
    fi

    echo -e "${BLUE}→ Incus has not been initialized, running incus admin init --auto...${NC}"
    local output
    if output="$(sudo incus admin init --auto 2>&1)"; then
        echo -e "${GREEN}✓ Incus initialized${NC}"
    else
        echo -e "${YELLOW}⚠ Incus initialization failed${NC}"
        if [ -n "$output" ]; then
            printf "  %s\n" "$output"
        fi
        return 1
    fi
}

# Restart Incus and wait for the daemon to accept connections again before
# returning. Callers issue `incus` commands right after a restart (re-read idmaps,
# probe a freshly installed storage driver), and `systemctl restart` returns as
# soon as the unit is active, which can be a beat before the API socket is ready.
# waitready is bounded and best-effort — it never aborts the installer.
restart_incus() {
    sudo systemctl restart incus.service
    incus admin waitready --timeout=30 2>/dev/null || true
}

# Detect an OrbStack guest, where ZFS can never work.
# OrbStack injects the kernel from the host: the guest has no kernel packages,
# no headers and no module tree, so the out-of-tree ZFS module can neither be
# shipped precompiled nor built with DKMS. btrfs is compiled into that kernel,
# so it works. Mirrors the osrelease check in internal/vmhost/vmhost.go.
is_orbstack() {
    case "$(uname -r 2>/dev/null | tr '[:upper:]' '[:lower:]')" in
        *orbstack*) return 0 ;;
        *)          return 1 ;;
    esac
}

# Decide the size (in GiB) for the container storage pool.
#
# 50GiB is often not enough once a few images and containers pile up, so scale
# with the machine: half of the total disk backing /var/lib/incus, with a 50GiB
# floor. The zfs/btrfs pool is a sparse loop-backed file, so this size is a
# CAP, not an upfront reservation — it does not consume the space until used,
# which is why a generous cap (and the floor even on smaller disks) is safe.
# Falls back to the 50GiB floor whenever the disk size can't be determined.
pool_size_gib() {
    local target="/var/lib/incus"
    [ -d "$target" ] || target="/"

    # df -Pk: POSIX format (no line-wrap), 1024-byte blocks; column 2 is total.
    local total_kib
    total_kib="$(df -Pk "$target" 2>/dev/null | awk 'NR==2 {print $2}')"

    local half_gib=0
    if [ -n "$total_kib" ] && [ "$total_kib" -gt 0 ] 2>/dev/null; then
        half_gib=$(( total_kib / 2 / 1024 / 1024 ))
    fi

    if [ "$half_gib" -lt 50 ]; then
        echo 50
    else
        echo "$half_gib"
    fi
}

# Set up fast copy-on-write storage for containers.
# ZFS is the first choice (fastest), btrfs the fallback when ZFS is unavailable.
# btrfs is still copy-on-write, so still far faster than the default `dir` pool.
setup_fast_storage() {
    echo ""

    if is_orbstack; then
        echo -e "${YELLOW}⚠ Skipping ZFS: not supported on OrbStack${NC}"
        echo "  OrbStack guests get their kernel from the host, with no headers or module"
        echo "  tree, so the out-of-tree ZFS module can never be built or loaded."
        echo "  Using btrfs instead, which is built into the OrbStack kernel."
    elif command -v zfs &> /dev/null || [ "$PKG_MANAGER" = "apt" ]; then
        # ZFS is already present, or we can install it cleanly (apt is a plain
        # userspace install). Try it; fall back to btrfs if the pool can't be made.
        if setup_zfs_storage; then
            return 0
        fi
        echo -e "${BLUE}→ Falling back to btrfs...${NC}"
    else
        # ZFS is not installed and this distro's ZFS packages can break the
        # initramfs on install (#666 — e.g. Arch/EndeavourOS, where installing
        # zfs-utils triggers a dracut/mkinitcpio rebuild that fails on the missing
        # zfs module). Use btrfs, which is in-kernel and safe to install.
        echo -e "${BLUE}→ ZFS not installed; using btrfs (in-kernel, safe to install)...${NC}"
    fi

    if ! setup_btrfs_storage; then
        echo -e "${YELLOW}  Containers will use default storage (slower but functional)${NC}"
        return 1
    fi
}

# Set up ZFS storage (for instant container creation)
setup_zfs_storage() {
    echo -e "${BLUE}→ Setting up fast storage (ZFS)...${NC}"

    # Check if ZFS is already installed
    if command -v zfs &> /dev/null; then
        echo -e "${GREEN}✓ ZFS already installed${NC}"
    else
        # Installing ZFS is only safe on apt (zfsutils-linux is a plain userspace
        # package); on pacman/dnf/zypper the ZFS packages can rebuild and break the
        # initramfs (#666). setup_fast_storage already gates on this, but guard
        # here too so a future caller can't reach a wrong-distro install: the
        # pkg_install below hard-codes the apt package name, so a non-apt distro
        # would otherwise silently install the wrong (or a destructive) package.
        if [ "$PKG_MANAGER" != "apt" ]; then
            echo -e "${YELLOW}⚠ ZFS not installed and auto-install is only supported on apt${NC}"
            return 1
        fi
        echo -e "${BLUE}→ Installing ZFS...${NC}"
        if ! pkg_install zfsutils-linux 2>/dev/null; then
            echo -e "${YELLOW}⚠ ZFS installation failed (may not be available for your kernel)${NC}"
            return 1
        fi
        echo -e "${GREEN}✓ ZFS installed${NC}"
    fi

    # Check if ZFS pool already exists
    if sudo incus storage list --format=csv 2>/dev/null | grep -q "^zfs-pool,"; then
        echo -e "${GREEN}✓ ZFS storage pool already configured${NC}"
        return 0
    fi

    # Create ZFS storage pool
    local pool_size
    pool_size="$(pool_size_gib)"
    echo -e "${BLUE}→ Creating ZFS storage pool (${pool_size}GiB)...${NC}"
    local storage_output
    if storage_output="$(sudo incus storage create zfs-pool zfs "size=${pool_size}GiB" 2>&1)"; then
        echo -e "${GREEN}✓ ZFS storage pool created${NC}"

        # Configure default profile to use ZFS
        echo -e "${BLUE}→ Configuring default profile to use ZFS...${NC}"
        local profile_output
        if profile_output="$(sudo incus profile device set default root pool=zfs-pool 2>&1)"; then
            echo -e "${GREEN}✓ Default profile configured for ZFS${NC}"
            echo -e "${GREEN}✓ Containers will now start instantly (~50ms vs 5-10s)${NC}"
        else
            echo -e "${YELLOW}⚠ Failed to configure default profile${NC}"
            if [ -n "$profile_output" ]; then
                printf "${YELLOW}  %s${NC}\n" "$profile_output"
            fi
            echo -e "${YELLOW}  You can manually configure it later with:${NC}"
            echo -e "  ${BLUE}incus profile device add default root disk pool=zfs-pool path=/${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ ZFS storage pool creation failed${NC}"
        if [ -n "$storage_output" ]; then
            printf "${YELLOW}  %s${NC}\n" "$storage_output"
        fi
        return 1
    fi
}

# Set up btrfs storage, the fallback when ZFS is unavailable.
# Still copy-on-write, so container launches from a cached image are roughly 7x
# faster than the default `dir` pool (~0.2s vs ~1.1s measured on OrbStack).
setup_btrfs_storage() {
    echo -e "${BLUE}→ Setting up fast storage (btrfs)...${NC}"

    # Check if btrfs tools are already installed
    if command -v mkfs.btrfs &> /dev/null; then
        echo -e "${GREEN}✓ btrfs tools already installed${NC}"
    else
        echo -e "${BLUE}→ Installing btrfs tools...${NC}"
        if ! pkg_install btrfs-progs btrfs-progs btrfs-progs btrfsprogs 2>/dev/null; then
            echo -e "${YELLOW}⚠ btrfs installation failed${NC}"
            return 1
        fi
        echo -e "${GREEN}✓ btrfs tools installed${NC}"

        # Incus probes for available storage drivers when it starts, so a freshly
        # installed mkfs.btrfs is invisible until the daemon is restarted.
        if systemctl is-active --quiet incus.service 2>/dev/null; then
            echo -e "${BLUE}→ Restarting Incus to pick up the btrfs driver...${NC}"
            restart_incus
        fi
    fi

    # Check if btrfs pool already exists
    if sudo incus storage list --format=csv 2>/dev/null | grep -q "^btrfs-pool,"; then
        echo -e "${GREEN}✓ btrfs storage pool already configured${NC}"
        return 0
    fi

    # Create btrfs storage pool
    local pool_size
    pool_size="$(pool_size_gib)"
    echo -e "${BLUE}→ Creating btrfs storage pool (${pool_size}GiB)...${NC}"
    local storage_output
    if storage_output="$(sudo incus storage create btrfs-pool btrfs "size=${pool_size}GiB" 2>&1)"; then
        echo -e "${GREEN}✓ btrfs storage pool created${NC}"

        # Configure default profile to use btrfs
        echo -e "${BLUE}→ Configuring default profile to use btrfs...${NC}"
        local profile_output
        if profile_output="$(sudo incus profile device set default root pool=btrfs-pool 2>&1)"; then
            echo -e "${GREEN}✓ Default profile configured for btrfs${NC}"
            echo -e "${GREEN}✓ Containers will now start much faster (~0.2s vs 1-5s)${NC}"
        else
            echo -e "${YELLOW}⚠ Failed to configure default profile${NC}"
            if [ -n "$profile_output" ]; then
                printf "${YELLOW}  %s${NC}\n" "$profile_output"
            fi
            echo -e "${YELLOW}  You can manually configure it later with:${NC}"
            echo -e "  ${BLUE}incus profile device add default root disk pool=btrfs-pool path=/${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ btrfs storage pool creation failed${NC}"
        if [ -n "$storage_output" ]; then
            printf "${YELLOW}  %s${NC}\n" "$storage_output"
        fi
        return 1
    fi
}

# Fetch detection databases (GTFOBins + Sigma)
fetch_detection_databases() {
    if ! command -v coi &> /dev/null; then
        return
    fi

    echo ""
    echo -e "${BLUE}→ Fetching detection databases (GTFOBins + Sigma)...${NC}"
    echo "  This clones the GTFOBins reverse-shell database and Sigma linux/process_creation"
    echo "  rules used by the monitoring daemon. The Sigma clone is sparse (~300 KB)."
    echo ""

    # `coi update patterns` clones these over git, so git must be present. A
    # clean Ubuntu image has no git; offer to install it (with consent, like the
    # installer's other system changes). Declining just skips the fetch — the
    # `coi update patterns` below then fails gracefully into the "run it later"
    # hint.
    if ! command -v git &> /dev/null && user_agrees "  git is required to fetch detection databases — install it? [Y/n]: "; then
        pkg_install git || true
    fi

    if coi update patterns; then
        echo -e "${GREEN}✓ Detection databases fetched${NC}"
    else
        echo -e "${YELLOW}⚠ Detection database fetch failed (requires git and network access)${NC}"
        echo -e "  Run manually later: ${BLUE}coi update patterns${NC}"
    fi
}

# Post-install setup
# Hand any root-owned Incus client config back to the invoking user. `sudo incus`
# calls during setup run as root but keep the user's HOME, so Incus can create
# ~/.config/incus owned by root, which then fails the user's own commands with a
# permission error. Best-effort and idempotent.
restore_incus_config_ownership() {
    local user home group
    user="${USER:-$(id -un)}"
    home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
    [ -n "$home" ] || home="$HOME"
    [ -d "$home/.config/incus" ] || return 0
    group="$(id -gn "$user" 2>/dev/null || echo "$user")"
    sudo chown -R "$user:$group" "$home/.config/incus" 2>/dev/null || true
}

post_install() {
    setup_nm_unmanaged_veths
    ensure_incus_service || true
    ensure_idmap || true
    ensure_incus_initialized || true

    # Try to set up fast storage (best-effort, don't abort installer on failure)
    setup_fast_storage || true

    # The `sudo incus` reads/writes above run as root but keep the invoking
    # user's HOME, so Incus can leave a root-owned client config at
    # ~/.config/incus — which then blocks the user's own `coi`/`incus` with
    # "permission denied". Hand it back to the user so the very next command
    # works. Best-effort; no-op if nothing was created.
    restore_incus_config_ownership || true

    # Fetch GTFOBins and Sigma detection databases
    fetch_detection_databases || true

    echo ""
    echo -e "${GREEN}✓ Installation complete!${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Build the Coi image:"
    echo -e "     ${BLUE}coi build${NC}"
    echo ""
    echo "  2. Start your first session:"
    echo -e "     ${BLUE}coi shell${NC}"
    echo ""
    echo "  3. View available commands:"
    echo -e "     ${BLUE}coi --help${NC}"
    echo ""

    local admin_user="${USER:-$(id -un)}"
    if groups | grep -qw incus-admin; then
        : # already active in this session — nothing to say
    elif id -nG "$admin_user" 2>/dev/null | grep -qw incus-admin; then
        # We added them (or they were already a member), but this shell hasn't
        # activated the group. Say so accurately instead of "remember to add".
        echo -e "${GREEN}✓ You're in the incus-admin group.${NC}"
        echo -e "   Open a new shell (or log out and back in) to activate it, then: ${BLUE}coi build${NC}"
        echo ""
    else
        echo -e "${YELLOW}⚠ Add yourself to the incus-admin group:${NC}"
        echo -e "   ${BLUE}sudo usermod -aG incus-admin $admin_user${NC}"
        echo "   Then log out and back in."
        echo ""
    fi

    if ! command -v nft &> /dev/null; then
        echo -e "${YELLOW}⚠ nftables is not installed — network isolation (restricted/allowlist modes) will not work.${NC}"
        echo -e "   Install with: ${BLUE}sudo apt install nftables${NC}"
        echo ""
    elif ! [ -f /etc/sudoers.d/coi-nft ]; then
        echo -e "${YELLOW}⚠ Passwordless sudo for nft not configured — network isolation (restricted/allowlist) won't work.${NC}"
        echo -e "   Fix it with: ${BLUE}coi health --fix${NC}"
        echo ""
    fi

    echo "Documentation: https://github.com/${REPO}"
    echo ""
}

# Main installation
# Prevent NetworkManager from enrolling container veths into firewalld zones.
# NM assigns each new veth to firewalld's default zone; leaked registrations
# survive container deletion, and firewalld generates FORWARD rules as the
# CROSS PRODUCT of zone interfaces — dead veths grow the ruleset quadratically
# (145 leaked veths ~= 101k rules, issue #695). Marking veth* unmanaged stops
# the enrollment at the source; container traffic policy lives on the bridge.
#
# Entirely best-effort: every step tolerates failure (a firewall nicety must
# never abort the install under set -e / the ERR trap), and it is skippable
# with COI_SKIP_NM_UNMANAGED=1 for hosts that intentionally manage veths
# through NetworkManager (e.g. nmcli-configured veth pairs).
setup_nm_unmanaged_veths() {
    [ "${COI_SKIP_NM_UNMANAGED:-0}" = "1" ] && return 0
    # COI_NM_CONF_DIR is a test seam; production always uses the real path.
    local conf_dir="${COI_NM_CONF_DIR:-/etc/NetworkManager/conf.d}"
    local conf_file="$conf_dir/99-coi-unmanaged.conf"
    [ -d "$conf_dir" ] || return 0
    if [ -f "$conf_file" ]; then
        return 0
    fi
    # Only an ACTIVE (uncommented) rule that mentions veths counts as existing
    # coverage — a commented-out example must not suppress the real one.
    if grep -rhs '^[[:space:]]*unmanaged-devices' "$conf_dir"/*.conf 2>/dev/null | grep -q 'veth'; then
        echo -e "${GREEN}✓ NetworkManager already has an unmanaged-devices rule mentioning veths — leaving it alone${NC}"
        return 0
    fi
    echo -e "${BLUE}→ Marking veth* unmanaged in NetworkManager (prevents firewalld zone bloat, #695; skip with COI_SKIP_NM_UNMANAGED=1)...${NC}"
    # unmanaged-devices+= APPENDS to any list set elsewhere; plain '=' would
    # REPLACE a user's own exclusions under NM's last-file-wins semantics.
    if ! sudo tee "$conf_file" > /dev/null 2>&1 <<'NMEOF'
# Installed by Coi (Code on Incus): container veths must not be enrolled in
# firewalld zones — leaked registrations grow the firewall ruleset
# quadratically. See https://github.com/coipond/coi/issues/695
# Remove this file (and reload NetworkManager) to undo.
[keyfile]
unmanaged-devices+=interface-name:veth*
NMEOF
    then
        echo -e "${YELLOW}⚠ Could not write $conf_file; skipping (see issue #695 for the manual step)${NC}"
        return 0
    fi
    sudo systemctl reload NetworkManager 2>/dev/null || true
    echo -e "${GREEN}✓ NetworkManager veth exclusion installed${NC}"
}

main() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Coi (Code on Incus) installer${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo ""

    detect_platform
    detect_pkg_manager
    check_incus
    check_group
    check_nft

    echo ""
    echo "Installation method:"
    echo "  1. Download pre-built binary (fastest)"
    echo "  2. Build from source"
    echo ""

    # Check if releases exist
    if curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" &> /dev/null; then
        prompt_choice "Choose [1/2] (default: 1): " "1"

        case $REPLY in
            2)
                build_from_source
                ;;
            *)
                download_binary
                ;;
        esac
    else
        echo -e "${YELLOW}⚠ No pre-built binaries available, building from source...${NC}"
        build_from_source
    fi

    post_install
}

# Handle errors
error_handler() {
    echo ""
    echo -e "${RED}✗ Installation failed${NC}"
    echo ""
    echo "If you need help:"
    echo "  - Check the documentation: https://github.com/${REPO}"
    echo "  - File an issue: https://github.com/${REPO}/issues"
    exit 1
}

trap error_handler ERR

# Run main
main "$@"
