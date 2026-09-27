#!/bin/bash
# Build script for coi image
# This script runs INSIDE the container during image build
#
# It installs all dependencies needed for CLI tool execution:
# - Base development tools
# - Node.js LTS (system, for Claude CLI)
# - mise (polyglot runtime manager) with Python 3, pnpm, npm:typescript, npm:tsx
# - Claude CLI
# - Docker
# - GitHub CLI
# - dummy (test stub for testing)

set -euo pipefail

# Configuration
CODE_USER="code"
CODE_UID=1000

log() {
    echo "[coi] $*"
}

#######################################
# Configure DNS if misconfigured
# Only applies fix if DNS resolution fails
#######################################
configure_dns_if_needed() {
    log "Checking DNS configuration..."

    # Test if DNS resolution works
    if getent hosts archive.ubuntu.com > /dev/null 2>&1; then
        log "DNS resolution works, keeping default configuration."
        return 0
    fi

    log "DNS resolution failed, configuring static DNS..."

    # Disable systemd-resolved (not needed in containers)
    systemctl disable systemd-resolved 2>/dev/null || true
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl mask systemd-resolved 2>/dev/null || true

    # Remove symlink and create static resolv.conf
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'EOF'
# Static DNS configuration (auto-configured due to DNS misconfiguration)
# See: https://github.com/mensfeld/code-on-incus#troubleshooting
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
EOF

    log "Static DNS configured (8.8.8.8, 8.8.4.4, 1.1.1.1)."

    # Verify it works now
    if getent hosts archive.ubuntu.com > /dev/null 2>&1; then
        log "DNS resolution now working."
    else
        log "WARNING: DNS still not working after fix. Build may fail."
    fi
}

#######################################
# Prefer IPv4 and bound apt's network waits
#######################################
# Build containers frequently have IPv6 configured but no working IPv6 route.
# apt (and installers) resolve AAAA records first, try the dead IPv6 path, and —
# because apt has no default network timeout — hang on connect essentially
# forever, stalling the whole build until the CI job's hard timeout kills it
# (observed: builds wedged at "Installing base dependencies..." for ~59m). The
# codebase already preferred IPv4 for the agent installers via /etc/gai.conf
# (prefer_ipv4), but that ran AFTER apt. Force IPv4 for apt and bound its
# retries/timeouts here, BEFORE the first apt-get, and set the gai.conf
# preference (Bun/Node installers resolve AAAA first;
# https://github.com/anthropics/claude-code/issues/13498) for everything else.
# Called once from main(); idempotent.
configure_network_ipv4() {
    log "Preferring IPv4 for network operations..."
    cat > /etc/apt/apt.conf.d/99coi-force-ipv4 <<'APTCONF'
Acquire::ForceIPv4 "true";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Retries "3";
APTCONF
    if ! grep -q '::ffff:0:0/96' /etc/gai.conf 2>/dev/null; then
        echo 'precedence ::ffff:0:0/96 100' >> /etc/gai.conf
    fi
}

#######################################
# Point apt at a faster mirror when one is provided
#######################################
# The build container is a fresh ubuntu image using the default
# archive.ubuntu.com/security.ubuntu.com mirrors, which are intermittently
# slow/rate-limited from some networks (observed in CI: base-dependency apt
# taking 35+ minutes vs ~2 on a good day, blowing the job timeout). When
# COI_APT_MIRROR is set (e.g. CI exports the runner's fast in-region mirror
# like http://azure.archive.ubuntu.com/ubuntu), rewrite the archive+security
# URIs to it before the first apt-get. Unset (the default for local builds) is
# a no-op, so ordinary users keep the stock mirrors. Handles both the 24.04
# deb822 sources and the legacy sources.list; idempotent (the optional
# azure./mirror host in the pattern makes a re-run a no-op).
configure_apt_mirror() {
    [ -n "${COI_APT_MIRROR:-}" ] || return 0
    log "Using apt mirror ${COI_APT_MIRROR} (COI_APT_MIRROR)"
    local f
    for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
        [ -f "$f" ] || continue
        sed -i -E \
            -e "s#https?://[a-z0-9.-]*archive\.ubuntu\.com/ubuntu#${COI_APT_MIRROR}#g" \
            -e "s#https?://security\.ubuntu\.com/ubuntu#${COI_APT_MIRROR}#g" \
            "$f"
    done
}

#######################################
# Install base dependencies
#######################################
install_base_dependencies() {
    log "Installing base dependencies..."

    apt-get update -qq

    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        curl wget git ca-certificates gnupg jq unzip sudo \
        tmux \
        dnsutils \
        ripgrep fzf fd-find bat tree \
        strace lsof \
        sqlite3 postgresql-client redis-tools \
        imagemagick \
        build-essential libssl-dev libreadline-dev zlib1g-dev \
        libffi-dev libyaml-dev libgmp-dev \
        libsqlite3-dev libpq-dev libmysqlclient-dev \
        libxml2-dev libxslt1-dev libcurl4-openssl-dev

    # On Ubuntu/Debian, fd-find and bat install as fdfind and batcat.
    # Create symlinks so the standard names work.
    ln -sf "$(command -v fdfind)" /usr/local/bin/fd
    ln -sf "$(command -v batcat)" /usr/local/bin/bat

    log "Base dependencies installed"
}

#######################################
# Disable host-only services
# Services that are useless in a container and, in
# udisks2's case, actively break the host.
#######################################
disable_host_only_services() {
    log "Disabling host-only services..."

    # udisks2 (pulled in as an fwupd dependency) keeps /proc/swaps
    # open in its main loop. Incus backs /proc/swaps with lxcfs, so
    # that poll() is a FUSE request to a daemon on the host. When the
    # host suspends, the kernel freezer stops lxcfs while the request
    # is in flight; it can never be answered, udisksd wedges in D
    # state, and the freezer gives up after its 20s timeout. The
    # host's suspend then aborts with "Device or resource busy" and
    # logind retries forever, so a laptop with a coi container running
    # never sleeps with the lid shut and takes ~20s to accept input on
    # lid open.
    systemctl disable --now udisks2.service 2>/dev/null || true
    systemctl mask udisks2.service 2>/dev/null || true

    log "Host-only services disabled"
}

#######################################
# Install Node.js LTS
#######################################
install_nodejs() {
    log "Installing Node.js LTS..."

    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y -qq nodejs

    log "Node.js $(node --version) installed"
}

#######################################
# Configure mise and install default runtimes
#
# mise manages Python, Node.js tools (pnpm, tsx), and other runtimes.
# System Node.js (from nodesource) is kept for Claude CLI and core
# tooling; mise handles everything else.
#
# See: https://mise.jdx.dev
#######################################
configure_mise_tools() {
    log "Configuring mise shell activation and default tools..."

    local CODE_HOME="/home/$CODE_USER"

    # Add mise activation to .bashrc so all interactive and login shells
    # (including those started by claude/opencode) pick up mise-managed tools.
    local BASHRC="$CODE_HOME/.bashrc"
    if ! grep -q 'mise activate' "$BASHRC" 2>/dev/null; then
        cat >> "$BASHRC" << 'MISE_EOF'

# mise: polyglot runtime manager
# Adds mise-managed tools (python, pnpm, tsx, etc.) to PATH
eval "$(mise activate bash)"
MISE_EOF
    fi

    # Also add to .profile for non-interactive login shells (e.g. `su - code -c "..."`)
    local PROFILE="$CODE_HOME/.profile"
    if ! grep -q 'mise activate' "$PROFILE" 2>/dev/null; then
        cat >> "$PROFILE" << 'MISE_EOF'

# mise: polyglot runtime manager
eval "$(mise activate bash)"
MISE_EOF
    fi

    # Add a system-wide profile hook so shells that source /etc/profile
    # (including non-interactive shells started by COI tooling via bash -c
    # inside tmux) get mise-managed shims on PATH as well.
    if [ ! -f /etc/profile.d/mise.sh ]; then
        cat > /etc/profile.d/mise.sh << 'MISE_PROFILE_EOF'
# system-wide mise activation for all users
if command -v mise >/dev/null 2>&1; then
    eval "$(mise activate bash)"
fi
MISE_PROFILE_EOF
        chmod 644 /etc/profile.d/mise.sh
    fi

    # Install default tools globally via mise as the code user.
    # This sets ~/.config/mise/config.toml with global tool versions.
    local attempt
    for attempt in 1 2 3; do
        if su - "$CODE_USER" -c 'mise use --global python@3 npm:pnpm@latest npm:typescript@latest npm:tsx@latest'; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: mise tool installation failed after 3 attempts."
            exit 1
        fi
        log "mise install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    # Verify tools are installed and accessible via mise
    for bin in python3 pnpm tsc tsx; do
        if ! su - "$CODE_USER" -c "mise exec -- which $bin" >/dev/null 2>&1; then
            log "ERROR: '$bin' not found via mise after installation."
            exit 1
        fi
    done

    # Ensure the code user owns all mise state
    chown -R "$CODE_USER:$CODE_USER" "$CODE_HOME/.local/share/mise" 2>/dev/null || true
    chown -R "$CODE_USER:$CODE_USER" "$CODE_HOME/.config/mise" 2>/dev/null || true

    log "mise tools installed (python3, pnpm, typescript, tsx)"
}

#######################################
# Create code user with passwordless sudo
#######################################
create_code_user() {
    log "Creating code user..."

    # Rename the default 'ubuntu' user to 'code' if it exists (Ubuntu 22.04 cloud images).
    # Ubuntu 24.04 minimal container images ship without a default user, so we
    # fall back to creating 'code' directly in that case.
    if getent passwd ubuntu > /dev/null 2>&1; then
        usermod -l "$CODE_USER" -d "/home/$CODE_USER" -m ubuntu
        groupmod -n "$CODE_USER" ubuntu
    else
        groupadd -g "$CODE_UID" "$CODE_USER" 2>/dev/null || true
        useradd -m -u "$CODE_UID" -g "$CODE_USER" -s /bin/bash "$CODE_USER"
    fi
    mkdir -p "/home/$CODE_USER/.claude"
    mkdir -p "/home/$CODE_USER/.codex"
    mkdir -p "/home/$CODE_USER/.ssh"
    chmod 700 "/home/$CODE_USER/.ssh"
    # Pre-populate known_hosts. Try ssh-keyscan first (fresh keys); fall back to
    # embedded static keys for hosts where the SSH endpoint is unreachable (e.g.
    # bitbucket.org blocks automated scans, may be in maintenance windows).
    for _host in github.com gitlab.com bitbucket.org; do
        for _attempt in 1 2 3; do
            if ssh-keyscan -T 10 -t ed25519,rsa,ecdsa "$_host" >> "/home/$CODE_USER/.ssh/known_hosts" 2>/dev/null; then
                break
            fi
            sleep 2
        done
    done
    unset _host _attempt

    # Ensure bitbucket.org is always present — its SSH endpoint is sometimes
    # unavailable (maintenance, IP rate-limiting). These are the published keys
    # from https://www.atlassian.com/blog/bitbucket/ssh-host-key-changes
    if ! grep -q "^bitbucket.org " "/home/$CODE_USER/.ssh/known_hosts" 2>/dev/null; then
        cat >> "/home/$CODE_USER/.ssh/known_hosts" <<'BBKEYS'
bitbucket.org ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIQmuzMBuKdWeF4+a2sjSSpBK0iqitSQ+5BM9KhpexuGt20JpTVM7u5BDZngncgrqDMbWdxMWWOGtZ9UgbqgZE=
bitbucket.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIazEu89wgQZ4bqs3d63QSMzYVa0MuJ2e2gKTKqu+UUO
bitbucket.org ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQeJzhupRu0u0cdegZIa8e86EG2qOCsIsD1Xw0xSeiPDlCr7kq97NLmMbpKTX6Esc30NuoqEEHCuc7yWtwp8dI76EEEB1VqY9QJq6vk+aySyboD5QF61I/1WeTwu+deCbgKMGbUijeXhtfbxSxm6JwGrXrhBdofTsbKRUsrN1WoNgUa8uqN1Vx6WAJw1JHPhglEGGHea6QICwJOAr/6mrui/oB7pkaWKHj3z7d1IC4KWLtY47elvjbaTlkN04Kc/5LFEirorGYVbt15kAUlqGM65pk6ZBxtaO3+30LVlORZkxOh+LKL/BvbZ/iRNhItLqNyieoQj/uh/7Iv4uyH/cV/0b4WDSd3DptigWq84lJubb9t/DnZlrJazxyDCulTmKdOR7vs9gMTo+uoIrPSb8ScTtvw65+odKAlBj59dhnVp9zd7QUojOpXlL62Aw56U4oO+FALuevvMjiWeavKhJqlR7i5n9srYcrNV7ttmDw7kf/97P5zauIhxcjX+xHv4M=
BBKEYS
    fi
    chmod 644 "/home/$CODE_USER/.ssh/known_hosts"
    chown -R "$CODE_USER:$CODE_USER" "/home/$CODE_USER"

    # Setup passwordless sudo for all commands
    echo "$CODE_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$CODE_USER"

    chown root:root "/etc/sudoers.d/$CODE_USER"
    chmod 440 "/etc/sudoers.d/$CODE_USER"
    usermod -aG sudo "$CODE_USER"

    log "User '$CODE_USER' created with passwordless sudo (uid: $CODE_UID)"
}

#######################################
# Install mise (polyglot runtime manager)
# See: https://mise.jdx.dev
#######################################
install_mise() {
    log "Installing mise..."

    # Install to /usr/local/bin so it's available system-wide
    local attempt
    for attempt in 1 2 3; do
        if curl -fsSL https://mise.jdx.dev/install.sh | MISE_INSTALL_PATH=/usr/local/bin/mise sh; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: mise installation failed after 3 attempts."
            exit 1
        fi
        log "mise install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    if [[ ! -x /usr/local/bin/mise ]]; then
        log "ERROR: mise binary not found at /usr/local/bin/mise after installation."
        exit 1
    fi

    log "mise $(/usr/local/bin/mise --version 2>/dev/null || echo 'installed')"
}

#######################################
# Configure power management wrappers
#######################################
configure_power_wrappers() {
    log "Configuring power management command wrappers..."

    # Create wrapper scripts that use sudo automatically
    # This allows users to type "poweroff" instead of "sudo poweroff"
    # while working around the lack of login sessions in containers

    # Incus assigns the container hostname at boot (from the UTS namespace), but
    # /etc/hosts is baked into the image at build time with a different name.
    # sudo looks up the current hostname for logging; if it is not in /etc/hosts
    # the lookup fails and prints "unable to resolve host" on every invocation.
    #
    # Fix: a oneshot systemd service that appends the runtime hostname to
    # /etc/hosts before multi-user.target is reached (i.e. before any shell).
    cat > /etc/systemd/system/coi-fix-hostname.service << 'UNIT_EOF'
[Unit]
Description=Add container hostname to /etc/hosts
After=local-fs.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'h=$(hostname); grep -qF "$h" /etc/hosts || echo "127.0.0.1 $h" >> /etc/hosts'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl enable coi-fix-hostname.service

    # Power-off wrappers.
    #
    # In Ubuntu 24.04 containers systemd-logind can be mid-start when a shutdown
    # is requested, producing a D-Bus transaction conflict.  One --force flag
    # makes systemctl talk directly to systemd (bypassing logind) without
    # resorting to a hard reboot() syscall, which lets COI clean up the session.
    for cmd in poweroff halt; do
        cat > "/usr/local/bin/${cmd}" << 'WRAPPER_EOF'
#!/bin/bash
exec sudo systemctl --force poweroff
WRAPPER_EOF
        chmod 755 "/usr/local/bin/${cmd}"
    done

    cat > "/usr/local/bin/reboot" << 'WRAPPER_EOF'
#!/bin/bash
exec sudo systemctl --force reboot
WRAPPER_EOF
    chmod 755 "/usr/local/bin/reboot"

    cat > "/usr/local/bin/shutdown" << 'WRAPPER_EOF'
#!/bin/bash
exec sudo systemctl --force poweroff
WRAPPER_EOF
    chmod 755 "/usr/local/bin/shutdown"

    # Create "close" as an alias for poweroff
    # This provides a safe alternative that doesn't exist on the host machine,
    # preventing accidental host shutdowns when typed outside the container
    cat > "/usr/local/bin/close" << 'WRAPPER_EOF'
#!/bin/bash
exec sudo systemctl --force poweroff
WRAPPER_EOF
    chmod 755 "/usr/local/bin/close"

    # Create "stop" as another poweroff alias
    # Same rationale as "close": it does not exist on the host, so typing it
    # outside the container is harmless. Provided because the two names are
    # easy to confuse and are used interchangeably.
    cat > "/usr/local/bin/stop" << 'WRAPPER_EOF'
#!/bin/bash
exec sudo systemctl --force poweroff
WRAPPER_EOF
    chmod 755 "/usr/local/bin/stop"

    log "Power management wrappers configured"
}

#######################################
# Install Claude CLI using native installer
# Note: npm installation is deprecated as of 2025
# See: https://code.claude.com/docs/en/setup
#######################################
install_claude_cli() {
    log "Installing Claude CLI (native)..."

    # Run the native installer as the code user (with retries for transient
    # network failures). `set -o pipefail` inside the su login shell is what
    # makes the retry work: without it the pipeline's status is bash's, which
    # exits 0 on the empty stdin a failed curl leaves behind — so a transient
    # network failure would "succeed", skip the retries, and hard-fail the
    # build at the binary check below.
    local attempt
    for attempt in 1 2 3; do
        if su - "$CODE_USER" -c 'set -o pipefail; curl -4 -fsSL https://claude.ai/install.sh | bash'; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: Claude CLI installation failed after 3 attempts."
            exit 1
        fi
        log "Claude CLI install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    # Verify that the installer actually created the Claude CLI binary
    local CLAUDE_PATH="/home/$CODE_USER/.local/bin/claude"
    if [[ ! -x "$CLAUDE_PATH" ]]; then
        log "ERROR: Claude CLI binary not found at $CLAUDE_PATH after installation."
        log "Installation may have failed or installed to an unexpected location."
        exit 1
    fi

    # Create a global symlink so it's accessible system-wide
    ln -sf "$CLAUDE_PATH" /usr/local/bin/claude

    log "Claude CLI $(claude --version 2>/dev/null || echo 'installed')"
}

#######################################
# Map the host CPU architecture to the opencode release asset suffix.
# opencode publishes opencode-linux-x64.tar.gz and opencode-linux-arm64.tar.gz.
# Installing the x86_64 build on an arm64 host fails at runtime with
# "qemu-x86_64: Could not open '/lib64/ld-linux-x86-64.so.2'" (issue #506).
# Echoes the suffix on stdout; returns non-zero for unsupported architectures.
#######################################
opencode_asset_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "x64" ;;
        aarch64 | arm64) echo "arm64" ;;
        *) return 1 ;;
    esac
}

#######################################
# Install opencode
# See: https://opencode.ai
#######################################
install_opencode() {
    log "Installing opencode..."

    # Select the release asset for the host architecture (issue #506).
    local OPENCODE_ARCH
    if ! OPENCODE_ARCH="$(opencode_asset_arch)"; then
        log "ERROR: unsupported CPU architecture '$(uname -m)' for opencode."
        exit 1
    fi

    # Download the binary directly from the /latest/download/ redirect URL.
    # This does NOT hit the GitHub API and is not subject to rate limits
    # (unlike the official installer which calls api.github.com).
    local INSTALL_DIR="/home/$CODE_USER/.opencode/bin"
    local OPENCODE_PATH="$INSTALL_DIR/opencode"
    local DOWNLOAD_URL="https://github.com/anomalyco/opencode/releases/latest/download/opencode-linux-${OPENCODE_ARCH}.tar.gz"

    mkdir -p "$INSTALL_DIR"
    chown "$CODE_USER:$CODE_USER" "$INSTALL_DIR"

    local attempt
    for attempt in 1 2 3; do
        if curl -fsSL "$DOWNLOAD_URL" | tar xz -C "$INSTALL_DIR"; then
            chmod +x "$OPENCODE_PATH"
            chown "$CODE_USER:$CODE_USER" "$OPENCODE_PATH"
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: opencode installation failed after 3 attempts."
            exit 1
        fi
        log "opencode download failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    if [[ ! -x "$OPENCODE_PATH" ]]; then
        log "ERROR: opencode binary not found at $OPENCODE_PATH after installation."
        exit 1
    fi

    ln -sf "$OPENCODE_PATH" /usr/local/bin/opencode

    log "opencode $(opencode --version 2>/dev/null || echo 'installed')"
}

#######################################
# Install pi (AI coding agent)
# See: https://pi.dev
#
# Installed via the official install script from https://pi.dev/install.sh
#######################################
install_pi() {
    log "Installing pi..."

    # Install as the code user via the official installer. `set -o pipefail`
    # makes a failed curl actually trigger the retries — see install_claude_cli.
    local attempt
    for attempt in 1 2 3; do
        if su - "$CODE_USER" -c 'set -o pipefail; curl -fsSL https://pi.dev/install.sh | sh'; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: pi installation failed after 3 attempts."
            exit 1
        fi
        log "pi install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    # Ensure pi is available system-wide for non-login/non-interactive shells
    local PI_BIN
    PI_BIN="$(su - "$CODE_USER" -c 'which pi' 2>/dev/null || true)"
    if [[ -z "$PI_BIN" ]]; then
        log "ERROR: pi binary not found after installation."
        exit 1
    fi
    ln -sf "$PI_BIN" /usr/local/bin/pi

    log "pi $(su - "$CODE_USER" -c 'pi --version' 2>/dev/null || echo 'installed')"
}

#######################################
# Install OpenAI Codex CLI using native installer
# See: https://developers.openai.com/codex/cli
#
# Not in the default agent set — opt in via [container.build]
# agents = ["claude", "codex"] before building (issue #698).
#######################################
install_codex() {
    log "Installing Codex CLI (native)..."

    # Run the native installer as the code user (with retries for transient
    # network failures). `set -o pipefail` inside the su login shell is
    # required for the retry to work at all: without it the pipeline's status
    # is sh's, and sh exits 0 on the empty stdin a failed curl leaves behind —
    # so a transient network failure would "succeed", skip the retries, and
    # hard-fail the build at the binary check below.
    local attempt
    for attempt in 1 2 3; do
        if su - "$CODE_USER" -c 'set -o pipefail; CODEX_NON_INTERACTIVE=1 curl -4 -fsSL https://chatgpt.com/codex/install.sh | sh'; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: Codex CLI installation failed after 3 attempts."
            exit 1
        fi
        log "Codex CLI install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    # Verify that the installer actually created the Codex CLI binary
    local CODEX_PATH="/home/$CODE_USER/.local/bin/codex"
    if [[ ! -x "$CODEX_PATH" ]]; then
        log "ERROR: Codex CLI binary not found at $CODEX_PATH after installation."
        log "Installation may have failed or installed to an unexpected location."
        exit 1
    fi

    # Create a global symlink so it's accessible system-wide
    ln -sf "$CODEX_PATH" /usr/local/bin/codex

    log "Codex CLI $(codex --version 2>/dev/null || echo 'installed')"

    # Smoke-check the resume grammar coi's codex integration depends on. coi
    # renders `codex resume <id> "$(cat prompt)"` (CodexTool.BuildCommandLaunch),
    # which requires the `resume` subcommand to accept a trailing [PROMPT]
    # positional. codex is unpinned (latest at build time), so fail the build
    # loudly if a release drops it — instead of silently shipping a broken
    # resume+prompt path (coi#755). Run as the code user (login shell, so codex
    # is on PATH with its HOME); --help is offline and needs no auth.
    local resume_help
    resume_help="$(su - "$CODE_USER" -c 'codex resume --help' 2>&1 || true)"
    if ! printf '%s' "$resume_help" | grep -qi '\[prompt\]'; then
        log "ERROR: 'codex resume' no longer advertises a [PROMPT] positional."
        log "coi's resume+prompt rendering (internal/tool/codex.go, coi#755) would break;"
        log "update CodexTool.BuildCommandLaunch to match the current codex grammar."
        exit 1
    fi
}

#######################################
# Install Oh My Pi (omp) using the native installer
# See: https://github.com/can1357/oh-my-pi
#
# Not in the default agent set — opt in via [container.build]
# agents = ["claude", "omp"] before building (issue #699).
#######################################
install_omp() {
    log "Installing omp..."

    # Install as the code user via the official installer. `set -o pipefail`
    # makes a failed curl actually trigger the retries — see install_pi.
    local attempt
    for attempt in 1 2 3; do
        if su - "$CODE_USER" -c 'set -o pipefail; curl -fsSL https://omp.sh/install | sh'; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            log "ERROR: omp installation failed after 3 attempts."
            exit 1
        fi
        log "omp install failed (attempt $attempt/3), retrying in 10s..."
        sleep 10
    done

    # Ensure omp is available system-wide for non-login/non-interactive shells
    local OMP_BIN
    OMP_BIN="$(su - "$CODE_USER" -c 'which omp' 2>/dev/null || true)"
    if [[ -z "$OMP_BIN" ]]; then
        log "ERROR: omp binary not found after installation."
        exit 1
    fi
    ln -sf "$OMP_BIN" /usr/local/bin/omp

    log "omp $(su - "$CODE_USER" -c 'omp --version' 2>/dev/null || echo 'installed')"
}

#######################################
# Install dummy (test stub for testing)
#######################################
install_dummy() {
    log "Installing dummy (test stub for testing)..."

    # dummy MUST be pushed to /tmp/dummy before running this script
    if [[ ! -f /tmp/dummy ]]; then
        log "ERROR: /tmp/dummy not found!"
        log "The dummy script must be pushed to the container before building."
        log "Make sure you're running the build from the project root directory."
        exit 1
    fi

    cp /tmp/dummy /usr/local/bin/dummy
    chmod +x /usr/local/bin/dummy
    rm /tmp/dummy
    log "dummy $(dummy --version 2>/dev/null || echo 'installed')"
}

#######################################
# Install Docker CE
#######################################
install_docker() {
    log "Installing Docker..."

    # Add Docker GPG key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    # Add code user to docker group (belt-and-suspenders, may not be sufficient
    # on its own — see daemon config below for the reliable fix)
    usermod -aG docker "$CODE_USER"

    # Make the Docker socket accessible to the code user's PRIMARY group.
    #
    # Why: incus exec may not call initgroups() when --group is specified,
    # so supplementary groups (including 'docker') may not be active in the
    # session. The user's primary group (code, GID 1000) is always active
    # regardless of how the session was started.
    #
    # Two layers of config are needed:
    #
    # 1. daemon.json "group": "code" — Docker daemon chowns the socket to
    #    root:code on startup (works when Docker creates the socket itself).
    #
    # 2. docker.socket systemd drop-in SocketGroup=code — Ubuntu's Docker
    #    package uses systemd socket activation: systemd creates
    #    /var/run/docker.sock before the daemon starts using the group from
    #    the socket unit (default: docker). The daemon.json setting alone is
    #    not enough when systemd socket activation is in play; this drop-in
    #    ensures the socket is created with root:code (0660) from the start.
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'EOF'
{
    "group": "code"
}
EOF

    mkdir -p /etc/systemd/system/docker.socket.d
    cat > /etc/systemd/system/docker.socket.d/override.conf << 'EOF'
[Socket]
SocketGroup=code
EOF

    log "Docker $(docker --version 2>/dev/null || echo 'installed')"
}

#######################################
# Install GitHub CLI
#######################################
install_github_cli() {
    log "Installing GitHub CLI..."

    # Add GitHub CLI GPG key
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
    chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg

    # Add GitHub CLI repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null

    # Install
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gh

    log "GitHub CLI $(gh --version 2>/dev/null | head -1 || echo 'installed')"
}

#######################################
# Configure /tmp auto-cleanup
#
# By default Ubuntu's systemd-tmpfiles-clean.timer runs daily and only
# removes files older than 10 days. AI coding agents can fill /tmp in
# minutes, so we:
#   1. Lower the age threshold to 1 hour so abandoned temp files are
#      collected promptly.
#   2. Run the cleanup timer every 15 minutes instead of daily so recovery
#      happens automatically between heavy operations.
#
# This complements the hard tmpfs size cap set by COI at container start.
#######################################
configure_tmp_cleanup() {
    log "Configuring /tmp auto-cleanup..."

    # Age threshold: remove files in /tmp not accessed for more than 1 hour.
    # The 'D' type removes the directory contents but keeps /tmp itself.
    cat > /etc/tmpfiles.d/coi-tmp-cleanup.conf << 'EOF'
# COI: clean files in /tmp that have not been accessed for 1 hour.
# This prevents abandoned build artefacts from exhausting the tmpfs.
D /tmp 1777 root root 1h
EOF

    # Override the cleanup timer to run every 15 minutes.
    mkdir -p /etc/systemd/system/systemd-tmpfiles-clean.timer.d
    cat > /etc/systemd/system/systemd-tmpfiles-clean.timer.d/coi-interval.conf << 'EOF'
[Timer]
# Reset inherited values before setting our own
OnBootSec=
OnUnitActiveSec=
# Start 5 minutes after boot, then every 15 minutes
OnBootSec=5min
OnUnitActiveSec=15min
EOF

    # Enable the timer (it is masked in some minimal Ubuntu images)
    systemctl enable systemd-tmpfiles-clean.timer 2>/dev/null || true

    log "/tmp cleanup configured (1h age threshold, 15min timer)"
}

#######################################
# Configure tmux scrollback history
#
# `coi shell` runs the interactive session inside a tmux session so
# that an exit of the inner CLI (e.g. Ctrl-C out of opencode) does not
# tear down the shell. Tmux's default `history-limit` is 2000 lines,
# which silently truncates the beginning of long command outputs
# (e.g. `bin/setup` in a Rails app) so the user cannot scroll back to
# the start. Bump the default high enough to cover realistic build
# logs. Users who want a different value can override this by writing
# their own `~/.tmux.conf` — tmux loads it after `/etc/tmux.conf` so
# per-user settings always win.
#######################################
configure_tmux() {
    log "Configuring tmux..."

    cat > /etc/tmux.conf << 'EOF'
# COI default: large scrollback so long build outputs (bin/setup, npm ci,
# cargo build, etc.) are fully retrievable. Override in ~/.tmux.conf —
# tmux loads the per-user file after this one, so your value wins.
set -g history-limit 50000

# Reduce escape-time from the default 500ms to 10ms so that the Escape key
# is delivered promptly to applications (e.g. vim, opencode) even when the
# container tmux is nested inside one or more outer tmux sessions on the
# host. With the default, each nesting layer adds up to 500ms of latency,
# making Esc feel completely broken. 10ms is enough to distinguish Esc from
# the start of an escape sequence without noticeable delay.
set -g escape-time 10
EOF
    chmod 644 /etc/tmux.conf

    log "tmux configured: history-limit=50000, escape-time=10ms in /etc/tmux.conf"
}

#######################################
# Cleanup
#######################################
cleanup() {
    log "Cleaning up..."
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    log "Cleanup complete"
}

#######################################
# Main
#######################################
# install_selected_agents installs the AI agents named in $COI_AGENTS (comma- or
# space-separated). When COI_AGENTS is unset/empty it installs the default agents,
# preserving the historical behavior (issue #454). codex is supported but opt-in
# only (issue #698) — request it explicitly to include it. Unknown names are
# warned and skipped (coi validates the list host-side before build, so this is
# defense-in-depth).
install_selected_agents() {
    local agents="${COI_AGENTS:-claude opencode pi}"
    for agent in ${agents//,/ }; do
        case "$agent" in
            claude) install_claude_cli ;;
            opencode) install_opencode ;;
            pi) install_pi ;;
            codex) install_codex ;;
            omp) install_omp ;;
            "") ;;
            *) log "WARNING: unknown agent '$agent' in COI_AGENTS, skipping" ;;
        esac
    done
}

main() {
    log "Starting coi image build..."

    configure_network_ipv4
    configure_apt_mirror
    configure_dns_if_needed
    install_base_dependencies
    disable_host_only_services
    install_nodejs
    create_code_user
    install_mise
    configure_mise_tools
    configure_power_wrappers
    configure_tmp_cleanup
    configure_tmux
    install_selected_agents
    install_dummy
    install_docker
    install_github_cli
    cleanup

    log "coi image build complete!"
}

main "$@"
