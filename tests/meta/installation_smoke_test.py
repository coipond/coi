"""
Meta test for full installation process.

This test acts as a smoke test for the entire installation workflow:
1. Launch a fresh Ubuntu 24.04 container
2. Install Incus inside it (nested Incus)
3. Follow the README installation steps
4. Build the coi binary
5. Verify coi --help works
6. Verify basic coi commands work

This validates the complete setup process from scratch.

Note: This test requires nested Incus support and takes longer to run.
"""

import os
import shlex
import subprocess
import time

import pytest

# Cap for one apt try; three tries plus pauses stay under the old 600 s.
APT_TRY_TIMEOUT_SEC = 180


@pytest.fixture(scope="module")
def meta_container():
    """
    Launch a fresh Ubuntu container to test the installation process.

    This validates that the README installation steps work correctly
    and produce a functioning coi binary.
    """
    container_name = "coi-meta-test"

    # Clean up any existing test container
    subprocess.run(
        ["incus", "delete", container_name, "--force"],
        capture_output=True,
        check=False,
    )

    # Launch fresh Ubuntu 24.04 container
    result = subprocess.run(
        [
            "incus",
            "launch",
            "images:ubuntu/24.04",
            container_name,
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    if result.returncode != 0:
        pytest.skip(f"Failed to launch meta container: {result.stderr}")

    # Wait for container to be ready
    time.sleep(10)

    yield container_name

    # Cleanup
    subprocess.run(
        ["incus", "delete", container_name, "--force"],
        capture_output=True,
        check=False,
    )


def exec_in_container(container_name, command, timeout=300, check=False):
    """Execute command in meta container and return result.

    check defaults to False so callers' assertions (which include stderr) produce
    a readable failure message instead of a bare CalledProcessError that hides
    the in-container output.
    """
    result = subprocess.run(
        ["incus", "exec", container_name, "--", "bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )
    return result


def test_full_installation_process(meta_container, coi_binary):
    """
    Test the complete installation process from README.

    This is a smoke test that validates:
    1. System dependencies can be installed
    2. Go can be installed
    3. Repository can be cloned
    4. coi binary can be built from source
    5. coi --help works
    6. coi version works

    This does NOT test Incus functionality - it only validates the
    build process and that the binary executes correctly.
    """
    container_name = meta_container

    # Phase 1: Install system dependencies
    # Retry apt-get operations to handle transient network issues in CI. A
    # stalled apt hangs instead of failing, so each try is killed inside the
    # container after APT_TRY_TIMEOUT_SEC and counts as a failed try.
    max_retries = 3
    last_error = None
    mirror = os.environ.get("COI_APT_MIRROR", "")

    for attempt in range(max_retries):
        # The mirror is a speed-up, not a dependency: later tries use the
        # stock Ubuntu archive.
        try_mirror = mirror if attempt == 0 else ""
        script = f"""
            set -e
            # Same apt settings as the image build (internal/image/build.sh
            # configure_network_ipv4).
            cat > /etc/apt/apt.conf.d/99coi-force-ipv4 <<'APTCONF'
Acquire::ForceIPv4 "true";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Retries "3";
APTCONF
            for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
                [ -f "$f" ] || continue
                orig="/root/$(echo "$f" | tr / _).orig"
                [ -f "$orig" ] || cp -p "$f" "$orig"
                cp -p "$orig" "$f"
                [ -n "{try_mirror}" ] || continue
                sed -i -E \\
                    -e "s#https?://[a-z0-9.-]*archive\\.ubuntu\\.com/ubuntu#{try_mirror}#g" \\
                    -e "s#https?://security\\.ubuntu\\.com/ubuntu#{try_mirror}#g" \\
                    "$f"
            done

            # A killed earlier try can leave dpkg half-configured.
            dpkg --configure -a

            # Wait for network and DNS to be ready
            for i in {{1..30}}; do
                if ping -c 1 archive.ubuntu.com >/dev/null 2>&1; then
                    break
                fi
                sleep 1
            done

            apt-get update -qq

            # Install packages
            # pkg-config is required by the Makefile's check-deps preflight
            # (coi links libsystemd via cgo, which needs pkg-config + libsystemd-dev).
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \\
                curl wget git ca-certificates gnupg build-essential pkg-config libsystemd-dev

            echo "System dependencies installed"
            """
        try:
            result = exec_in_container(
                container_name,
                f"timeout -k 10 {APT_TRY_TIMEOUT_SEC} bash -c {shlex.quote(script)}",
                timeout=APT_TRY_TIMEOUT_SEC + 30,
                check=False,
            )
            if result.returncode == 0:
                break
            last_error = result.stderr
            if result.returncode == 124:
                last_error = f"timed out after {APT_TRY_TIMEOUT_SEC}s: {last_error}"
        except subprocess.TimeoutExpired as e:
            result = None
            last_error = f"incus exec timed out after {e.timeout}s"

        if attempt < max_retries - 1:
            print(f"apt-get attempt {attempt + 1} failed, retrying: {last_error}")
            time.sleep(10)  # Wait before retry

    assert result is not None and result.returncode == 0, (
        f"Failed to install dependencies after {max_retries} attempts: {last_error}"
    )

    # Phase 2: Install Go. Use the latest stable release rather than a pinned
    # version: the repo's go.mod sets a minimum (currently `go 1.26.0`) and a
    # too-old pinned Go fails the build deterministically with "go.mod requires
    # go >= ...". Fetching latest keeps this smoke test correct across future
    # go.mod bumps; fall back to a known-good version if go.dev is unreachable.
    result = exec_in_container(
        container_name,
        """
        set -e
        GO_VERSION="$(wget -qO- https://go.dev/VERSION?m=text | head -1 | sed 's/^go//')"
        case "$GO_VERSION" in
            [0-9]*) : ;;                 # looks like a version
            *) GO_VERSION="1.26.10" ;;   # fallback if the lookup failed
        esac
        echo "Installing Go ${GO_VERSION}"
        wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
        rm go${GO_VERSION}.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
        /usr/local/go/bin/go version
        """,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"Failed to install Go: stdout={result.stdout} stderr={result.stderr}"
    )
    assert "go version" in result.stdout, "Go installation verification failed"

    # Phase 3: Clone repository and build coi
    # In CI (pull requests), try PR branch first, fall back to default branch
    # This handles:
    # - Fork PRs (branch doesn't exist in main repo)
    # - Deleted branches (branch was deleted after PR merged)
    github_branch = os.environ.get("GITHUB_HEAD_REF", "")
    github_repo = os.environ.get("GITHUB_REPOSITORY", "coipond/coi")
    github_server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo_url = f"{github_server}/{github_repo}.git"

    # Build clone command with fallback: try branch first, then default
    if github_branch:
        clone_script = f"""
        if git clone -b {github_branch} {repo_url} 2>/dev/null; then
            echo "Cloned branch {github_branch}"
        else
            echo "Branch {github_branch} not found, cloning default branch"
            git clone {repo_url}
        fi
        """
    else:
        clone_script = f"git clone {repo_url}"

    result = exec_in_container(
        container_name,
        f"""
        set -e
        cd /root
        {clone_script}
        cd coi
        export PATH=$PATH:/usr/local/go/bin
        make build
        ./coi version
        """,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"Failed to build coi: stdout={result.stdout} stderr={result.stderr}"
    )
    assert "Coi (Code on Incus) v" in result.stdout, "coi version check failed"

    # Phase 4: Test coi --help
    result = exec_in_container(
        container_name,
        """
        cd /root/coi
        ./coi --help
        """,
        timeout=30,
    )
    assert result.returncode == 0, f"coi --help failed: {result.stderr}"
    assert "Coi (Code on Incus) is a CLI tool" in result.stdout, (
        "coi help output missing expected text"
    )
    assert "Available Commands:" in result.stdout, "coi help missing commands section"

    # Phase 5: Test coi basic commands
    result = exec_in_container(
        container_name,
        """
        cd /root/coi
        ./coi image list --help
        ./coi list --help
        ./coi shell --help
        echo "Basic commands work"
        """,
        timeout=30,
    )
    assert result.returncode == 0, f"Basic coi commands failed: {result.stderr}"


def test_installation_with_prebuilt_binary(meta_container, coi_binary):
    """
    Test installation using pre-built binary (simpler workflow).

    This tests the path where users download a pre-built binary
    instead of building from source. No Incus installation needed,
    just validates the binary executes correctly.

    Flow:
    1. Copy pre-built coi binary into container
    2. Test coi --help works
    3. Test coi version works
    """
    container_name = meta_container

    # Push pre-built binary to container
    result = subprocess.run(
        ["incus", "file", "push", coi_binary, f"{container_name}/usr/local/bin/coi"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Failed to push binary: {result.stderr}"

    # Make executable and test
    result = exec_in_container(
        container_name,
        """
        chmod +x /usr/local/bin/coi
        coi --help
        coi version
        """,
        timeout=30,
    )
    assert result.returncode == 0, f"Pre-built binary test failed: {result.stderr}"
    assert "Coi (Code on Incus)" in result.stdout, "coi binary not working correctly"
