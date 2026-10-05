"""
Pytest configuration and fixtures for CLI integration tests.
"""

import os
import subprocess
import sys

import pytest

# Add tests directory to Python path so 'from support.helpers import ...' works
tests_dir = os.path.dirname(os.path.abspath(__file__))
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

# Many integration tests intentionally configure out-of-workspace mounts via a
# project .coi/config.toml (host paths under pytest's tmp_path). Those are gated
# behind `coi trust` by default; opt the whole suite into the CI bypass so those
# tests keep working without per-test trust setup. The dedicated trust test
# (tests/mount/test_untrusted_mount_trust.py) removes this var to exercise the gate.
os.environ.setdefault("COI_TRUST_ALL", "1")


# Load skip list for temporarily disabled tests
def pytest_collection_modifyitems(config, items):
    """Skip tests listed in pytest_skip_list.txt"""
    skip_list_path = os.path.join(os.path.dirname(__file__), "..", "pytest_skip_list.txt")

    if not os.path.exists(skip_list_path):
        return

    # Read skip list
    skip_tests = set()
    with open(skip_list_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                skip_tests.add(line)

    # Mark matching tests to skip
    for item in items:
        # Get test node ID relative to project root
        test_id = item.nodeid
        # Also try with tests/ prefix since skip list has full paths
        if test_id in skip_tests or f"tests/{test_id}" in skip_tests:
            item.add_marker(
                pytest.mark.skip(reason="Temporarily disabled - see pytest_skip_list.txt")
            )


@pytest.fixture(scope="session")
def coi_binary():
    """Return path to coi binary."""
    # Check COI_BINARY env var first (for CI)
    if "COI_BINARY" in os.environ:
        binary_path = os.environ["COI_BINARY"]
        if os.path.exists(binary_path):
            return os.path.abspath(binary_path)

    # Look for coi binary in project root
    binary_path = os.path.join(os.path.dirname(__file__), "..", "coi")
    if not os.path.exists(binary_path):
        pytest.skip("coi binary not found - run 'make build' first")
    return os.path.abspath(binary_path)


@pytest.fixture
def workspace_dir(tmp_path):
    """Provide an isolated temporary workspace directory for each test."""
    # Create a unique workspace directory for this test
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return str(workspace)


@pytest.fixture
def cleanup_containers(workspace_dir, coi_binary):
    """Cleanup test containers and associated network resources after each test."""
    # Import here to avoid circular imports
    from support.helpers import calculate_container_name, get_container_list

    yield

    # Calculate container names for this workspace (slots 1-10)
    workspace_containers = set()
    for slot in range(1, 11):
        workspace_containers.add(calculate_container_name(workspace_dir, slot))

    # Get all running containers and delete any that belong to this test's workspace
    containers = get_container_list()
    for container in containers:
        if container in workspace_containers:
            # Delete the container
            # Note: ACLs are already cleaned up by coi shell cleanup when it exits
            subprocess.run(
                [coi_binary, "container", "delete", container, "--force"],
                capture_output=True,
                timeout=30,
                check=False,
            )

    # Kill any orphaned tmux sessions to prevent test pollution
    # This ensures clean state between tests, especially after tmux command tests
    subprocess.run(
        ["tmux", "kill-server"],
        capture_output=True,
        timeout=5,
        check=False,
    )


@pytest.fixture(scope="session")
def dummy_path():
    """Return path to dummy CLI for testing.

    This allows tests to run without requiring actual software licenses.
    The dummy simulates basic interactive CLI behavior for testing container
    orchestration logic.
    """
    dummy_dir = os.path.join(os.path.dirname(__file__), "..", "testdata", "dummy")
    if not os.path.exists(os.path.join(dummy_dir, "dummy")):
        pytest.skip("dummy not found")
    return os.path.abspath(dummy_dir)


@pytest.fixture(scope="session")
def dummy_image(coi_binary, tmp_path_factory):
    """Build and return a test image with dummy pre-installed.

    This image includes dummy at /usr/local/bin/dummy, allowing
    tests to run 10x+ faster without requiring actual software licenses.

    The image is built once per test session and reused across all tests.
    The image name includes a hash of the install script to force rebuilds
    when the script changes.
    """
    # Build image with dummy
    script_path = os.path.join(os.path.dirname(__file__), "..", "testdata", "dummy", "install.sh")

    if not os.path.exists(script_path):
        pytest.skip(f"Dummy install script not found: {script_path}")

    # Generate hash of install script AND dummy binary to version the image
    # Both files affect the image content, so changes to either should trigger rebuild
    import hashlib
    import shutil

    hasher = hashlib.sha256()

    # Hash install script
    with open(script_path, "rb") as f:
        hasher.update(f.read())

    # Hash dummy binary
    dummy_path = os.path.join(os.path.dirname(__file__), "..", "testdata", "dummy", "dummy")
    if os.path.exists(dummy_path):
        with open(dummy_path, "rb") as f:
            hasher.update(f.read())

    script_hash = hasher.hexdigest()[:8]
    image_name = f"coi-test-dummy-{script_hash}"

    # Check if image already exists
    result = subprocess.run([coi_binary, "image", "exists", image_name], capture_output=True)

    if result.returncode == 0:
        return image_name  # Already built

    print(f"\nBuilding test image with dummy (script hash: {script_hash})...")

    # Create a temporary workspace with a profile for building
    tmp_dir = tmp_path_factory.mktemp("dummy-build")
    profile_dir = tmp_dir / ".coi" / "profiles" / "dummy"
    profile_dir.mkdir(parents=True)

    # Write profile config.toml
    config_toml = profile_dir / "config.toml"
    config_toml.write_text(
        f'[container]\nimage = "{image_name}"\n\n[container.build]\nscript = "build.sh"\n'
    )

    # Copy the install script into the profile directory as build.sh
    shutil.copy2(script_path, str(profile_dir / "build.sh"))

    result = subprocess.run(
        [coi_binary, "build", "--profile", "dummy"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(tmp_dir),
    )

    if result.returncode != 0:
        pytest.skip(f"Could not build dummy image: {result.stderr}")

    print(f"Test image '{image_name}' built successfully")
    return image_name


# Hook to show test duration inline with each test result
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Add duration to test reports."""
    outcome = yield
    report = outcome.get_result()

    # Add duration to the report for later display
    if call.when == "call":
        report.duration = call.duration


def pytest_report_teststatus(report, config):
    """Customize test status output to include duration inline."""
    if report.when == "call" and hasattr(report, "duration"):
        duration = report.duration
        # Format duration nicely
        duration_str = f"{duration:.2f}s" if duration < 1 else f"{duration:.1f}s"

        # Append duration to the word (status)
        if report.passed:
            word = f"PASSED ({duration_str})"
        elif report.failed:
            word = f"FAILED ({duration_str})"
        elif report.skipped:
            word = f"SKIPPED ({duration_str})"
        else:
            word = f"{report.outcome.upper()} ({duration_str})"

        return report.outcome, "", word

    return None  # Use default formatting


def pytest_runtest_logreport(report):
    """Print why a test's first attempt failed before --reruns retries it.

    A retried test that then passes shows only "RERUN" in the log, hiding the
    failure and its captured output; print both so a flaky test's cause is
    visible in CI.
    """
    if report.outcome != "rerun":
        return
    out = sys.__stderr__
    out.write(f"\n===== first attempt of {report.nodeid} failed (retrying) =====\n")
    out.write(report.longreprtext + "\n")
    for name, content in report.sections:
        out.write(f"--- {name} ---\n{content}\n")
    out.flush()


def pytest_sessionfinish(session, exitstatus):
    """Clean up orphaned resources at the end of the test session.

    This runs even if tests crash, ensuring firewall rules, veth interfaces,
    and other resources don't leak on the developer's machine.
    """
    # Find the coi binary
    coi_binary = None
    if "COI_BINARY" in os.environ:
        coi_binary = os.environ["COI_BINARY"]
    else:
        binary_path = os.path.join(os.path.dirname(__file__), "..", "coi")
        if os.path.exists(binary_path):
            coi_binary = os.path.abspath(binary_path)

    if not coi_binary or not os.path.exists(coi_binary):
        return  # Can't clean up without the binary

    # Clean up any orphaned resources (veths, firewall rules, zone bindings)
    subprocess.run(
        [coi_binary, "clean", "--orphans", "--force"],
        capture_output=True,
        timeout=120,
        check=False,
    )

    # Also kill all test containers to be safe
    subprocess.run(
        [coi_binary, "kill", "--all", "--force"],
        capture_output=True,
        timeout=120,
        check=False,
    )
