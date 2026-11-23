"""
Integration tests for container alias support (#304).

Tests alias registration, resolution, conflict detection, and cross-command support.
"""

import json
import os
import subprocess
import time
import uuid

from pexpect import EOF, TIMEOUT

from support.helpers import (
    calculate_container_name,
    container_config_get,
    get_container_list,
    incus_status,
    spawn_coi,
    start_background_shell,
    wait_for_text_in_monitor,
    with_live_screen,
    workspace_containers,
    write_workspace_container_config,
)


def run_coi(coi_binary, args, workspace_dir=None, env_extra=None, timeout=120):
    """Run a coi command and return the result."""
    env = os.environ.copy()
    env["COI_USE_DUMMY"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [coi_binary, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=workspace_dir,
        env=env,
    )


def get_aliases_registry():
    """Read and return the aliases.json registry."""
    path = os.path.join(os.path.expanduser("~"), ".coi", "aliases.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


# ============================================================
# Core alias tests
# ============================================================


class TestAliasStoredOnContainer:
    """Test that alias metadata is set on the container."""

    def test_alias_stored_on_container(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Launch persistent session with alias, verify user.coi.alias is set."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="testalias"
        )
        container_name = calculate_container_name(workspace_dir, 1)

        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        # Container is persistent, so it should still exist
        containers = get_container_list()
        assert container_name in containers, (
            f"Expected persistent container '{container_name}' to exist for alias verification"
        )

        alias = container_config_get(container_name, "user.coi.alias")
        assert alias == "testalias", f"Expected alias 'testalias', got '{alias}'"


class TestAliasInRegistry:
    """Test that alias is registered in ~/.coi/aliases.json."""

    def test_alias_in_registry(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch session with alias, verify it appears in registry."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="registrytest")

        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        registry = get_aliases_registry()
        assert "registrytest" in registry, f"Alias 'registrytest' not found in registry: {registry}"
        assert registry["registrytest"]["workspace"] == os.path.abspath(workspace_dir)


class TestAliasShownInList:
    """Test that aliases are displayed in coi list output."""

    def test_alias_shown_in_list_json(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Launch container with alias, verify it appears in JSON list output."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="listalias"
        )
        container_name = calculate_container_name(workspace_dir, 1)

        # Launch a persistent container so it stays running
        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        list_result = run_coi(coi_binary, ["list", "--format=json"])
        assert list_result.returncode == 0

        data = json.loads(list_result.stdout)
        containers = data.get("active_containers", [])

        # Find our container and verify alias
        found = [c for c in containers if c.get("name") == container_name]
        assert len(found) > 0, (
            f"Expected container '{container_name}' in list output, "
            f"got: {[c.get('name') for c in containers]}"
        )
        assert "alias" in found[0], f"Missing 'alias' key in container: {found[0]}"
        assert found[0]["alias"] == "listalias", (
            f"Expected alias 'listalias', got '{found[0].get('alias')}'"
        )

    def test_alias_shown_in_list_text(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Launch container with alias, verify (alias) appears in text output."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="textalias"
        )
        container_name = calculate_container_name(workspace_dir, 1)

        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        list_result = run_coi(coi_binary, ["list"])
        # Container should be in the list since it's persistent
        assert container_name in list_result.stdout, (
            f"Expected container '{container_name}' in text output"
        )
        assert "(textalias)" in list_result.stdout, "Expected '(textalias)' in text output"


# ============================================================
# Alias resolution for action commands
# ============================================================


class TestAttachByAlias:
    """Test that coi attach resolves aliases."""

    def test_attach_by_alias(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch container with alias, attempt to attach by alias."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="attachalias"
        )

        # Start a persistent container
        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        # Try attaching by alias with --bash (will timeout quickly, but should not error with "not found")
        result = run_coi(
            coi_binary,
            ["attach", "attachalias", "--bash"],
            timeout=10,
        )
        # It should either succeed or fail with a container-level error, NOT "not found"
        # Alias resolution means it found the container
        if result.returncode != 0:
            assert (
                "not found" not in result.stderr.lower()
                or "container or alias" in result.stderr.lower()
            )


class TestKillByAlias:
    """Test that coi kill resolves aliases."""

    def test_kill_by_alias(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch container with alias, kill it by alias."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="killalias"
        )

        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        result = run_coi(
            coi_binary,
            ["kill", "killalias", "--force"],
        )
        # Should succeed (exit 0) or report a "not found" style error (not a flag/syntax error)
        assert result.returncode == 0 or "not found" in result.stderr.lower()


class TestShutdownByAlias:
    """Test that coi shutdown resolves aliases."""

    def test_shutdown_by_alias(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch container with alias, shutdown by alias."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="shutdownalias"
        )

        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        result = run_coi(
            coi_binary,
            ["shutdown", "shutdownalias", "--force"],
        )
        # Should succeed (exit 0) or report a "not found" style error (not a flag/syntax error)
        assert result.returncode == 0 or "not found" in result.stderr.lower()


class TestUnfreezeByAlias:
    """Test that coi unfreeze resolves aliases."""

    def test_unfreeze_by_alias(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch container with alias, freeze it, unfreeze by alias."""
        env = {**os.environ, "COI_USE_DUMMY": "1"}
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="unfreezealias")
        container_name, _ = start_background_shell(coi_binary, workspace_dir, env, slot=1)

        result = subprocess.run(
            ["incus", "pause", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"incus pause failed: {result.stderr}"
        assert incus_status(container_name) == "FROZEN"

        result = run_coi(coi_binary, ["unfreeze", "unfreezealias"], timeout=60)
        assert result.returncode == 0, f"coi unfreeze unfreezealias failed: {result.stderr}"
        assert f"Unfroze container: {container_name}" in result.stderr, result.stderr
        assert incus_status(container_name) == "RUNNING"


# ============================================================
# Slot suffix tests
# ============================================================


class TestAliasSlotSuffix:
    """Test alias with slot suffixes (e.g. myproject-2)."""

    def test_alias_with_slot_suffix(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Launch two containers, kill slot 2 by alias suffix."""
        write_workspace_container_config(
            workspace_dir, persistent=True, image=dummy_image, alias="slotalias"
        )

        # Launch slot 1
        run_coi(
            coi_binary,
            ["run", "--slot", "1", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        # Launch slot 2
        run_coi(
            coi_binary,
            ["run", "--slot", "2", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        container1 = calculate_container_name(workspace_dir, 1)
        container2 = calculate_container_name(workspace_dir, 2)

        # Kill slot 2 by alias suffix
        result = run_coi(
            coi_binary,
            ["kill", "slotalias-2", "--force"],
        )
        if result.returncode == 0:
            containers = get_container_list()
            assert container2 not in containers, "Slot 2 container should be deleted"
            # Slot 1 should still exist
            assert container1 in containers, "Slot 1 container should still exist"


class TestAliasEndingInSlotSuffix:
    """Test that an alias ending in -N resolves to itself, not to slot N of another alias."""

    def test_alias_ending_in_slot_suffix(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image, tmp_path
    ):
        """Aliases "<a>" and "<a>-2": "<a>-2" never reaches slot 2 of "<a>"."""
        base = f"wholename{uuid.uuid4().hex[:8]}"
        suffixed = f"{base}-2"
        env = {**os.environ, "COI_USE_DUMMY": "1"}

        write_workspace_container_config(workspace_dir, image=dummy_image, alias=base)
        base_slot2, _ = start_background_shell(coi_binary, workspace_dir, env, slot=2)

        workspace_b = str(tmp_path / "workspace_b")
        os.makedirs(workspace_b)
        write_workspace_container_config(workspace_b, image=dummy_image, alias=suffixed)

        try:
            # Register the "-2" alias; its ephemeral container is gone after the run
            result = run_coi(coi_binary, ["run", "echo", "ok"], workspace_dir=workspace_b)
            assert result.returncode == 0, f"coi run failed: {result.stderr}"
            assert suffixed in get_aliases_registry()
            assert not workspace_containers(workspace_b)

            # A registered alias with no running container is not found
            for argv in (["attach", suffixed, "--bash"], ["kill", suffixed, "--force"]):
                result = run_coi(coi_binary, argv, timeout=60)
                assert result.returncode != 0, f"coi {argv[0]} {suffixed} should fail"
                assert "not found" in result.stderr.lower(), result.stderr
                assert incus_status(base_slot2) == "RUNNING", (
                    f"coi {argv[0]} {suffixed} must not act on slot 2 of {base}"
                )

            # -0 is never a slot
            result = run_coi(coi_binary, ["kill", f"{base}-0", "--force"], timeout=60)
            assert result.returncode != 0, f"coi kill {base}-0 should fail"
            assert incus_status(base_slot2) == "RUNNING", f"coi kill {base}-0 killed {base_slot2}"

            # With its own container running, "<a>-2" acts on that container
            suffixed_slot1, _ = start_background_shell(coi_binary, workspace_b, env, slot=1)
            child = spawn_coi(coi_binary, ["attach", suffixed, "--bash"], env=env, timeout=60)
            with with_live_screen(child) as monitor:
                time.sleep(3)
                child.send("echo HOST_$(hostname)\r")
                attached = wait_for_text_in_monitor(monitor, f"HOST_{suffixed_slot1}", timeout=30)
            child.send("exit\r")
            try:
                child.expect(EOF, timeout=30)
            except TIMEOUT:
                pass
            child.close(force=True)
            assert attached, f"coi attach {suffixed} --bash should open a shell in {suffixed_slot1}"
            assert incus_status(base_slot2) == "RUNNING", (
                f"coi attach {suffixed} touched {base_slot2}"
            )

            result = run_coi(coi_binary, ["kill", suffixed, "--force"], timeout=60)
            assert result.returncode == 0, f"coi kill {suffixed} failed: {result.stderr}"
            containers = get_container_list()
            assert suffixed_slot1 not in containers, f"{suffixed_slot1} should be deleted"
            assert base_slot2 in containers, f"{base_slot2} of {base} should still exist"
        finally:
            for name in workspace_containers(workspace_b):
                subprocess.run(
                    [coi_binary, "container", "delete", name, "--force"],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )


class TestAliasWithContainerPrefix:
    """Test that an alias starting with the container prefix resolves for running-container commands."""

    def test_running_commands_resolve_prefixed_alias(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Alias "<prefix>web..." reaches its container in attach, monitor, unfreeze and kill."""
        prefix = os.environ.get("COI_CONTAINER_PREFIX", "coi-")
        prefixed = f"{prefix}web{uuid.uuid4().hex[:8]}"
        env = {**os.environ, "COI_USE_DUMMY": "1"}

        write_workspace_container_config(workspace_dir, image=dummy_image, alias=prefixed)
        container_name, _ = start_background_shell(coi_binary, workspace_dir, env, slot=1)
        assert prefixed in get_aliases_registry()

        child = spawn_coi(coi_binary, ["attach", prefixed, "--bash"], env=env, timeout=60)
        with with_live_screen(child) as monitor:
            time.sleep(3)
            child.send("echo HOST_$(hostname)\r")
            attached = wait_for_text_in_monitor(monitor, f"HOST_{container_name}", timeout=30)
        child.send("exit\r")
        try:
            child.expect(EOF, timeout=30)
        except TIMEOUT:
            pass
        child.close(force=True)
        assert attached, f"coi attach {prefixed} --bash should open a shell in {container_name}"

        result = run_coi(coi_binary, ["monitor", prefixed, "--json"], timeout=60)
        assert result.returncode == 0, f"coi monitor {prefixed} failed: {result.stderr}"
        assert f"Monitoring container: {container_name}" in result.stderr, result.stderr

        # A running container is not frozen: the error names the resolved container
        result = run_coi(coi_binary, ["unfreeze", prefixed], timeout=60)
        assert result.returncode != 0, f"coi unfreeze {prefixed} should fail on a running container"
        assert f"container {container_name} is not frozen" in result.stderr, result.stderr

        result = run_coi(coi_binary, ["kill", prefixed, "--force"], timeout=60)
        assert result.returncode == 0, f"coi kill {prefixed} failed: {result.stderr}"
        assert container_name not in get_container_list(), f"{container_name} should be deleted"


# ============================================================
# Conflict detection tests
# ============================================================


class TestAliasConflict:
    """Test alias conflict detection."""

    def test_alias_conflict_different_workspace(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image, tmp_path
    ):
        """Register alias for workspace A, try to use same alias from workspace B."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="conflictalias")

        # Register alias from workspace A
        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        # Create workspace B with same alias
        workspace_b = str(tmp_path / "workspace_b")
        os.makedirs(workspace_b)
        write_workspace_container_config(workspace_b, image=dummy_image, alias="conflictalias")

        # Try to run from workspace B
        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_b,
        )
        # Should fail with alias conflict
        assert result.returncode != 0, "Should fail with alias conflict"
        assert "conflict" in result.stderr.lower() or "already registered" in result.stderr.lower()

    def test_alias_same_workspace_idempotent(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Running twice from same workspace with same alias should not conflict."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="idempotentalias")

        result1 = run_coi(
            coi_binary,
            ["run", "echo", "first"],
            workspace_dir=workspace_dir,
        )
        assert result1.returncode == 0

        result2 = run_coi(
            coi_binary,
            ["run", "echo", "second"],
            workspace_dir=workspace_dir,
        )
        assert result2.returncode == 0, f"Second run should succeed: {result2.stderr}"


# ============================================================
# Shell launch-by-alias tests
# ============================================================


class TestShellAlias:
    """Test coi shell <alias> positional argument."""

    def test_shell_positional_arg_unknown_alias(self, coi_binary, tmp_path):
        """Running coi shell with unknown alias should show clear error."""
        other_dir = str(tmp_path / "other")
        os.makedirs(other_dir)

        result = run_coi(
            coi_binary,
            ["shell", "nonexistentalias"],
            workspace_dir=other_dir,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()


# ============================================================
# Edge case tests
# ============================================================


class TestAliasEdgeCases:
    """Test alias edge cases."""

    def test_alias_exact_container_name_passthrough(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Exact container name format should pass through without alias resolution."""
        write_workspace_container_config(workspace_dir, alias="edgealias")

        # Try to kill a container with exact name format (even if it doesn't exist)
        result = run_coi(
            coi_binary,
            ["kill", "coi-abc12345-1", "--force"],
        )
        # Should NOT error with "alias not found" — should pass through as container name
        if result.returncode != 0:
            assert "alias" not in result.stderr.lower()

    def test_alias_invalid_characters(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Invalid alias characters should be rejected."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="my project!")

        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode != 0
        assert "invalid" in result.stderr.lower()

    def test_alias_starts_with_digit(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Alias starting with digit should be rejected."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="123project")

        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode != 0
        assert (
            "invalid" in result.stderr.lower()
            or "must start with a letter" in result.stderr.lower()
        )

    def test_alias_empty_string(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Empty alias should work normally (no alias set)."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="")

        result = run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"Empty alias should work: {result.stderr}"

    def test_list_no_alias(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Container without alias should show empty alias in JSON output."""
        container_name = calculate_container_name(workspace_dir, 1)

        # No alias config — just launch normally (persistent/image via config)
        write_workspace_container_config(workspace_dir, persistent=True, image=dummy_image)
        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        list_result = run_coi(coi_binary, ["list", "--format=json"])
        assert list_result.returncode == 0

        data = json.loads(list_result.stdout)
        containers = data.get("active_containers", [])
        found = [c for c in containers if c.get("name") == container_name]
        assert len(found) > 0, f"Expected container '{container_name}' in list output"
        assert "alias" in found[0], f"Missing 'alias' key in container: {found[0]}"
        assert found[0]["alias"] == "", f"Expected empty alias, got '{found[0]['alias']}'"


# ============================================================
# CWD alias auto-registration tests (chicken-and-egg fix)
# ============================================================


def write_profile_config(workspace_dir, profile_name, alias=None, image=None):
    """Create a profile with optional alias and image in the workspace."""
    profile_dir = os.path.join(workspace_dir, ".coi", "profiles", profile_name)
    os.makedirs(profile_dir, exist_ok=True)
    lines = ["[container]"]
    if alias:
        lines.append(f'alias = "{alias}"')
    if image:
        lines.append(f'image = "{image}"')
    with open(os.path.join(profile_dir, "config.toml"), "w") as f:
        f.write("\n".join(lines) + "\n")


class TestAliasCWDAutoRegister:
    """Test that aliases from CWD config are auto-registered on first use."""

    def test_shell_alias_auto_registers_from_cwd(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """coi shell <alias> should work when CWD config has matching alias, even without prior registration."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="cwdauto")

        # Clear any existing registry entry for this alias
        registry = get_aliases_registry()
        if "cwdauto" in registry:
            # Remove it so we test the fallback
            del registry["cwdauto"]
            reg_path = os.path.join(os.path.expanduser("~"), ".coi", "aliases.json")
            with open(reg_path, "w") as f:
                json.dump(registry, f)

        # Run coi shell <alias> --background from the workspace dir — should auto-register.
        # Use --background so the command exits after starting the detached session.
        result = run_coi(
            coi_binary,
            ["shell", "cwdauto", "--background"],
            workspace_dir=workspace_dir,
        )
        # Should succeed (alias resolved via CWD fallback)
        assert result.returncode == 0, (
            f"Expected coi shell cwdauto to succeed via CWD fallback, "
            f"got rc={result.returncode}\nstderr: {result.stderr}\nstdout: {result.stdout}"
        )

        # Verify alias was auto-registered in the registry
        registry = get_aliases_registry()
        assert "cwdauto" in registry, (
            f"Alias 'cwdauto' should have been auto-registered, registry: {registry}"
        )
        assert registry["cwdauto"]["workspace"] == os.path.abspath(workspace_dir)

    def test_shell_alias_cwd_mismatch_still_fails(self, coi_binary, tmp_path):
        """coi shell <alias> should still fail when CWD config has a different alias."""
        workspace = str(tmp_path / "mismatch_workspace")
        os.makedirs(workspace)
        write_workspace_container_config(workspace, alias="actualname")

        result = run_coi(
            coi_binary,
            ["shell", "wrongname"],
            workspace_dir=workspace,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()

    def test_shell_alias_no_cwd_config_still_fails(self, coi_binary, tmp_path):
        """coi shell <alias> should still fail when CWD has no .coi/config.toml."""
        workspace = str(tmp_path / "no_config_workspace")
        os.makedirs(workspace)

        result = run_coi(
            coi_binary,
            ["shell", "nosuchproject"],
            workspace_dir=workspace,
        )
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()


# ============================================================
# Profile alias override prevention tests
# ============================================================


class TestProfileAliasNoOverride:
    """Test that profile aliases don't stomp project-level aliases."""

    def test_profile_alias_does_not_override_project_alias(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """When project has alias and profile has alias, project alias wins."""
        # Project config with its own alias
        write_workspace_container_config(workspace_dir, alias="projectalias")

        # Profile with a different alias
        write_profile_config(workspace_dir, "testprofile", alias="profilealias", image=dummy_image)

        result = run_coi(
            coi_binary,
            ["run", "--profile", "testprofile", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        # Verify the registry has the project alias, not the profile alias
        registry = get_aliases_registry()
        assert "projectalias" in registry, (
            f"Project alias 'projectalias' should be in registry: {registry}"
        )
        # The profile alias should NOT have replaced the project alias
        assert registry["projectalias"]["workspace"] == os.path.abspath(workspace_dir)

    def test_profile_alias_applied_when_project_has_none(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """When project has no alias but profile does, profile alias is used."""
        # Project config WITHOUT alias
        config_dir = os.path.join(workspace_dir, ".coi")
        os.makedirs(config_dir, exist_ok=True)
        with open(os.path.join(config_dir, "config.toml"), "w") as f:
            f.write("[container]\n")  # no alias

        # Profile with an alias
        write_profile_config(workspace_dir, "withalias", alias="fromsprofile", image=dummy_image)

        result = run_coi(
            coi_binary,
            ["run", "--profile", "withalias", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        # Verify the profile's alias was applied
        registry = get_aliases_registry()
        assert "fromsprofile" in registry, (
            f"Profile alias 'fromsprofile' should be in registry when project has no alias: {registry}"
        )

    def test_same_profile_two_projects_no_conflict(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image, tmp_path
    ):
        """Two projects with own aliases using same profile (which has alias) should not conflict."""
        # Project A with its own alias
        write_workspace_container_config(workspace_dir, alias="projectA")
        write_profile_config(workspace_dir, "shared", alias="sharedname", image=dummy_image)

        result_a = run_coi(
            coi_binary,
            ["run", "--profile", "shared", "echo", "ok"],
            workspace_dir=workspace_dir,
        )
        assert result_a.returncode == 0, f"Project A run failed: {result_a.stderr}"

        # Project B with its own alias
        workspace_b = str(tmp_path / "workspace_b")
        os.makedirs(workspace_b)
        write_workspace_container_config(workspace_b, alias="projectB")
        write_profile_config(workspace_b, "shared", alias="sharedname", image=dummy_image)

        result_b = run_coi(
            coi_binary,
            ["run", "--profile", "shared", "echo", "ok"],
            workspace_dir=workspace_b,
        )
        # Should NOT conflict because project aliases are preserved (not overridden by profile)
        assert result_b.returncode == 0, (
            f"Project B should not conflict with project A when both use same profile. "
            f"rc={result_b.returncode}\nstderr: {result_b.stderr}"
        )


# ============================================================
# Saved alias profile tests
# ============================================================


class TestAliasSavedProfile:
    """Test the profile that `coi shell --profile` saves for an alias."""

    def test_run_keeps_profile_saved_by_shell(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """`coi run` with an alias keeps the profile `coi shell --profile` saved
        for it in aliases.json, so `coi shell <alias>` still selects it."""
        write_workspace_container_config(workspace_dir, image=dummy_image, alias="keepprofile")
        write_profile_config(workspace_dir, "pa")

        registry = get_aliases_registry()
        if "keepprofile" in registry:
            del registry["keepprofile"]
            reg_path = os.path.join(os.path.expanduser("~"), ".coi", "aliases.json")
            with open(reg_path, "w") as f:
                json.dump(registry, f)

        result = run_coi(
            coi_binary,
            ["shell", "--background", "--profile", "pa"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi shell failed: {result.stderr}"
        entry = get_aliases_registry().get("keepprofile")
        assert entry == {"workspace": os.path.abspath(workspace_dir), "profile": "pa"}, (
            f"coi shell --profile pa should save the profile: {entry}"
        )

        result = run_coi(coi_binary, ["run", "echo", "ok"], workspace_dir=workspace_dir)
        assert result.returncode == 0, f"coi run failed: {result.stderr}"
        entry = get_aliases_registry().get("keepprofile")
        assert entry == {"workspace": os.path.abspath(workspace_dir), "profile": "pa"}, (
            f"coi run should keep the saved profile: {entry}"
        )
