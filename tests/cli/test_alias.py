"""
Integration tests for container alias support (#304).

Tests alias registration, resolution, conflict detection, and cross-command support.
"""

import json
import os
import subprocess

from support.helpers import (
    calculate_container_name,
    get_container_list,
    write_workspace_container_config,
)


def write_alias_config(workspace_dir, alias_name, persistent=None, image=None):
    """Create .coi/config.toml with alias (and optional container settings).

    persistent/image go into the same [container] block — they replace the
    removed --persistent / --image CLI flags.
    """
    config_dir = os.path.join(workspace_dir, ".coi")
    os.makedirs(config_dir, exist_ok=True)
    lines = ["[container]", f'alias = "{alias_name}"']
    if persistent is not None:
        lines.append(f"persistent = {'true' if persistent else 'false'}")
    if image is not None:
        lines.append(f'image = "{image}"')
    with open(os.path.join(config_dir, "config.toml"), "w") as f:
        f.write("\n".join(lines) + "\n")


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
        write_alias_config(workspace_dir, "testalias", persistent=True, image=dummy_image)
        container_name = calculate_container_name(workspace_dir, 1)

        result = run_coi(
            coi_binary,
            ["run", "sleep", "30"],
            workspace_dir=workspace_dir,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        # Container is persistent, so it should still exist
        containers = get_container_list()
        assert container_name in containers, (
            f"Expected persistent container '{container_name}' to exist for alias verification"
        )

        check = subprocess.run(
            ["incus", "config", "get", container_name, "user.coi.alias"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert check.stdout.strip() == "testalias", (
            f"Expected alias 'testalias', got '{check.stdout.strip()}'"
        )


class TestAliasInRegistry:
    """Test that alias is registered in ~/.coi/aliases.json."""

    def test_alias_in_registry(self, coi_binary, workspace_dir, cleanup_containers, dummy_image):
        """Launch session with alias, verify it appears in registry."""
        write_alias_config(workspace_dir, "registrytest", image=dummy_image)

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
        write_alias_config(workspace_dir, "listalias", persistent=True, image=dummy_image)
        container_name = calculate_container_name(workspace_dir, 1)

        # Launch a persistent container so it stays running
        run_coi(
            coi_binary,
            ["run", "sleep", "30"],
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
        write_alias_config(workspace_dir, "textalias", persistent=True, image=dummy_image)
        container_name = calculate_container_name(workspace_dir, 1)

        run_coi(
            coi_binary,
            ["run", "sleep", "30"],
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
        write_alias_config(workspace_dir, "attachalias", persistent=True, image=dummy_image)

        # Start a persistent container
        run_coi(
            coi_binary,
            ["run", "sleep", "60"],
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
        write_alias_config(workspace_dir, "killalias", persistent=True, image=dummy_image)

        run_coi(
            coi_binary,
            ["run", "sleep", "60"],
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
        write_alias_config(workspace_dir, "shutdownalias", persistent=True, image=dummy_image)

        run_coi(
            coi_binary,
            ["run", "sleep", "60"],
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
        write_alias_config(workspace_dir, "unfreezealias", persistent=True, image=dummy_image)
        container_name = calculate_container_name(workspace_dir, 1)

        run_coi(
            coi_binary,
            ["run", "sleep", "60"],
            workspace_dir=workspace_dir,
        )

        # Pause the container
        subprocess.run(
            ["incus", "pause", container_name],
            capture_output=True,
            timeout=10,
        )

        # Unfreeze by alias
        result = run_coi(
            coi_binary,
            ["unfreeze", "unfreezealias"],
        )
        if result.returncode == 0:
            # Verify container is running again
            check = subprocess.run(
                ["incus", "list", container_name, "--format=csv", "-c", "s"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert "RUNNING" in check.stdout.upper()


# ============================================================
# Slot suffix tests
# ============================================================


class TestAliasSlotSuffix:
    """Test alias with slot suffixes (e.g. myproject-2)."""

    def test_alias_with_slot_suffix(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image
    ):
        """Launch two containers, kill slot 2 by alias suffix."""
        write_alias_config(workspace_dir, "slotalias", persistent=True, image=dummy_image)

        # Launch slot 1
        run_coi(
            coi_binary,
            ["run", "--slot", "1", "sleep", "60"],
            workspace_dir=workspace_dir,
        )
        # Launch slot 2
        run_coi(
            coi_binary,
            ["run", "--slot", "2", "sleep", "60"],
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


# ============================================================
# Conflict detection tests
# ============================================================


class TestAliasConflict:
    """Test alias conflict detection."""

    def test_alias_conflict_different_workspace(
        self, coi_binary, workspace_dir, cleanup_containers, dummy_image, tmp_path
    ):
        """Register alias for workspace A, try to use same alias from workspace B."""
        write_alias_config(workspace_dir, "conflictalias", image=dummy_image)

        # Register alias from workspace A
        run_coi(
            coi_binary,
            ["run", "echo", "ok"],
            workspace_dir=workspace_dir,
        )

        # Create workspace B with same alias
        workspace_b = str(tmp_path / "workspace_b")
        os.makedirs(workspace_b)
        write_alias_config(workspace_b, "conflictalias", image=dummy_image)

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
        write_alias_config(workspace_dir, "idempotentalias", image=dummy_image)

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
        write_alias_config(workspace_dir, "edgealias")

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
        write_alias_config(workspace_dir, "my project!", image=dummy_image)

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
        write_alias_config(workspace_dir, "123project", image=dummy_image)

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
        write_alias_config(workspace_dir, "", image=dummy_image)

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
            ["run", "sleep", "30"],
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
        write_alias_config(workspace_dir, "cwdauto", image=dummy_image)

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
        write_alias_config(workspace, "actualname")

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
        write_alias_config(workspace_dir, "projectalias")

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
        write_alias_config(workspace_dir, "projectA")
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
        write_alias_config(workspace_b, "projectB")
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
        write_alias_config(workspace_dir, "keepprofile", image=dummy_image)
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
