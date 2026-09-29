"""
Test for coi snapshot error cases and edge scenarios.

Tests that:
1. Commands handle missing arguments gracefully
2. Invalid command combinations fail appropriately
3. Proper error messages for common mistakes
"""

import subprocess


def test_snapshot_no_subcommand(coi_binary):
    """
    Test that snapshot command without subcommand shows help.
    """
    result = subprocess.run(
        [coi_binary, "snapshot"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Should show help, not fail
    assert result.returncode == 0, "snapshot without subcommand should show help"
    assert "Available Commands:" in result.stdout, "Should show available commands"
    assert "create" in result.stdout, "Should list create subcommand"
    assert "list" in result.stdout, "Should list list subcommand"


def test_snapshot_invalid_subcommand(coi_binary):
    """
    Test that invalid subcommand shows help (Cobra default behavior).
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "invalid-command"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Cobra shows help for invalid subcommands
    assert result.returncode == 0, "Cobra shows help for invalid subcommand"
    assert "Available Commands:" in result.stdout, "Should show available commands in help"


def test_snapshot_create_too_many_args(coi_binary):
    """
    Test that create with too many arguments fails.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "create", "name1", "name2", "-c", "test-container"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Create with too many args should fail"
    # Cobra will show usage error


def test_snapshot_restore_requires_name(coi_binary):
    """
    Test that restore requires snapshot name.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "restore"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Restore without name should fail"
    assert "accepts 1 arg" in result.stderr or "required" in result.stderr.lower(), (
        "Should indicate argument required"
    )


def test_snapshot_info_requires_name(coi_binary):
    """
    Test that info requires snapshot name.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "info"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Info without name should fail"
    assert "accepts 1 arg" in result.stderr or "required" in result.stderr.lower(), (
        "Should indicate argument required"
    )


def test_snapshot_delete_requires_name_or_all(coi_binary):
    """
    Test that delete requires either name or --all flag.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "delete"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Without --container, it will fail trying to resolve container
    # But the important thing is it doesn't proceed without name or --all
    assert result.returncode != 0, "Delete without name or --all should fail"


def test_snapshot_list_all_no_containers(coi_binary):
    """
    Test listing all snapshots when no Coi containers exist.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "list", "--all"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    # Should succeed but show no containers
    assert result.returncode == 0, "List --all should succeed even with no containers"
    # Output should indicate no containers (either empty or explicit message)


def test_snapshot_create_empty_name(coi_binary):
    """
    Test that create with empty string name uses auto-generated name.
    """
    # Empty string as name - should be treated as no argument and use auto-generated
    result = subprocess.run(
        [coi_binary, "snapshot", "create", "", "-c", "nonexistent"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Will fail because container doesn't exist, but that's expected
    # The point is it shouldn't crash on empty name
    assert result.returncode != 0, "Should fail for nonexistent container"
    assert "not found" in result.stderr, "Should fail with container not found error, not crash"


def test_snapshot_restore_too_many_args(coi_binary):
    """
    Test that restore with too many arguments fails.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "restore", "name1", "name2", "-c", "test-container"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Restore with too many args should fail"


def test_snapshot_info_too_many_args(coi_binary):
    """
    Test that info with too many arguments fails.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "info", "name1", "name2", "-c", "test-container"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Info with too many args should fail"


def test_snapshot_delete_both_name_and_all(coi_binary):
    """
    Test that delete with both name and --all is valid (--all takes precedence).

    This is actually allowed - when --all is specified, any positional name is ignored.
    """
    result = subprocess.run(
        [coi_binary, "snapshot", "delete", "some-name", "--all", "-c", "nonexistent"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # Will fail because container doesn't exist
    assert result.returncode != 0, "Should fail for nonexistent container"
    assert "not found" in result.stderr, "Should fail with container not found error"


def test_snapshot_conflicting_flags(coi_binary):
    """
    Test handling of potentially conflicting flags.
    """
    # Try to create stateful snapshot with invalid container
    result = subprocess.run(
        [coi_binary, "snapshot", "create", "test", "--stateful", "-c", "nonexistent"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0, "Should fail for nonexistent container"
    assert "not found" in result.stderr, "Should fail with container not found error"


def test_snapshot_help_flag_all_subcommands(coi_binary):
    """
    Test that -h and --help work for all subcommands.
    """
    subcommands = ["create", "list", "restore", "delete", "info"]

    for subcmd in subcommands:
        for help_flag in ["-h", "--help"]:
            result = subprocess.run(
                [coi_binary, "snapshot", subcmd, help_flag],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0, f"Help should work for {subcmd} with {help_flag}"
            assert "Usage:" in result.stdout, f"Help output should show usage for {subcmd}"
            assert "Flags:" in result.stdout or "flags" in result.stdout.lower(), (
                f"Help should show flags for {subcmd}"
            )
