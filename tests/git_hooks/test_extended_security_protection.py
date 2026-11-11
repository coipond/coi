"""Test extended security protection feature.

This feature extends the git hooks protection to support configurable protected paths.
Default protected paths include:
- .git/hooks (git hooks execute on git operations)
- .git/config (can set core.hooksPath to bypass hooks protection)
- .husky (husky git hooks manager)
- .vscode (VS Code tasks.json can auto-execute, settings.json can inject shell args)

Configuration options:
- [security] protected_paths - Replace default protected paths list
- [security] additional_protected_paths - Add paths without replacing defaults
- [security] disable_protection - Disable all path protection
"""

import subprocess
from pathlib import Path

import pytest

from support.helpers import (
    has_immutable_capability,
    write_trusted_coi_config,
)
from support.helpers import (
    make_workspace_writable as _make_workspace_writable,
)


class TestGitConfigProtection:
    """Tests for .git/config protection (prevents core.hooksPath bypass)."""

    def test_git_config_readonly_by_default(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .git/config is mounted read-only by default."""
        # Initialize a git repository
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Ensure .git/config exists
        git_config = Path(workspace_dir) / ".git" / "config"
        assert git_config.exists(), ".git/config should exist after git init"

        # Try to modify .git/config from container
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "echo '[core]' >> /workspace/.git/config",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should fail because .git/config is read-only
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"

    def test_git_config_core_hookspath_attack_blocked(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that setting core.hooksPath via git config fails."""
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Try to set core.hooksPath to a malicious location
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "git",
                "-C",
                "/workspace",
                "config",
                "core.hooksPath",
                "/tmp/malicious-hooks",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should fail because .git/config is read-only
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "could not lock" in combined.lower()
            or "unable to create" in combined.lower()
        ), f"Expected config lock error, got: {combined}"

    def test_git_config_readable(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .git/config can be read from container."""
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Read .git/config from container
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "cat",
                "/workspace/.git/config",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should succeed and show config content
        assert result.returncode == 0
        # Git config should have at least [core] section
        assert "[core]" in result.stdout or "repositoryformatversion" in result.stdout


class TestHuskyProtection:
    """Tests for .husky directory protection (husky git hooks manager)."""

    def test_husky_readonly_by_default(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .husky directory is mounted read-only by default."""
        # Create .husky directory (simulating a project using husky)
        husky_dir = Path(workspace_dir) / ".husky"
        husky_dir.mkdir(parents=True, exist_ok=True)

        # Create a pre-commit hook
        pre_commit = husky_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho 'Original hook'\n")

        # Try to write to .husky from container
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "echo 'malicious' > /workspace/.husky/pre-commit",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should fail because .husky is read-only
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"

        # Original content should be preserved
        assert "Original hook" in pre_commit.read_text()

    def test_husky_touch_fails(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that creating files in .husky fails when protected."""
        husky_dir = Path(workspace_dir) / ".husky"
        husky_dir.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "touch",
                "/workspace/.husky/new-hook",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"

    def test_husky_readable(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .husky files can be read from container."""
        husky_dir = Path(workspace_dir) / ".husky"
        husky_dir.mkdir(parents=True, exist_ok=True)

        pre_commit = husky_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho 'Husky pre-commit'\n")

        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "cat",
                "/workspace/.husky/pre-commit",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0
        assert "Husky pre-commit" in result.stdout

    def test_husky_nonexistent_no_error(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that missing .husky directory doesn't cause errors."""
        # workspace_dir has no .husky directory

        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "hello",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should succeed without any husky-related errors
        assert result.returncode == 0
        assert "hello" in result.stdout


class TestVscodeProtection:
    """Tests for .vscode directory protection (prevents tasks.json auto-execute attacks)."""

    def test_vscode_readonly_by_default(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .vscode directory is mounted read-only by default."""
        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)

        # Create a tasks.json
        tasks_json = vscode_dir / "tasks.json"
        tasks_json.write_text('{"version": "2.0.0", "tasks": []}\n')

        # Try to write to .vscode from container
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                "echo 'malicious' > /workspace/.vscode/tasks.json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"

    def test_vscode_settings_json_protected(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .vscode/settings.json cannot be modified."""
        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)

        settings_json = vscode_dir / "settings.json"
        settings_json.write_text('{"editor.fontSize": 14}\n')

        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sh",
                "-c",
                'echo \'{"terminal.integrated.shellArgs.linux": ["-c", "malicious"]}\' > /workspace/.vscode/settings.json',
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode != 0
        # Original content should be preserved
        assert "editor.fontSize" in settings_json.read_text()

    def test_vscode_readable(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .vscode files can be read from container."""
        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)

        settings_json = vscode_dir / "settings.json"
        settings_json.write_text('{"editor.fontSize": 16}\n')

        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "cat",
                "/workspace/.vscode/settings.json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0
        assert "editor.fontSize" in result.stdout


class TestSecurityConfigAdditionalPaths:
    """Tests for additional_protected_paths configuration."""

    def test_additional_paths_are_protected(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that additional_protected_paths adds to defaults."""
        # Create config that adds .idea to protected paths
        config_content = """
[security]
additional_protected_paths = [".idea"]
"""
        config_dir = Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.toml"
        config_file.write_text(config_content)

        # Create .idea directory (simulating IntelliJ project)
        idea_dir = Path(workspace_dir) / ".idea"
        idea_dir.mkdir(parents=True, exist_ok=True)
        workspace_xml = idea_dir / "workspace.xml"
        workspace_xml.write_text("<project></project>")

        # Run command from workspace directory to pick up config
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "sh",
                "-c",
                "echo 'malicious' > /workspace/.idea/workspace.xml",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
        )

        # Should fail because .idea is now protected
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"

    def test_additional_paths_preserves_defaults(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that additional_protected_paths doesn't replace defaults."""
        # Create config that adds .idea
        config_content = """
[security]
additional_protected_paths = [".idea"]
"""
        config_dir = Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.toml"
        config_file.write_text(config_content)

        # Initialize git repo (for .git/hooks default protection)
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Ensure hooks dir exists
        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # Run command - default .git/hooks should still be protected
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "touch",
                "/workspace/.git/hooks/new-hook",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
        )

        # Should fail because .git/hooks is still protected (default)
        assert result.returncode != 0


class TestSecurityConfigCustomPaths:
    """Tests for protected_paths configuration (replaces defaults)."""

    def test_custom_paths_replace_defaults(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that protected_paths replaces the default list."""
        # protected_paths REPLACES the defaults — a protection downgrade, so it is
        # honored only from trusted-scope config (COI_CONFIG), not an untrusted
        # project .coi/config.toml.
        env = write_trusted_coi_config('[security]\nprotected_paths = [".git/hooks"]\n')

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Create .vscode (would be protected by default, but not with our custom list)
        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)

        # Make workspace writable by container user (CI UID mismatch workaround)
        _make_workspace_writable(workspace_dir)

        # Try to write to .vscode - should succeed since it's not in custom list
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "touch",
                "/workspace/.vscode/test.json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
            env=env,
        )

        # Should succeed because .vscode is not in our custom protected_paths
        assert result.returncode == 0, f"Expected success, got: {result.stderr}"

        # Verify file was created
        test_file = vscode_dir / "test.json"
        assert test_file.exists()


class TestSecurityConfigDisableProtection:
    """Tests for disable_protection configuration."""

    def test_disable_protection_allows_all(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that disable_protection=true allows writing to all paths."""
        # disable_protection removes ALL protections — a downgrade, so it is
        # honored only from trusted-scope config (COI_CONFIG), not an untrusted
        # project .coi/config.toml.
        env = write_trusted_coi_config("[security]\ndisable_protection = true\n")

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Ensure hooks dir exists
        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # Make workspace writable by container user (CI UID mismatch workaround)
        _make_workspace_writable(workspace_dir)

        # Run command - should be able to write to hooks
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "sh",
                "-c",
                "echo '#!/bin/sh' > /workspace/.git/hooks/pre-commit",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
            env=env,
        )

        # Should succeed because protection is disabled
        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Verify hook was created
        hook_file = hooks_dir / "pre-commit"
        assert hook_file.exists()


class TestSecurityLogging:
    """Tests for security protection logging."""

    def test_protection_logged_for_multiple_paths(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that protection status is logged for multiple paths."""
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Create multiple protected paths
        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)

        # Run command and check for protection message
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode == 0
        combined = result.stdout + result.stderr

        # Should mention protected paths
        assert "protected" in combined.lower(), f"Expected protection message, got: {combined}"


class TestSymlinkSecurity:
    """Tests for symlink security (preventing mount of arbitrary host paths)."""

    def test_symlinked_protected_path_rejected(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that symlinked protected paths are rejected."""
        # Create a target directory
        target_dir = Path(workspace_dir) / "target"
        target_dir.mkdir(parents=True, exist_ok=True)

        # Create .vscode as a symlink to target
        vscode_link = Path(workspace_dir) / ".vscode"
        vscode_link.symlink_to(target_dir)

        # Run command - should not error but symlink should not be mounted
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should succeed (symlink just skipped, not an error)
        assert result.returncode == 0

    def test_symlinked_git_dir_handled(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .git as symlink (worktree) is handled gracefully."""
        # Create a target directory
        target_dir = Path(workspace_dir) / "git-target"
        target_dir.mkdir(parents=True, exist_ok=True)

        # Create .git as a symlink (simulating git worktree)
        git_link = Path(workspace_dir) / ".git"
        git_link.symlink_to(target_dir)

        # Run command - should not error
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should succeed - symlinked .git is skipped gracefully
        assert result.returncode == 0

    def test_git_file_handled(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that .git as file (submodule/worktree) is handled gracefully."""
        # Create .git as a file (simulating submodule or worktree)
        git_file = Path(workspace_dir) / ".git"
        git_file.write_text("gitdir: /some/other/path\n")

        # Run command - should not error
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should succeed - .git as file is skipped gracefully
        assert result.returncode == 0


class TestWritableGitHooksConfigCompat:
    """Tests for [git] writable_hooks config compatibility."""

    def test_writable_git_hooks_config_makes_hooks_writable(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that writable_hooks config makes .git/hooks writable.

        Note: writable_hooks = true only removes .git/hooks from protected
        paths. Other paths (.vscode, .husky, .git/config) remain protected.
        """
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # writable_hooks is honored only from trusted-scope config (COI_CONFIG),
        # not an untrusted project .coi/config.toml.
        env = write_trusted_coi_config("[git]\nwritable_hooks = true\n")

        # Create hooks dir
        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # Make workspace writable by container user (CI UID mismatch workaround)
        _make_workspace_writable(workspace_dir)

        # Run with writable hooks enabled — only .git/hooks should be writable
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "touch",
                "/workspace/.git/hooks/test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
            env=env,
        )

        # Should succeed — .git/hooks is writable
        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert (hooks_dir / "test").exists()

    def test_config_writable_hooks_keeps_other_paths_protected(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that [git] writable_hooks=true still protects non-hooks paths.

        writable_hooks only removes .git/hooks from the protected list.
        Other paths like .husky remain read-only.
        """
        # Create config with writable_hooks
        config_content = """
[git]
writable_hooks = true
"""
        config_dir = Path(workspace_dir) / ".coi"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "config.toml"
        config_file.write_text(config_content)

        # Initialize git repo
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        # Create .husky (should still be protected)
        husky_dir = Path(workspace_dir) / ".husky"
        husky_dir.mkdir(parents=True, exist_ok=True)

        # Run from workspace to pick up config
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "touch",
                "/workspace/.husky/test",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
        )

        # Should fail — .husky is still protected despite writable_hooks
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert (
            "read-only" in combined.lower()
            or "read only" in combined.lower()
            or "permission denied" in combined.lower()
        ), f"Expected read-only error, got: {combined}"


class TestImmutableProtection:
    """Tests for host-side immutable attribute protection (P0-2a).

    The immutable attribute (FS_IMMUTABLE_FL / chattr +i) is applied on the host
    before the container starts. This prevents the unshare+umount bypass of
    read-only bind mounts: even after unmounting the overlay, the underlying
    inode is immutable and writes fail with EPERM.

    These tests require the coi binary to have CAP_LINUX_IMMUTABLE
    (granted by: sudo setcap cap_linux_immutable=ep <coi-binary>).
    Without the capability, immutable protection is not applied and
    the tests are skipped.
    """

    def test_unshare_umount_bypass_blocked(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that unshare+umount cannot bypass protected path protection.

        This is the core P0-2a security test. Without immutable protection,
        a process with CAP_SYS_ADMIN (root) inside the container can:
          1. Create a new mount namespace (unshare -m)
          2. Unmount the read-only bind mount
          3. Write directly to the underlying file

        With immutable protection, step 3 fails because FS_IMMUTABLE_FL is
        enforced at the inode level, independent of mount namespace.
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        # Initialize a git repository with a hook file
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho safe\n")

        # Attempt the unshare+umount attack from inside the container.
        # sudo unshare -m creates a new mount namespace where we can umount
        # the read-only overlay, exposing the underlying filesystem.
        subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.git/hooks 2>/dev/null; "
                "echo pwned > /workspace/.git/hooks/pre-commit 2>&1 || echo ATTACK_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Verify original content is preserved on host
        content = pre_commit.read_text()
        assert "safe" in content, (
            f"Hook file was modified by attack! Content: {content} (see FLAWS.md Finding 1)"
        )
        assert "pwned" not in content, (
            f"Attack bypassed immutable protection! Content: {content} (see FLAWS.md Finding 1)"
        )

    def test_unshare_umount_file_creation_blocked(
        self, coi_binary, workspace_dir, cleanup_containers
    ):
        """Test that creating new files via unshare+umount is blocked."""
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)

        # Attempt to create a new hook file after umounting the read-only overlay
        subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.git/hooks 2>/dev/null; "
                "touch /workspace/.git/hooks/evil-hook 2>&1 || echo CREATION_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # The evil hook should not exist on host
        evil_hook = hooks_dir / "evil-hook"
        assert not evil_hook.exists(), (
            "New file was created despite immutable protection! (see FLAWS.md Finding 1)"
        )

    def test_immutable_cleaned_after_session(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that immutable bits are cleared after the session ends.

        After coi run completes, the workspace files should be writable again
        on the host. This ensures immutable doesn't interfere with normal
        developer workflow between sessions.
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho original\n")

        # Run a simple command (this applies + removes immutable)
        result = subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "echo",
                "done",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"coi run failed: {result.stderr}"

        # After session ends, files should be writable again on host
        pre_commit.write_text("#!/bin/sh\necho modified\n")
        assert "modified" in pre_commit.read_text()

    def test_unshare_umount_git_config_blocked(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that unshare+umount cannot bypass .git/config protection.

        .git/config is a file-level protected path. An attacker who can
        modify it can set core.hooksPath to a directory they control,
        bypassing hooks protection entirely (see FLAWS.md Finding 1).
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)

        git_config = Path(workspace_dir) / ".git" / "config"
        original_content = git_config.read_text()

        # Attempt to overwrite .git/config with a malicious hooksPath
        subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.git/config 2>/dev/null; "
                "echo '[core]\nhookspath=/tmp/evil' > /workspace/.git/config 2>&1 "
                "|| echo ATTACK_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Verify original content is preserved on host
        content = git_config.read_text()
        assert content == original_content, (
            f".git/config was modified by attack! "
            f"Expected: {original_content!r}, Got: {content!r} "
            f"(see FLAWS.md Finding 1)"
        )
        assert "hookspath" not in content.lower(), (
            f"Attack injected core.hooksPath into .git/config! Content: {content} "
            f"(see FLAWS.md Finding 1)"
        )

    def test_unshare_umount_husky_blocked(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that unshare+umount cannot bypass .husky protection.

        .husky is a directory-level protected path. Husky hooks execute
        automatically on git operations, so an attacker who can write here
        gains host-side code execution (see FLAWS.md Finding 1).
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        husky_dir = Path(workspace_dir) / ".husky"
        husky_dir.mkdir(parents=True, exist_ok=True)
        pre_commit = husky_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho safe\n")

        # Attempt the unshare+umount attack on .husky
        subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.husky 2>/dev/null; "
                "echo pwned > /workspace/.husky/pre-commit 2>&1 "
                "|| echo ATTACK_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Verify original content is preserved on host
        content = pre_commit.read_text()
        assert "safe" in content, (
            f".husky/pre-commit was modified by attack! Content: {content} (see FLAWS.md Finding 1)"
        )
        assert "pwned" not in content, (
            f"Attack bypassed immutable protection on .husky! Content: {content} "
            f"(see FLAWS.md Finding 1)"
        )

    def test_unshare_umount_vscode_blocked(self, coi_binary, workspace_dir, cleanup_containers):
        """Test that unshare+umount cannot bypass .vscode protection.

        .vscode is a directory-level protected path. tasks.json can
        auto-execute commands and settings.json can inject shell arguments,
        so an attacker who can write here gains host-side code execution
        (see FLAWS.md Finding 1).
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        vscode_dir = Path(workspace_dir) / ".vscode"
        vscode_dir.mkdir(parents=True, exist_ok=True)
        tasks_json = vscode_dir / "tasks.json"
        tasks_json.write_text('{"version": "2.0.0", "tasks": []}\n')

        # Attempt the unshare+umount attack on .vscode
        subprocess.run(
            [
                coi_binary,
                "run",
                "--workspace",
                workspace_dir,
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.vscode 2>/dev/null; "
                "echo '{\"malicious\": true}' > /workspace/.vscode/tasks.json 2>&1 "
                "|| echo ATTACK_BLOCKED",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Verify original content is preserved on host
        content = tasks_json.read_text()
        assert "2.0.0" in content, (
            f".vscode/tasks.json was modified by attack! Content: {content} "
            f"(see FLAWS.md Finding 1)"
        )
        assert "malicious" not in content, (
            f"Attack bypassed immutable protection on .vscode! Content: {content} "
            f"(see FLAWS.md Finding 1)"
        )

    def test_bypass_succeeds_without_immutable(self, coi_binary, workspace_dir, cleanup_containers):
        """Negative test: unshare+umount SUCCEEDS when immutable is disabled.

        This test proves the attack vector is real and that the immutable
        attribute is what blocks it. Without this test, the other immutable
        tests could vacuously pass (e.g. if unshare is broken, or the
        container lacks CAP_SYS_ADMIN).

        With host_immutable=false, the only protection is the read-only
        bind mount, which is defeated by unshare+umount.
        """
        if not has_immutable_capability(coi_binary):
            pytest.skip(
                "coi binary lacks CAP_LINUX_IMMUTABLE "
                "(grant with: sudo setcap cap_linux_immutable=ep <coi-binary>)"
            )

        # host_immutable=false is a protection downgrade, honored only from
        # trusted-scope config (COI_CONFIG), not an untrusted project config.
        env = write_trusted_coi_config("[security]\nhost_immutable = false\n")

        # Initialize git repo with a hook file
        subprocess.run(["git", "init"], cwd=workspace_dir, check=True, capture_output=True)
        hooks_dir = Path(workspace_dir) / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit = hooks_dir / "pre-commit"
        pre_commit.write_text("#!/bin/sh\necho safe\n")

        # Make workspace writable so the container user can write after umount
        _make_workspace_writable(workspace_dir)

        # Run the attack with immutable disabled — should succeed
        subprocess.run(
            [
                coi_binary,
                "run",
                "--",
                "sudo",
                "unshare",
                "-m",
                "sh",
                "-c",
                "umount /workspace/.git/hooks 2>/dev/null; "
                "echo pwned > /workspace/.git/hooks/pre-commit",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=workspace_dir,
            env=env,
        )

        # The attack SHOULD succeed — this validates the test isn't vacuous
        content = pre_commit.read_text()
        assert "pwned" in content, (
            f"Expected attack to succeed with host_immutable=false, "
            f"but hook was NOT modified. Content: {content}. "
            f"This means the test is vacuous — the attack vector may not "
            f"be working, making the immutable protection tests meaningless "
            f"(see FLAWS.md Finding 1)"
        )
