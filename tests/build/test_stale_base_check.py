"""
Integration tests for stale base image detection.

Tests that coi run correctly errors, warns, or silently proceeds when a custom
image's base was rebuilt more recently than the custom image itself.

The stale condition is simulated by directly editing ~/.coi/image-meta.json
after building, so the tests do not need to actually rebuild the base image.
"""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path


def _meta_path() -> Path:
    return Path.home() / ".coi" / "image-meta.json"


def _make_base_stale(child_alias: str, base_alias: str):
    """Rewrite image-meta.json so base_alias appears newer than child_alias."""
    meta_path = _meta_path()
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}

    now = datetime.now(tz=UTC)
    meta[child_alias] = {
        "built_at": (now - timedelta(hours=2)).isoformat(),
        "base_image": base_alias,
    }
    meta[base_alias] = {
        "built_at": now.isoformat(),
        "base_image": "",
    }
    meta_path.write_text(json.dumps(meta, indent=2))


def _remove_meta_entries(*aliases):
    meta_path = _meta_path()
    if not meta_path.exists():
        return
    meta = json.loads(meta_path.read_text())
    for alias in aliases:
        meta.pop(alias, None)
    meta_path.write_text(json.dumps(meta, indent=2))


def _build_custom_image(coi_binary, image_name, tmp_path):
    """Build a minimal custom image and return True on success."""
    profile_dir = tmp_path / ".coi" / "profiles" / "stale-test"
    profile_dir.mkdir(parents=True)
    (profile_dir / "config.toml").write_text(
        f'[container]\nimage = "{image_name}"\n\n'
        '[container.build]\nbase = "coi-default"\n'
        'commands = ["echo stale-test > /tmp/marker.txt"]\n'
    )
    result = subprocess.run(
        [coi_binary, "build", "--profile", "stale-test"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(tmp_path),
    )
    return result.returncode == 0


def _run_with_config(coi_binary, image_name, stale_base_check, tmp_path):
    """Run `coi run -- true` with the given stale_base_check setting."""
    config_dir = tmp_path / ".coi"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "config.toml").write_text(
        f'[container]\nimage = "{image_name}"\nstale_base_check = "{stale_base_check}"\n'
    )
    return subprocess.run(
        [coi_binary, "run", "--", "true"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(tmp_path),
    )


def test_stale_base_check_error(coi_binary, tmp_path):
    """When stale_base_check = "error", coi run must fail with a message."""
    image_name = "coi-test-stale-error"

    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        return

    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)

    if not _build_custom_image(coi_binary, image_name, tmp_path):
        return

    try:
        _make_base_stale(image_name, "coi-default")

        result = _run_with_config(coi_binary, image_name, "error", tmp_path)

        assert result.returncode != 0, (
            "coi run should fail when stale_base_check=error and base is newer. "
            f"stderr: {result.stderr}"
        )
        assert "older than its base" in result.stderr, (
            f"Error message should mention stale base. stderr: {result.stderr}"
        )
    finally:
        _remove_meta_entries(image_name, "coi-default")
        subprocess.run(
            [coi_binary, "image", "delete", image_name], check=False, capture_output=True
        )


def test_stale_base_check_warn(coi_binary, tmp_path):
    """When stale_base_check = "warn", coi run succeeds but prints a warning."""
    image_name = "coi-test-stale-warn"

    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        return

    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)

    if not _build_custom_image(coi_binary, image_name, tmp_path):
        return

    try:
        _make_base_stale(image_name, "coi-default")

        result = _run_with_config(coi_binary, image_name, "warn", tmp_path)

        assert result.returncode == 0, (
            f"coi run should succeed when stale_base_check=warn. stderr: {result.stderr}"
        )
        assert "WARNING" in result.stderr and "older than its base" in result.stderr, (
            f"Warning should be printed. stderr: {result.stderr}"
        )
    finally:
        _remove_meta_entries(image_name, "coi-default")
        subprocess.run(
            [coi_binary, "image", "delete", image_name], check=False, capture_output=True
        )


def test_stale_base_check_off(coi_binary, tmp_path):
    """When stale_base_check = "off", coi run succeeds silently."""
    image_name = "coi-test-stale-off"

    result = subprocess.run(
        [coi_binary, "image", "exists", "coi-default"],
        capture_output=True,
    )
    if result.returncode != 0:
        return

    subprocess.run([coi_binary, "image", "delete", image_name], check=False, capture_output=True)

    if not _build_custom_image(coi_binary, image_name, tmp_path):
        return

    try:
        _make_base_stale(image_name, "coi-default")

        result = _run_with_config(coi_binary, image_name, "off", tmp_path)

        assert result.returncode == 0, (
            f"coi run should succeed when stale_base_check=off. stderr: {result.stderr}"
        )
        assert "older than its base" not in result.stderr, (
            f"No stale warning should be printed. stderr: {result.stderr}"
        )
    finally:
        _remove_meta_entries(image_name, "coi-default")
        subprocess.run(
            [coi_binary, "image", "delete", image_name], check=False, capture_output=True
        )
