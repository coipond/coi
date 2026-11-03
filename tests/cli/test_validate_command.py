"""
`coi validate profile <path>` — the schema-validation *logic* is covered by
tests/schema/test_profile_schema.py (65 tests via the validator), but the CLI
command that wraps it had no coverage (#559 A9).

Host-only: validate's PersistentPreRunE skips config loading, so these need no
Incus and run in the misc-cli lane.
"""

import json
import subprocess


def _validate(coi_binary, *args, timeout=30):
    return subprocess.run(
        [coi_binary, "validate", "profile", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_validate_profile_valid(coi_binary, tmp_path):
    """A schema-valid profile exits 0 with 'Profile is valid.'"""
    p = tmp_path / "config.toml"
    p.write_text('[network]\nmode = "restricted"\n')
    r = _validate(coi_binary, str(p))
    assert r.returncode == 0, f"valid profile should exit 0.\n{r.stdout}{r.stderr}"
    assert "is valid" in (r.stdout + r.stderr).lower()


def test_validate_profile_invalid(coi_binary, tmp_path):
    """A schema-invalid profile (unknown network mode) exits 1 with an error.
    `mode = "blocked"` is rejected by the schema (see test_profile_schema)."""
    p = tmp_path / "config.toml"
    p.write_text('[network]\nmode = "blocked"\n')
    r = _validate(coi_binary, str(p))
    assert r.returncode == 1, f"invalid profile should exit 1.\n{r.stdout}{r.stderr}"
    assert "validation failed" in (r.stdout + r.stderr).lower()


def test_validate_profile_json_output(coi_binary, tmp_path):
    """--format json emits a machine-readable result ({'valid': true, ...})."""
    p = tmp_path / "config.toml"
    p.write_text('[network]\nmode = "open"\n')
    r = subprocess.run(
        [coi_binary, "validate", "profile", str(p), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0, f"valid profile --format json should exit 0.\n{r.stdout}{r.stderr}"
    obj = json.loads(r.stdout)  # raises if stdout is not valid JSON
    assert obj.get("valid") is True, f"expected valid=true, got {obj}"


def test_validate_profile_missing_arg(coi_binary):
    """`coi validate profile` with no path is a usage error (ExactArgs(1))."""
    r = subprocess.run(
        [coi_binary, "validate", "profile"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode != 0, "missing path argument must fail"


def test_validate_profile_removed_network_logging(coi_binary, tmp_path):
    """A profile that still sets the removed [network.logging] section is valid,
    with one warning naming the file; --format json keeps stdout valid JSON."""
    p = tmp_path / "config.toml"
    p.write_text('[network]\nmode = "open"\n\n[network.logging]\nenabled = true\n')

    r = _validate(coi_binary, str(p))
    assert r.returncode == 0, f"profile with [network.logging] should exit 0.\n{r.stdout}{r.stderr}"
    assert "Profile is valid." in r.stdout
    assert r.stderr.count("[network.logging]") == 1, r.stderr
    assert str(p) in r.stderr

    r = _validate(coi_binary, str(p), "--format", "json")
    assert r.returncode == 0, f"--format json should exit 0.\n{r.stdout}{r.stderr}"
    assert json.loads(r.stdout).get("valid") is True
    assert r.stderr.count("[network.logging]") == 1, r.stderr
