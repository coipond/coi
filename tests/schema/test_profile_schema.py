"""
Integration tests for `coi schema profile`.

Verifies that the command outputs a valid JSON Schema (2020-12) document
and that the schema correctly accepts and rejects profile configurations.

These tests use the `jsonschema` Python package (declared in
tests/support/requirements.txt) to exercise the schema as an external
consumer (e.g. a Rails web UI) would.
"""

import json
import subprocess

import pytest
from jsonschema import Draft202012Validator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def profile_schema(coi_binary):
    """Run `coi schema profile` once per module and return the parsed schema."""
    result = subprocess.run(
        [coi_binary, "schema", "profile"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"coi schema profile failed:\n{result.stderr}"
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def validator(profile_schema):
    """Return a Draft202012Validator pre-loaded with the profile schema."""
    Draft202012Validator.check_schema(profile_schema)
    return Draft202012Validator(profile_schema)


# ---------------------------------------------------------------------------
# Schema structure tests
# ---------------------------------------------------------------------------


def test_schema_output_is_valid_json(coi_binary):
    """coi schema profile must emit valid JSON."""
    result = subprocess.run(
        [coi_binary, "schema", "profile"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    json.loads(result.stdout)  # raises if invalid


def test_schema_meta_fields(profile_schema):
    """Schema must declare required meta-fields."""
    assert profile_schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    assert "$id" in profile_schema
    assert "title" in profile_schema
    assert profile_schema.get("type") == "object"


def test_schema_top_level_properties(profile_schema):
    """All expected top-level profile keys must be declared."""
    props = profile_schema.get("properties", {})
    expected = {
        "inherits",
        "context",
        "forward_env",
        "environment",
        "container",
        "limits",
        "tool",
        "mounts",
        "network",
        "paths",
        "incus",
        "git",
        "ssh",
        "security",
        "monitoring",
        "timezone",
        "shell",
    }
    missing = expected - set(props.keys())
    assert not missing, f"Schema is missing top-level properties: {missing}"


def test_schema_defs_present(profile_schema):
    """All referenced $defs must be present in the schema document."""
    defs = profile_schema.get("$defs", {})
    expected_defs = {
        "ContainerConfig",
        "BuildConfig",
        "LimitsConfig",
        "CPULimits",
        "MemoryLimits",
        "DiskLimits",
        "RuntimeLimits",
        "ToolConfig",
        "ClaudeToolConfig",
        "MountEntry",
        "NetworkConfig",
        "NetworkLoggingConfig",
        "PathsConfig",
        "IncusConfig",
        "GitConfig",
        "SSHConfig",
        "SecurityConfig",
        "MonitoringConfig",
        "NFTMonitoringConfig",
        "TimezoneConfig",
        "ShellConfig",
    }
    missing = expected_defs - set(defs.keys())
    assert not missing, f"Schema is missing $defs entries: {missing}"


def test_schema_is_valid_draft202012(profile_schema):
    """The schema itself must be a valid JSON Schema 2020-12 document."""
    Draft202012Validator.check_schema(profile_schema)


# ---------------------------------------------------------------------------
# Valid profile tests
# ---------------------------------------------------------------------------


def test_empty_profile_is_valid(validator):
    """An empty profile (no keys at all) must be valid — everything is optional."""
    validator.validate({})


def test_minimal_profile_with_image(validator):
    """A profile that only sets a container image must be valid."""
    validator.validate({"container": {"image": "coi-rust"}})


def test_full_profile_is_valid(validator):
    """A profile exercising every section must pass validation."""
    profile = {
        "inherits": "default",
        "context": "CONTEXT.md",
        "forward_env": ["RUST_BACKTRACE", "CARGO_HOME"],
        "environment": {"RUST_BACKTRACE": "1", "EDITOR": "vim"},
        "container": {
            "image": "coi-rust",
            "persistent": True,
            "storage_pool": "default",
            "alias": "rust-workspace",
            "build": {
                "base": "coi",
                "script": "build.sh",
                "commands": ["apt-get install -y rustup"],
            },
        },
        "limits": {
            "cpu": {"count": "4", "allowance": "50%", "priority": 5},
            "memory": {"limit": "8GiB", "enforce": "hard", "swap": "false"},
            "disk": {
                "read": "100MiB/s",
                "write": "50MiB/s",
                "max": "150MiB/s",
                "priority": 3,
                "tmpfs_size": "4GiB",
            },
            "runtime": {
                "max_duration": "4h",
                "max_processes": 512,
                "auto_stop": True,
                "stop_graceful": True,
            },
        },
        "tool": {
            "name": "claude",
            "binary": "claude",
            "permission_mode": "bypass",
            "context_file": "~/.coi/context.md",
            "auto_context": True,
            "claude": {"effort_level": "high", "model": "opus"},
        },
        "mounts": [
            {"host": "~/.cargo", "container": "/home/code/.cargo"},
            {"host": "~/.rustup", "container": "/home/code/.rustup", "readonly": True},
        ],
        "network": {
            "mode": "restricted",
            "block_private_networks": True,
            "block_metadata_endpoint": True,
            "allowed_domains": ["crates.io", "github.com"],
            "refresh_interval_minutes": 60,
            "allow_local_network_access": False,
            "logging": {"enabled": True, "path": "/tmp/net.log"},
        },
        "paths": {
            "sessions_dir": "~/.coi/sessions",
            "storage_dir": "~/.coi/storage",
            "logs_dir": "~/.coi/logs",
            "preserve_workspace_path": False,
        },
        "incus": {
            "project": "default",
            "group": "incus",
            "code_uid": 1000,
            "code_user": "code",
            "disable_shift": False,
        },
        "git": {"writable_hooks": False},
        "ssh": {"forward_agent": True},
        "security": {
            "protected_paths": [".git/hooks", ".git/config"],
            "additional_protected_paths": [".husky"],
            "disable_protection": False,
            "host_immutable": True,
        },
        "monitoring": {
            "enabled": True,
            "auto_pause_on_high": True,
            "auto_kill_on_critical": True,
            "poll_interval_sec": 5,
            "file_read_threshold_mb": 500.0,
            "file_read_rate_mb_per_sec": 100.0,
            "audit_log_retention_days": 30,
            "nft": {
                "enabled": True,
                "rate_limit_per_second": 100,
                "dns_query_threshold": 200,
                "log_dns_queries": True,
                "lima_host": "",
            },
        },
        "timezone": {"mode": "fixed", "name": "Europe/Warsaw"},
        "shell": {"use_tmux": True},
    }
    validator.validate(profile)


def test_network_mode_open(validator):
    validator.validate({"network": {"mode": "open"}})


def test_network_mode_allowlist(validator):
    validator.validate({"network": {"mode": "allowlist", "allowed_domains": ["example.com"]}})


def test_tool_permission_mode_interactive(validator):
    validator.validate({"tool": {"permission_mode": "interactive"}})


def test_claude_effort_level_variants(validator):
    for level in ["low", "medium", "high", "xhigh", "max", "auto", ""]:
        validator.validate({"tool": {"claude": {"effort_level": level}}})


def test_claude_model_variants(validator):
    # model is a free-form string (aliases and full IDs both allowed).
    for model in ["opus", "sonnet", "claude-opus-4-8", ""]:
        validator.validate({"tool": {"claude": {"model": model}}})


def test_root_model_rejected(validator):
    """The old root-level `model` was moved to [tool.claude]; it is no longer a
    valid top-level key."""
    errors = list(validator.iter_errors({"model": "opus"}))
    assert errors, "Expected validation error for removed root-level 'model'"


def test_timezone_utc_mode(validator):
    validator.validate({"timezone": {"mode": "utc"}})


def test_timezone_host_mode(validator):
    validator.validate({"timezone": {"mode": "host"}})


def test_memory_enforce_soft(validator):
    validator.validate({"limits": {"memory": {"enforce": "soft"}}})


# ---------------------------------------------------------------------------
# Invalid profile tests
# ---------------------------------------------------------------------------


def test_invalid_network_mode_rejected(validator):
    """Unknown network mode must fail validation."""
    errors = list(validator.iter_errors({"network": {"mode": "blocked"}}))
    assert errors, "Expected validation error for unknown network mode"
    paths = [list(e.absolute_path) for e in errors]
    assert any("mode" in p for p in paths), f"Error should point to 'mode', got: {paths}"


def test_invalid_permission_mode_rejected(validator):
    """Unknown permission mode must fail validation."""
    errors = list(validator.iter_errors({"tool": {"permission_mode": "auto"}}))
    assert errors, "Expected validation error for unknown permission_mode"


def test_invalid_effort_level_rejected(validator):
    """Unknown effort level must fail validation."""
    errors = list(validator.iter_errors({"tool": {"claude": {"effort_level": "turbo"}}}))
    assert errors, "Expected validation error for unknown effort_level"


def test_invalid_timezone_mode_rejected(validator):
    """Unknown timezone mode must fail validation."""
    errors = list(validator.iter_errors({"timezone": {"mode": "localtime"}}))
    assert errors, "Expected validation error for unknown timezone mode"


def test_invalid_memory_enforce_rejected(validator):
    """Unknown memory enforce value must fail validation."""
    errors = list(validator.iter_errors({"limits": {"memory": {"enforce": "oom-kill"}}}))
    assert errors, "Expected validation error for unknown memory enforce value"


def test_mount_missing_host_rejected(validator):
    """A mount entry without 'host' must fail validation."""
    errors = list(validator.iter_errors({"mounts": [{"container": "/data"}]}))
    assert errors, "Expected validation error for mount missing 'host'"


def test_mount_missing_container_rejected(validator):
    """A mount entry without 'container' must fail validation."""
    errors = list(validator.iter_errors({"mounts": [{"host": "~/data"}]}))
    assert errors, "Expected validation error for mount missing 'container'"


def test_unknown_top_level_key_rejected(validator):
    """Unknown top-level keys must fail validation (additionalProperties: false)."""
    errors = list(validator.iter_errors({"unknown_key": "value"}))
    assert errors, "Expected validation error for unknown top-level key"


def test_unknown_container_key_rejected(validator):
    """Unknown keys inside [container] must fail validation."""
    errors = list(validator.iter_errors({"container": {"typo_key": "oops"}}))
    assert errors, "Expected validation error for unknown key in container"


def test_cpu_priority_out_of_range(validator):
    """CPU priority > 10 must fail validation."""
    errors = list(validator.iter_errors({"limits": {"cpu": {"priority": 11}}}))
    assert errors, "Expected validation error for CPU priority > 10"


def test_wrong_type_for_persistent(validator):
    """container.persistent must be boolean, not string."""
    errors = list(validator.iter_errors({"container": {"persistent": "yes"}}))
    assert errors, "Expected validation error for persistent='yes' (should be boolean)"


def test_wrong_type_for_environment_value(validator):
    """Environment values must be strings, not integers."""
    errors = list(validator.iter_errors({"environment": {"PORT": 8080}}))
    assert errors, "Expected validation error for integer environment value"


# ---------------------------------------------------------------------------
# Edge cases: unknown keys in every nested section
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        {"network": {"typo": "x"}},
        {"limits": {"cpu": {"typo": "x"}}},
        {"limits": {"memory": {"typo": "x"}}},
        {"limits": {"disk": {"typo": "x"}}},
        {"limits": {"runtime": {"typo": "x"}}},
        {"tool": {"typo": "x"}},
        {"tool": {"claude": {"typo": "x"}}},
        {"mounts": [{"host": "~/x", "container": "/x", "typo": True}]},
        {"network": {"logging": {"typo": "x"}}},
        {"paths": {"typo": "x"}},
        {"incus": {"typo": "x"}},
        {"git": {"typo": "x"}},
        {"ssh": {"typo": "x"}},
        {"security": {"typo": "x"}},
        {"monitoring": {"typo": "x"}},
        {"monitoring": {"nft": {"typo": "x"}}},
        {"timezone": {"typo": "x"}},
        {"shell": {"typo": "x"}},
        {"container": {"build": {"typo": "x"}}},
    ],
)
def test_unknown_key_in_nested_section_rejected(validator, profile):
    """Unknown keys inside any nested section must be rejected."""
    errors = list(validator.iter_errors(profile))
    assert errors, f"Expected rejection for unknown key in: {profile}"


# ---------------------------------------------------------------------------
# Edge cases: wrong types for scalar fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        # Strings expected — wrong types supplied
        {"inherits": 123},
        {"context": True},
        {"tool": {"claude": {"model": ["gpt-4"]}}},
        {"container": {"image": 42}},
        {"container": {"storage_pool": False}},
        {"container": {"alias": 0}},
        {"container": {"build": {"base": True}}},
        {"container": {"build": {"script": 99}}},
        {"tool": {"name": False}},
        {"tool": {"binary": 0}},
        {"tool": {"context_file": []}},
        {"network": {"logging": {"path": 1}}},
        {"paths": {"sessions_dir": True}},
        {"paths": {"storage_dir": 0}},
        {"paths": {"logs_dir": False}},
        {"incus": {"project": 1}},
        {"incus": {"group": True}},
        {"incus": {"code_user": []}},
        {"monitoring": {"nft": {"lima_host": 1}}},
        {"timezone": {"name": 42}},
        # Booleans expected — strings/ints supplied
        {"container": {"persistent": "true"}},
        {"container": {"persistent": 1}},
        {"tool": {"auto_context": "yes"}},
        {"tool": {"auto_context": 0}},
        {"paths": {"preserve_workspace_path": "false"}},
        {"git": {"writable_hooks": "no"}},
        {"ssh": {"forward_agent": 1}},
        {"security": {"disable_protection": "true"}},
        {"security": {"host_immutable": "false"}},
        {"monitoring": {"enabled": "yes"}},
        {"monitoring": {"auto_pause_on_high": 1}},
        {"monitoring": {"auto_kill_on_critical": "true"}},
        {"monitoring": {"nft": {"enabled": "true"}}},
        {"monitoring": {"nft": {"log_dns_queries": 0}}},
        {"network": {"block_private_networks": "true"}},
        {"network": {"block_metadata_endpoint": "no"}},
        {"network": {"allow_local_network_access": 1}},
        {"network": {"logging": {"enabled": "yes"}}},
        {"limits": {"runtime": {"auto_stop": "true"}}},
        {"limits": {"runtime": {"stop_graceful": 0}}},
        {"shell": {"use_tmux": "yes"}},
        {"mounts": [{"host": "~/x", "container": "/x", "readonly": "true"}]},
        # Integers expected — strings/booleans supplied
        {"limits": {"cpu": {"priority": "5"}}},
        {"limits": {"cpu": {"priority": True}}},
        {"limits": {"disk": {"priority": "3"}}},
        {"limits": {"runtime": {"max_processes": "100"}}},
        {"limits": {"runtime": {"max_processes": True}}},
        {"monitoring": {"poll_interval_sec": "5"}},
        {"monitoring": {"audit_log_retention_days": "30"}},
        {"monitoring": {"nft": {"rate_limit_per_second": "100"}}},
        {"monitoring": {"nft": {"dns_query_threshold": True}}},
        {"incus": {"code_uid": "1000"}},
        {"network": {"refresh_interval_minutes": "60"}},
        # Arrays expected — wrong types supplied
        {"forward_env": "SOME_VAR"},
        {"forward_env": True},
        # mounts must be an array ([[mounts]]) or a { default = [...] } table
        # ([[mounts.default]]); a scalar is neither. (An empty {} table is a
        # valid "no mounts" nested form, so it is intentionally NOT rejected.)
        {"mounts": "not-a-mount-block"},
        {"network": {"allowed_domains": "github.com"}},
        {"security": {"protected_paths": ".git/hooks"}},
        {"security": {"additional_protected_paths": True}},
        {"container": {"build": {"commands": "apt-get install foo"}}},
        # Object expected — wrong types supplied
        {"environment": ["KEY=VALUE"]},
        {"container": "coi-rust"},
        {"limits": "unlimited"},
        {"tool": "claude"},
        {"network": "open"},
        {"paths": "/home/user/.coi"},
        {"incus": "default"},
        {"git": True},
        {"ssh": 1},
        {"security": "disabled"},
        {"monitoring": False},
        {"timezone": "UTC"},
        {"shell": "bash"},
        {"container": {"build": "build.sh"}},
        {"network": {"logging": True}},
        {"limits": {"cpu": "4"}},
        {"limits": {"memory": "2GiB"}},
        {"limits": {"disk": "fast"}},
        {"limits": {"runtime": "2h"}},
        {"tool": {"claude": "high"}},
        {"monitoring": {"nft": "enabled"}},
    ],
)
def test_wrong_type_rejected(validator, profile):
    """Wrong-type values for any field must fail validation."""
    errors = list(validator.iter_errors(profile))
    assert errors, f"Expected type error for: {profile}"


# ---------------------------------------------------------------------------
# Edge cases: numeric boundary conditions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("priority", [0, 1, 5, 10])
def test_cpu_priority_valid_boundaries(validator, priority):
    """CPU priority must accept values 0-10 inclusive."""
    validator.validate({"limits": {"cpu": {"priority": priority}}})


@pytest.mark.parametrize("priority", [-1, 11, 100, -100])
def test_cpu_priority_invalid_boundaries(validator, priority):
    """CPU priority outside 0-10 must be rejected."""
    errors = list(validator.iter_errors({"limits": {"cpu": {"priority": priority}}}))
    assert errors, f"Expected rejection for cpu.priority={priority}"


@pytest.mark.parametrize("priority", [0, 1, 5, 10])
def test_disk_priority_valid_boundaries(validator, priority):
    """Disk priority must accept values 0-10 inclusive."""
    validator.validate({"limits": {"disk": {"priority": priority}}})


@pytest.mark.parametrize("priority", [-1, 11])
def test_disk_priority_invalid_boundaries(validator, priority):
    """Disk priority outside 0-10 must be rejected."""
    errors = list(validator.iter_errors({"limits": {"disk": {"priority": priority}}}))
    assert errors, f"Expected rejection for disk.priority={priority}"


@pytest.mark.parametrize("count", [0, 1, 999])
def test_max_processes_valid_values(validator, count):
    """max_processes must accept 0 (unlimited) and any positive integer."""
    validator.validate({"limits": {"runtime": {"max_processes": count}}})


def test_max_processes_negative_rejected(validator):
    """max_processes must reject negative values."""
    errors = list(validator.iter_errors({"limits": {"runtime": {"max_processes": -1}}}))
    assert errors, "Expected rejection for negative max_processes"


@pytest.mark.parametrize(
    "field,value",
    [
        ("poll_interval_sec", 0),
        ("poll_interval_sec", 1),
        ("file_read_threshold_mb", 0.0),
        ("file_read_threshold_mb", 0.001),
        ("file_read_rate_mb_per_sec", 0.0),
        ("audit_log_retention_days", 0),
        ("audit_log_retention_days", 365),
    ],
)
def test_monitoring_numeric_valid(validator, field, value):
    """Non-negative monitoring numeric fields must accept 0 and positive values."""
    validator.validate({"monitoring": {field: value}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("poll_interval_sec", -1),
        ("file_read_threshold_mb", -0.1),
        ("file_read_rate_mb_per_sec", -1.0),
        ("audit_log_retention_days", -1),
    ],
)
def test_monitoring_numeric_negative_rejected(validator, field, value):
    """Negative monitoring numeric values must be rejected."""
    errors = list(validator.iter_errors({"monitoring": {field: value}}))
    assert errors, f"Expected rejection for monitoring.{field}={value}"


@pytest.mark.parametrize("value", [0, 1, 100])
def test_nft_rate_limit_valid(validator, value):
    validator.validate({"monitoring": {"nft": {"rate_limit_per_second": value}}})


def test_nft_rate_limit_negative_rejected(validator):
    errors = list(validator.iter_errors({"monitoring": {"nft": {"rate_limit_per_second": -1}}}))
    assert errors, "Expected rejection for negative nft.rate_limit_per_second"


@pytest.mark.parametrize("value", [0, 1, 1000])
def test_refresh_interval_valid(validator, value):
    validator.validate({"network": {"refresh_interval_minutes": value}})


def test_refresh_interval_negative_rejected(validator):
    errors = list(validator.iter_errors({"network": {"refresh_interval_minutes": -1}}))
    assert errors, "Expected rejection for negative refresh_interval_minutes"


# ---------------------------------------------------------------------------
# Edge cases: mount entry specifics
# ---------------------------------------------------------------------------


def test_mount_empty_host_rejected(validator):
    """Mount host must not be an empty string (minLength: 1)."""
    errors = list(validator.iter_errors({"mounts": [{"host": "", "container": "/data"}]}))
    assert errors, "Expected rejection for empty mount host"


def test_mount_empty_container_rejected(validator):
    """Mount container path must not be an empty string (minLength: 1)."""
    errors = list(validator.iter_errors({"mounts": [{"host": "~/data", "container": ""}]}))
    assert errors, "Expected rejection for empty mount container path"


def test_mount_both_paths_empty_rejected(validator):
    """Both host and container empty must be rejected."""
    errors = list(validator.iter_errors({"mounts": [{"host": "", "container": ""}]}))
    assert errors, "Expected rejection for mount with both paths empty"


def test_mount_no_fields_at_all_rejected(validator):
    """A mount entry with no fields at all must be rejected (host+container required)."""
    errors = list(validator.iter_errors({"mounts": [{}]}))
    assert errors, "Expected rejection for completely empty mount entry"


def test_mount_only_readonly_rejected(validator):
    """A mount entry with only readonly set must be rejected (host+container required)."""
    errors = list(validator.iter_errors({"mounts": [{"readonly": True}]}))
    assert errors, "Expected rejection for mount with only readonly"


def test_mounts_non_array_rejected(validator):
    """mounts must be an array, not an object or string."""
    for bad in [{"host": "~/x", "container": "/x"}, "~/x:/x", 42]:
        errors = list(validator.iter_errors({"mounts": bad}))
        assert errors, f"Expected rejection for mounts={bad!r}"


def test_multiple_mounts_one_invalid(validator):
    """A list of mounts where one entry is invalid must fail validation."""
    errors = list(
        validator.iter_errors(
            {
                "mounts": [
                    {"host": "~/.cargo", "container": "/home/code/.cargo"},
                    {"container": "/data"},  # missing host
                ]
            }
        )
    )
    assert errors, "Expected rejection when one mount is missing host"


# ---------------------------------------------------------------------------
# Edge cases: array item type errors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad_items",
    [
        ("forward_env", [1, 2, 3]),
        ("forward_env", [True, "VAR"]),
        ("forward_env", [None]),
        ("network.allowed_domains", [1, "example.com"]),
        ("network.allowed_domains", [None]),
        ("security.protected_paths", [True]),
        ("security.protected_paths", [42]),
        ("security.additional_protected_paths", [{}]),
        ("container.build.commands", [1, 2]),
        ("container.build.commands", [None, "apt install"]),
    ],
)
def test_array_item_wrong_type_rejected(validator, field, bad_items):
    """Non-string items in string-array fields must be rejected."""
    parts = field.split(".")
    profile: dict = {}
    node = profile
    for part in parts[:-1]:
        node[part] = {}
        node = node[part]
    node[parts[-1]] = bad_items
    errors = list(validator.iter_errors(profile))
    assert errors, f"Expected rejection for {field}={bad_items!r}"


# ---------------------------------------------------------------------------
# Edge cases: null values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        {"inherits": None},
        {"tool": {"claude": {"model": None}}},
        {"context": None},
        {"container": None},
        {"limits": None},
        {"tool": None},
        {"network": None},
        {"mounts": None},
        {"environment": None},
        {"forward_env": None},
        {"git": None},
        {"ssh": None},
        {"security": None},
        {"monitoring": None},
        {"timezone": None},
        {"shell": None},
        {"container": {"image": None}},
        {"container": {"persistent": None}},
        {"network": {"mode": None}},
        {"tool": {"permission_mode": None}},
        {"tool": {"claude": {"effort_level": None}}},
        {"timezone": {"mode": None}},
        {"limits": {"memory": {"enforce": None}}},
    ],
)
def test_null_values_rejected(validator, profile):
    """Null values must be rejected for typed fields."""
    errors = list(validator.iter_errors(profile))
    assert errors, f"Expected rejection for null value in: {profile}"


# ---------------------------------------------------------------------------
# Edge cases: empty collections are valid
# ---------------------------------------------------------------------------


def test_empty_forward_env_valid(validator):
    validator.validate({"forward_env": []})


def test_empty_mounts_valid(validator):
    validator.validate({"mounts": []})


def test_empty_allowed_domains_valid(validator):
    validator.validate({"network": {"allowed_domains": []}})


def test_empty_protected_paths_valid(validator):
    validator.validate({"security": {"protected_paths": []}})


def test_empty_additional_protected_paths_valid(validator):
    validator.validate({"security": {"additional_protected_paths": []}})


def test_empty_build_commands_valid(validator):
    validator.validate({"container": {"build": {"commands": []}}})


def test_empty_environment_valid(validator):
    validator.validate({"environment": {}})


# ---------------------------------------------------------------------------
# Edge cases: enum boundary — empty string is allowed where specified
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        {"network": {"mode": ""}},
        {"tool": {"permission_mode": ""}},
        {"tool": {"claude": {"effort_level": ""}}},
        {"timezone": {"mode": ""}},
        {"limits": {"memory": {"enforce": ""}}},
    ],
)
def test_empty_string_enum_valid(validator, profile):
    """Empty string must be accepted for enum fields that list '' as a valid value."""
    validator.validate(profile)


# ---------------------------------------------------------------------------
# Edge cases: error path precision
# ---------------------------------------------------------------------------


def test_error_path_points_to_invalid_network_mode(validator):
    """Validation error for an invalid network mode must reference network→mode."""
    errors = list(validator.iter_errors({"network": {"mode": "deny-all"}}))
    assert errors
    paths = [list(e.absolute_path) for e in errors]
    assert any(p == ["network", "mode"] for p in paths), (
        f"Expected path ['network', 'mode'], got: {paths}"
    )


def test_error_path_points_to_invalid_effort_level(validator):
    """Validation error for an invalid effort level must reference tool→claude→effort_level."""
    errors = list(validator.iter_errors({"tool": {"claude": {"effort_level": "extreme"}}}))
    assert errors
    paths = [list(e.absolute_path) for e in errors]
    assert any(p == ["tool", "claude", "effort_level"] for p in paths), (
        f"Expected path ['tool', 'claude', 'effort_level'], got: {paths}"
    )


def test_error_path_points_to_invalid_mount_host(validator):
    """Missing required 'host' in the second mount must reference mounts[1]."""
    errors = list(
        validator.iter_errors(
            {
                "mounts": [
                    {"host": "~/valid", "container": "/valid"},
                    {"container": "/no-host"},
                ]
            }
        )
    )
    assert errors
    # At least one error must reference index 1 in the mounts array
    paths = [list(e.absolute_path) for e in errors]
    assert any(len(p) >= 2 and p[0] == "mounts" and p[1] == 1 for p in paths), (
        f"Expected error at mounts[1], got paths: {paths}"
    )


def test_error_path_points_to_wrong_type_in_environment(validator):
    """Type error for an environment value must reference the specific key."""
    errors = list(validator.iter_errors({"environment": {"PORT": 8080}}))
    assert errors
    paths = [list(e.absolute_path) for e in errors]
    assert any("PORT" in p for p in paths), f"Expected error path containing 'PORT', got: {paths}"


def test_multiple_errors_reported(validator):
    """A profile with multiple violations must report all of them."""
    errors = list(
        validator.iter_errors(
            {
                "network": {"mode": "bad-mode"},
                "tool": {"permission_mode": "unknown"},
                "limits": {"cpu": {"priority": 99}},
            }
        )
    )
    assert len(errors) >= 3, f"Expected at least 3 errors, got {len(errors)}: {errors}"


# ---------------------------------------------------------------------------
# Schema command output stability tests
# ---------------------------------------------------------------------------


def test_schema_command_output_is_deterministic(coi_binary):
    """Running `coi schema profile` twice must produce identical output."""
    runs = []
    for _ in range(2):
        result = subprocess.run(
            [coi_binary, "schema", "profile"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        runs.append(result.stdout)
    assert runs[0] == runs[1], "Schema output is not deterministic"


def test_schema_command_exits_zero_without_config(tmp_path, coi_binary):
    """schema profile must work even when there is no Coi config in the workspace."""
    result = subprocess.run(
        [coi_binary, "schema", "profile", "--workspace", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(tmp_path),
    )
    assert result.returncode == 0, (
        f"Expected exit 0 in empty workspace, got {result.returncode}:\n{result.stderr}"
    )
    json.loads(result.stdout)
