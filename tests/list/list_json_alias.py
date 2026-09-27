"""Test that the --json shorthand on coi list matches --format=json.

The 0.12 release added --json as an alias for --format json on every command
that supports formats; the alias itself had no coverage on `coi list`. Runs
against whatever container state exists (works on an empty host too, like
list_format_json_empty.py).
"""

import json
import subprocess


def _list(coi_binary, *args):
    result = subprocess.run(
        [coi_binary, "list", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"coi list {args} failed: {result.stderr}"
    return json.loads(result.stdout)


def test_list_json_alias_matches_format_json(coi_binary):
    """--json must produce the same JSON document shape as --format=json."""
    alias = _list(coi_binary, "--json")
    explicit = _list(coi_binary, "--format=json")

    assert isinstance(alias, dict), f"--json should emit a JSON object, got {type(alias)}"
    assert "active_containers" in alias, f"missing active_containers: {list(alias)}"
    assert set(alias.keys()) == set(explicit.keys()), (
        f"--json and --format=json disagree on top-level keys: "
        f"{sorted(alias)} vs {sorted(explicit)}"
    )
