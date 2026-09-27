"""Test that the --json shorthand on coi list emits the JSON document at runtime.

Help-level alias recognition across commands (including list) is covered by
tests/cli/test_json_alias.py; this pins the runtime half for `coi list`. A
comparison against --format=json would be vacuous here: without --all the
document always has exactly one top-level key (saved_sessions is emitted only
when sessions exist), so a single invocation asserting the real shape is the
honest invariant. Works on an empty host, like list_format_json_empty.py.
"""

import json
import subprocess


def test_list_json_alias_emits_json_document(coi_binary):
    """--json must produce the list JSON document (alias routes at runtime)."""
    result = subprocess.run(
        [coi_binary, "list", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"coi list --json failed: {result.stderr}"

    data = json.loads(result.stdout)
    assert isinstance(data, dict), f"--json should emit a JSON object, got {type(data)}"
    assert "active_containers" in data, f"missing active_containers: {list(data)}"
    assert isinstance(data["active_containers"], list), "active_containers should be a list"
