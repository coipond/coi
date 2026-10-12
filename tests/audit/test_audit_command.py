"""
`coi audit` had zero integration coverage (#559 A6).

The command streams threat-event audit records as JSON lines. `--file <path>`
reads an arbitrary JSONL file and re-emits each parsed event — a host-only path
(no container, no monitoring), which makes it the cheapest honest way to exercise
the command's real render pipeline (audit.HostAuditTail -> StreamEvents/ParseLine).
"""

import json
import subprocess

# A valid audit event line (ParseLine requires a known `type`).
EVENT = '{"ts":"2026-01-01T00:00:00Z","type":"audit","msg":"AUDIT-SENTINEL-7f3a"}'


def _audit(coi_binary, *args):
    return subprocess.run(
        [coi_binary, "audit", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_audit_file_streams_events_as_valid_jsonl(coi_binary, tmp_path):
    """`coi audit --file <jsonl>` re-emits each event; output is valid JSON lines."""
    log = tmp_path / "session.jsonl"
    log.write_text(EVENT + "\n")

    r = _audit(coi_binary, "--file", str(log))
    assert r.returncode == 0, f"coi audit --file should succeed. stderr:\n{r.stderr}"
    assert "AUDIT-SENTINEL-7f3a" in r.stdout, (
        f"the event must be echoed on stdout.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    # Every non-empty stdout line must be a valid JSON object carrying `type`.
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, "expected at least one JSON line on stdout"
    for ln in lines:
        obj = json.loads(ln)  # raises if the output is not valid JSONL
        assert "type" in obj, f"event missing 'type': {ln}"


def test_audit_file_empty_is_clean(coi_binary, tmp_path):
    """An empty audit file streams nothing and exits 0 (not an error)."""
    log = tmp_path / "empty.jsonl"
    log.write_text("")

    r = _audit(coi_binary, "--file", str(log))
    assert r.returncode == 0, f"empty --file should exit 0. stderr:\n{r.stderr}"
    assert r.stdout.strip() == "", f"empty file should produce no events, got:\n{r.stdout}"


def test_audit_file_nonexistent_errors(coi_binary, tmp_path):
    """A missing --file path fails with a clear error, not a silent success."""
    r = _audit(coi_binary, "--file", str(tmp_path / "does-not-exist.jsonl"))
    assert r.returncode != 0, "a nonexistent --file must fail"
    assert "audit log" in (r.stdout + r.stderr).lower(), (
        f"expected an 'open audit log' error.\n{r.stdout}\n{r.stderr}"
    )


def test_audit_file_passes_monitor_threat_events_through(coi_binary, tmp_path):
    """The monitor's own records (threat events, snapshots) have no `type` field;
    `coi audit` must still print them (it used to drop them silently, so a dump
    of ~/.coi/audit/<container>.jsonl printed nothing)."""
    threat = (
        '{"id":"t-1","timestamp":"2026-01-01T00:00:00Z","level":"critical",'
        '"category":"network","title":"MONITOR-SENTINEL-4c1d","description":"",'
        '"evidence":{},"action":"killed"}'
    )
    log = tmp_path / "coi-x.jsonl"
    log.write_text(threat + "\n" + EVENT + "\n")

    r = _audit(coi_binary, "--file", str(log))
    assert r.returncode == 0, f"coi audit --file should succeed. stderr:\n{r.stderr}"
    lines = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    assert any(obj.get("title") == "MONITOR-SENTINEL-4c1d" for obj in lines), (
        f"the monitor threat event must be printed.\nstdout:\n{r.stdout}"
    )
    assert any(obj.get("msg") == "AUDIT-SENTINEL-7f3a" for obj in lines)
