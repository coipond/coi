"""
Interactive-prompt tests for install.sh (P1 coverage).

install.sh asks several yes/no questions in one run (install Incus, add to the
incus-admin group, install nftables, configure passwordless nft sudo, install
git, ...). A real regression shipped here: the prompts used single-character
reads, so typing a multi-character answer like "YES" left "ES" in the tty
buffer, which the NEXT prompt consumed as a stray answer — silently declining
it (the user typed YES to the nft-sudo prompt, yet it was skipped).

Nothing in the suite exercised the interactive prompt path — the install-flow
CI lane runs non-interactively (COI_ASSUME_YES=1). These tests drive the actual
prompt functions through a pty (pexpect) and assert every answer is honored and
that no prompt cross-contaminates the next one.

The functions are sourced from the real install.sh with its `main` entrypoint
and ERR trap stripped (the same idiom the Go install_sh_test.go harness uses),
so no Incus/network/root is needed — pure prompt-parsing behavior.
"""

import os
import tempfile

import pexpect
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INSTALL_SH = os.path.join(REPO_ROOT, "install.sh")


def _driver(num_prompts):
    """A bash script that sources install.sh's functions and runs `num_prompts`
    back-to-back user_agrees prompts, echoing R<n>=YES/NO after each."""
    lines = [
        "set +e",
        # Source only the definitions (drop the `main \"$@\"` entrypoint + ERR trap).
        f"source <(sed '/^main \"$@\"/d; /^trap error_handler ERR/d' {INSTALL_SH})",
        # We are under a pty, so /dev/tty is usable; force interactive regardless.
        "NONINTERACTIVE=0",
    ]
    for i in range(1, num_prompts + 1):
        lines.append(f'if user_agrees "Q{i}: "; then echo "R{i}=YES"; else echo "R{i}=NO"; fi')
    lines.append('echo "DONE"')
    return "\n".join(lines)


def _run(answers):
    """Spawn the driver under a pty, send one line per prompt, and return the
    dict of parsed results {1: 'YES'|'NO', ...}."""
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(_driver(len(answers)))
        path = fh.name
    try:
        child = pexpect.spawn("bash", [path], encoding="utf-8", timeout=20)
        results = {}
        for i, ans in enumerate(answers, start=1):
            child.expect(rf"Q{i}: ")
            child.sendline(ans)
            child.expect(rf"R{i}=(YES|NO)")
            results[i] = child.match.group(1)
        child.expect("DONE")
        child.expect(pexpect.EOF)
        return results
    finally:
        os.unlink(path)


@pytest.mark.skipif(not os.path.exists(INSTALL_SH), reason="install.sh not found")
def test_multichar_yes_does_not_corrupt_next_prompt():
    """The regression: typing "YES" to prompt 1 must be honored AND must not
    bleed into prompt 2. With the old single-char read, prompt 2 would read the
    leftover "ES" and answer itself before the user could — so "YES" to Q2 here
    would come back NO. Line-based reads keep them independent."""
    results = _run(["YES", "YES", "n"])
    assert results == {1: "YES", 2: "YES", 3: "NO"}, results


@pytest.mark.skipif(not os.path.exists(INSTALL_SH), reason="install.sh not found")
def test_yes_variants_are_accepted():
    """y / Y / yes / YES / Yes all mean yes; a bare Enter defaults to yes."""
    results = _run(["y", "Y", "yes", "YES", "Yes", ""])
    assert all(v == "YES" for v in results.values()), results


@pytest.mark.skipif(not os.path.exists(INSTALL_SH), reason="install.sh not found")
def test_no_variants_are_declined():
    """n / N / no / anything-not-yes declines."""
    results = _run(["n", "N", "no", "nope", "maybe"])
    assert all(v == "NO" for v in results.values()), results
