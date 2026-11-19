"""Shared helpers for the hermetic build.sh tests (tests/build)."""

import re
from pathlib import Path

BUILD_SH = Path(__file__).resolve().parents[2] / "profiles" / "default" / "build.sh"


def build_sh_var(name):
    """The value of the one top-level `NAME="value"` line in build.sh."""
    values = re.findall(rf'^{name}="([^"]+)"', BUILD_SH.read_text(), re.MULTILINE)
    assert len(values) == 1, f"expected one {name}, got {values}"
    return values[0]
