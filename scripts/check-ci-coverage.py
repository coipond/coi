#!/usr/bin/env python3
"""
Verify that every test directory and standalone test file under tests/ is
referenced by at least one group in the CI integration matrix.

Run: python3 scripts/check-ci-coverage.py
Exit 0 = all covered. Exit 1 = uncovered paths found.
"""
import re
import sys
import yaml
from pathlib import Path

# Files/dirs that intentionally live under tests/ but are not test groups.
NOT_TEST_ENTRIES = {
    "conftest.py",  # pytest fixtures shared across groups
    "support",      # helper modules (helpers.py etc.)
    "__pycache__",
}


def check_pytest_k_filters(ci: dict, repo: Path) -> list[str]:
    """Verify `-k` class filters against the classes actually in the file.

    A lane can narrow a big test file to a subset of classes via
    `pytest_args: -k 'ClassA or ClassB'` (sharding one file across several
    lanes; prefer a directory per lane). The failure mode is silent
    DRIFT: rename/add a class and a lane's `-k` still "passes" while that class
    never runs in CI, or a `-k` names a class that no longer exists (dead
    reference). For every single-file lane path that carries a `-k`, this
    checks BOTH directions:
      - every `Test*` class declared in the file is named by some lane's `-k`
        (nothing falls out of CI), and
      - every class token in a `-k` matches a real class (no dead reference).
    """
    errors: list[str] = []
    groups = ci["jobs"]["integration"]["strategy"]["matrix"]["test_group"]

    # file path -> union of class tokens across every lane that runs it with -k
    filtered: dict[str, set[str]] = {}
    for group in groups:
        args = group.get("pytest_args", "")
        # Match either quote style: -k 'A or B' or -k "A or B".
        m = re.search(r"-k\s+(['\"])(.*?)\1", args)
        if not m:
            continue
        expr = m.group(2).strip()
        # The guard models pytest's simple "A or B or C" filters (all the CI
        # matrix uses). Refuse to guess on and/not/parentheses rather than
        # silently misclassify tokens — a clear error beats a wrong answer.
        if re.search(r"\band\b|\bnot\b|[()]", expr):
            errors.append(
                f"pytest_args {args!r}: the -k drift guard only supports 'A or B or C' "
                "filters; and/not/parentheses are not modeled. Keep monitoring filters simple."
            )
            continue
        tokens = {t for t in re.split(r"\s+or\s+", expr) if t}
        py_paths = [p for p in group.get("path", "").split() if p.endswith(".py")]
        if not py_paths:
            # A -k on a directory lane applies to every file collected under it;
            # this guard only validates single-file lanes. Surface it instead of
            # silently skipping (which would disable the check).
            errors.append(
                f"pytest_args {args!r}: a -k filter on a non-single-file lane "
                f"(path={group.get('path', '')!r}) is not validated by this guard."
            )
            continue
        for path in py_paths:
            filtered.setdefault(path, set()).update(tokens)

    for path, referenced in sorted(filtered.items()):
        f = repo / path
        if not f.exists():
            errors.append(f"{path}: referenced by a -k lane but the file does not exist")
            continue
        declared = set(re.findall(r"^class (Test\w+)", f.read_text(), re.MULTILINE))
        # pytest -k matches a token as a SUBSTRING of the node id (which contains
        # the class name), so token "TestFoo" also selects "TestFooExtended".
        # Model that instead of exact-set equality, or valid substring filters
        # would be falsely flagged.
        missing = {c for c in declared if not any(tok in c for tok in referenced)}
        dead = {tok for tok in referenced if not any(tok in c for c in declared)}
        for c in sorted(missing):
            errors.append(f"{path}: class {c} is not selected by any lane's -k filter (it never runs in CI)")
        for c in sorted(dead):
            errors.append(f"{path}: -k filter references {c}, which does not exist in the file (dead reference)")
    return errors


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    ci_file = repo / ".github" / "workflows" / "ci.yml"
    tests_dir = repo / "tests"

    with open(ci_file) as f:
        ci = yaml.safe_load(f)

    # Collect every path token from every group's `path:` field.
    covered: set[str] = set()
    for group in ci["jobs"]["integration"]["strategy"]["matrix"]["test_group"]:
        path_field = group.get("path", "")
        for token in path_field.split():
            covered.add(token)

    uncovered: list[str] = []

    for item in sorted(tests_dir.iterdir()):
        if item.name in NOT_TEST_ENTRIES or item.name.startswith("_"):
            continue

        if item.is_dir():
            # Only flag directories that actually contain .py files.
            if not any(item.rglob("*.py")):
                continue
            rel = f"tests/{item.name}"
        elif item.suffix == ".py":
            rel = f"tests/{item.name}"
        else:
            continue

        # Covered if: exact match, rel is a sub-path of a covered token,
        # or a covered token is a sub-path of rel (e.g. tests/shell covered
        # via tests/shell/ephemeral and tests/shell/persistent).
        is_covered = any(
            rel == p
            or rel.startswith(p.rstrip("/") + "/")
            or p.startswith(rel.rstrip("/") + "/")
            for p in covered
        )
        if not is_covered:
            uncovered.append(rel)

    # Every test file must be selected by some lane, not just its top-level
    # directory: a lane can point at a subdirectory (tests/shell/ephemeral,
    # tests/security_monitoring/threats), and a new sibling directory would
    # otherwise never run.
    for f in sorted(tests_dir.rglob("*.py")):
        rel_parts = f.relative_to(tests_dir).parts
        if f.name == "conftest.py" or any(p in NOT_TEST_ENTRIES or p.startswith("_") for p in rel_parts):
            continue
        rel = f"tests/{'/'.join(rel_parts)}"
        if rel in uncovered or any(rel.startswith(u + "/") for u in uncovered):
            continue
        if not any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in covered):
            uncovered.append(rel)

    if uncovered:
        print("ERROR: the following test paths are not assigned to any CI group:")
        for p in uncovered:
            print(f"  {p}")
        print()
        print("Add them to a group in .github/workflows/ci.yml under")
        print("jobs.integration.strategy.matrix.test_group[*].path")
        return 1

    k_errors = check_pytest_k_filters(ci, repo)
    if k_errors:
        print("ERROR: pytest -k class-filter drift in the CI matrix:")
        for e in k_errors:
            print(f"  {e}")
        print()
        print("Update the lane's pytest_args -k filter in .github/workflows/ci.yml so the")
        print("union of selected classes matches the Test* classes declared in the file.")
        return 1

    print(f"OK: all test paths are covered ({len(covered)} path entries across CI groups)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
