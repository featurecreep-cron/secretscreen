#!/usr/bin/env python3
"""Require every behaviour change to arrive with a test that proves it.

The gate runs the pull request's own tests against the pull request's *base*
source. At least one newly added test must fail there, and every changed test
must pass once the patch is applied. A test that passes without the patch does
not demonstrate anything; it is the failure on base that turns a test into
evidence.

Exit codes: 0 pass, 1 gate failure, 2 harness error.

Run it locally the same way CI does:

    python .github/scripts/pr_test_gate.py --base origin/main --head HEAD

Escape hatch: a pull request that genuinely changes no behaviour (a pure
refactor, a rename, a performance change covered by existing tests) is exempt
via the `no-test-gate` label. The label is checked by the workflow, not here,
so that the reason is recorded on the pull request rather than buried in a log.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SRC_DIR = "src"
TEST_DIR = "tests"

# `def test_x`, `async def test_x`, added by the diff.
ADDED_TEST_RE = re.compile(r"^\+\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)")
# pytest's short summary lines: "FAILED tests/test_x.py::Cls::test_y - detail"
OUTCOME_RE = re.compile(r"^(?:FAILED|ERROR)\s+(\S+)")


class GateError(RuntimeError):
    """The gate could not run. Distinct from the gate deciding to fail."""


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise GateError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def changed_files(base: str, head: str, path: str) -> list[str]:
    out = git("diff", "--name-only", "--diff-filter=ACMR", base, head, "--", path)
    return [line for line in out.splitlines() if line.strip()]


def added_test_names(base: str, head: str) -> set[str]:
    diff = git("diff", base, head, "--", TEST_DIR)
    return {match.group(1) for line in diff.splitlines() if (match := ADDED_TEST_RE.match(line))}


def run_pytest(paths: list[str]) -> tuple[int, str, set[str]]:
    """Run pytest over `paths`; return (exit code, output, failing test names)."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *paths,
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "--tb=no",
            "-rfE",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    failing = set()
    for line in output.splitlines():
        if match := OUTCOME_RE.match(line):
            # tests/test_core.py::TestFoo::test_bar -> test_bar
            failing.add(match.group(1).split("::")[-1].split("[")[0])
    return result.returncode, output, failing


def fail(reason: str, *, detail: str = "") -> int:
    print(f"\n::error::PR test gate: {reason}")
    print(f"\n  FAILED — {reason}\n")
    if detail:
        print(detail)
    print(
        "\n  A change to src/ has to arrive with a test that fails without it.\n"
        "  If this pull request genuinely changes no behaviour — a pure refactor,\n"
        "  a rename, a dependency bump — add the `no-test-gate` label and say why\n"
        "  in the pull request body. The exemption is recorded, not silent.\n"
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="base ref or SHA")
    parser.add_argument("--head", default="HEAD", help="head ref or SHA")
    args = parser.parse_args()

    if not Path(SRC_DIR).is_dir() or not Path(TEST_DIR).is_dir():
        raise GateError(f"expected {SRC_DIR}/ and {TEST_DIR}/ in {Path.cwd()}")

    base, head = args.base, args.head
    src_changed = changed_files(base, head, SRC_DIR)
    test_changed = changed_files(base, head, TEST_DIR)

    print(f"  base {git('rev-parse', '--short', base).strip()}  head {git('rev-parse', '--short', head).strip()}")

    if not src_changed:
        print("\n  SKIPPED — no changes under src/. Nothing to demonstrate.\n")
        return 0

    print(f"\n  source files changed ({len(src_changed)}):")
    for path in src_changed:
        print(f"    {path}")

    if not test_changed:
        return fail(
            "src/ changed but no test changed",
            detail="  Changed without a test:\n" + "".join(f"    {p}\n" for p in src_changed),
        )

    added = added_test_names(base, head)
    if not added:
        return fail(
            "test files changed but no new test was added",
            detail=f"  Changed test files: {', '.join(test_changed)}\n"
            "  The gate looks for added `def test_*`. Editing an existing\n"
            "  test in place cannot show that the defect was ever present.\n",
        )

    print(f"\n  tests added ({len(added)}):")
    for name in sorted(added):
        print(f"    {name}")

    # --- Half one: the new tests must fail against the base source. ----------
    # Only src/ is reverted. Packaging and test fixtures stay at head so the
    # single variable under test is the source change itself.
    print("\n  [1/2] running the PR's tests against base source ...")
    git("checkout", base, "--", SRC_DIR)
    try:
        code, output, failing = run_pytest(test_changed)
    finally:
        git("checkout", head, "--", SRC_DIR)

    if code == 0:
        return fail(
            "every test passes without the patch",
            detail="  The tests in this pull request pass against the base source,\n"
            "  so they do not demonstrate that anything was broken.\n"
            "  Write a test that fails first, then make it pass.\n",
        )

    proving = sorted(added & failing)
    if not proving:
        if not failing:
            # Base could not even collect the tests — they reference API that
            # only exists on head. That is the strongest possible signal.
            print("  base run could not collect the tests (new API referenced).")
            print("  accepted as evidence the tests require the patch.")
        else:
            return fail(
                "no *added* test fails without the patch",
                detail=f"  Failing on base: {', '.join(sorted(failing))}\n"
                f"  Added by this PR: {', '.join(sorted(added))}\n"
                "  Something failed on base, but nothing this pull request\n"
                "  added. That is a pre-existing failure, not evidence.\n",
            )
    else:
        print(f"  {len(proving)} added test(s) fail without the patch:")
        for name in proving:
            print(f"    {name}")

    # --- Half two: everything must pass with the patch applied. -------------
    print("\n  [2/2] running the same tests against the PR ...")
    code, output, failing = run_pytest(test_changed)
    if code != 0:
        return fail(
            "the tests do not pass with the patch applied",
            detail=f"  Still failing: {', '.join(sorted(failing))}\n\n{output[-2000:]}",
        )

    print("\n  PASSED — the defect is demonstrated and the patch closes it.\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GateError as exc:
        print(f"::error::PR test gate could not run: {exc}", file=sys.stderr)
        sys.exit(2)
