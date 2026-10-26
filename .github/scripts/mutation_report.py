"""Turn a finished `mutmut run` into a report a reviewer can act on without rerunning it.

`mutmut results` lists survivor names and `mutmut show` prints one diff per process
start, about two seconds each; hundreds of survivors would take longer than the run.
This reads the same state in one process and writes:

    mutation-report/summary.json   counts, score, per-file breakdown
    mutation-report/survivors.md   every non-killed mutant with its diff, by file and function

It imports mutmut internals, so it is tied to the version pinned in the workflow.
Run from the repository root after `mutmut run`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from mutmut.mutation.data import SourceFileMutationData
from mutmut.mutation.diff_apply import get_diff_for_mutant
from mutmut.stats import status_by_exit_code
from mutmut.utils.file_utils import walk_mutatable_files

OUT = Path("mutation-report")

# Statuses that mean the tests did not catch the change. Timeouts and suspicious
# results are listed too: they are not proof of a gap, but each needs a look.
REPORTED = ("survived", "no tests", "timeout", "suspicious", "segfault")


def _function_of(mutant: str) -> str:
    # secretscreen._config.x_merge__mutmut_5 -> merge ; class methods: xǁClassǁmethod__mutmut_3
    name = mutant.rpartition(".")[-1].rpartition("__mutmut_")[0]
    return name.removeprefix("x_").removeprefix("x").replace("ǁ", ".").strip(".")


def main() -> int:
    totals: Counter[str] = Counter()
    per_file: dict[str, Counter[str]] = {}
    found: dict[str, dict[str, list[tuple[str, str, str]]]] = defaultdict(lambda: defaultdict(list))

    for path in walk_mutatable_files():
        data = SourceFileMutationData(path=path)
        data.load()
        if not data.exit_code_by_key:
            continue
        counts: Counter[str] = Counter()
        for mutant, code in sorted(data.exit_code_by_key.items()):
            status = status_by_exit_code[code]
            counts[status] += 1
            if status in REPORTED:
                found[str(path)][_function_of(mutant)].append((mutant, status, get_diff_for_mutant(mutant, path=path)))
        per_file[str(path)] = counts
        totals.update(counts)

    if not per_file:
        print("no mutation results found; run `mutmut run` first", file=sys.stderr)
        return 1

    not_checked = totals["not checked"]
    if not_checked:
        print(f"{not_checked} mutants were never checked; the run did not finish", file=sys.stderr)
        return 1

    total = sum(totals.values())
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    summary = {
        "commit": commit,
        "run_url": os.environ.get("RUN_URL", ""),
        "total": total,
        "statuses": dict(totals),
        "score": round(100 * totals["killed"] / total, 1),
        "files": {
            p: {"total": sum(c.values()), "survived": c["survived"], "statuses": dict(c)} for p, c in per_file.items()
        },
    }

    OUT.mkdir(exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    lines = [
        f"# Mutation survivors at {commit[:12]}",
        "",
        f"Score {summary['score']}% — {totals['killed']} killed of {total}. "
        + ", ".join(f"{s}: {totals[s]}" for s in REPORTED if totals[s]),
        "",
        "| File | Mutants | Survived | Other unkilled |",
        "|---|---:|---:|---:|",
    ]
    for p, c in sorted(per_file.items(), key=lambda kv: -kv[1]["survived"]):
        other = sum(c[s] for s in REPORTED if s != "survived")
        lines.append(f"| `{p}` | {sum(c.values())} | {c['survived']} | {other} |")
    for p in sorted(found, key=lambda f: -sum(len(v) for v in found[f].values())):
        lines += ["", f"## `{p}`"]
        for func in sorted(found[p], key=lambda fn: -len(found[p][fn])):
            lines += ["", f"### `{func}` — {len(found[p][func])}"]
            for mutant, status, diff in found[p][func]:
                lines += ["", f"`{mutant}` ({status})", "", "```diff", diff.rstrip(), "```"]
    (OUT / "survivors.md").write_text("\n".join(lines) + "\n")

    print(f"score {summary['score']}%: {totals['killed']}/{total} killed, {totals['survived']} survived")
    return 0


if __name__ == "__main__":
    sys.exit(main())
