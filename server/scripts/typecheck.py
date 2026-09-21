#!/usr/bin/env python3
"""Run mypy and fail only on NEW type errors.

`strict = true` sat in `pyproject.toml` for the life of the project, was never
run in CI, and produced 532 errors. A gate nobody runs is not a gate — but
turning it on as a hard pass/fail would have meant either a green build that
ignores 80 real complaints or a red build nobody can fix today.

This is the ratchet instead. The committed baseline records how many errors each
file currently has. A change that adds an error to a file fails; a change that
removes one is expected to lower the baseline (`--update`), which makes the
number monotonically decrease. New files start at zero, so nothing written from
here on is allowed to add debt.

    python scripts/typecheck.py            # check against the baseline
    python scripts/typecheck.py --update   # after fixing some, record the win
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "mypy-baseline.json"

#: "path/to/file.py:12: error: message  [code]"
LINE = re.compile(r"^(?P<file>[^:]+):\d+: error:")


def run_mypy() -> dict[str, int]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mypy", "src"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    counts: dict[str, int] = {}
    for line in result.stdout.splitlines():
        if match := LINE.match(line):
            counts[match.group("file")] = counts.get(match.group("file"), 0) + 1
    return counts


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    return json.loads(BASELINE.read_text())["files"]


def main() -> int:
    current = run_mypy()
    total = sum(current.values())

    if "--update" in sys.argv:
        BASELINE.write_text(
            json.dumps(
                {
                    "_comment": (
                        "Known mypy errors per file. This number may only go "
                        "DOWN. Regenerate with: python scripts/typecheck.py "
                        "--update"
                    ),
                    "total": total,
                    "files": dict(sorted(current.items())),
                },
                indent=2,
            )
            + "\n"
        )
        print(f"baseline updated: {total} error(s) across {len(current)} file(s)")
        return 0

    baseline = load_baseline()
    regressions = {
        path: (count, baseline.get(path, 0))
        for path, count in current.items()
        if count > baseline.get(path, 0)
    }

    if regressions:
        print("New type errors were introduced:\n")
        for path, (now, before) in sorted(regressions.items()):
            print(f"  {path}: {before} → {now}")
        print(
            "\nFix them, or run `python scripts/typecheck.py --update` only if "
            "you are deliberately accepting the debt (and say why in the commit)."
        )
        print("\nFull output:")
        subprocess.run([sys.executable, "-m", "mypy", "src"], cwd=ROOT)  # noqa: S603
        return 1

    improved = sum(baseline.values()) - total
    if improved > 0:
        print(
            f"{improved} fewer type error(s) than the baseline. Run "
            "`python scripts/typecheck.py --update` to lock the improvement in."
        )
    print(f"no new type errors ({total} known, baseline {sum(baseline.values())})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
