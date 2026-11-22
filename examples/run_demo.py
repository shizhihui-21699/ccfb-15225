#!/usr/bin/env python3
"""Build the demo repositories, then verify the example advisories against them.

    python examples/run_demo.py [--keep]

Without ``--keep`` the repositories live in a temporary directory that is
removed on exit.  With it, the path is printed so the history can be inspected
with ordinary git commands.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from build_fixtures import build_scenario  # noqa: E402

from vulnrange.advisory import extract_advisory  # noqa: E402
from vulnrange.analysis.universe import build_universe  # noqa: E402
from vulnrange.analysis.verify import verify  # noqa: E402
from vulnrange.repo.git import GitRepo  # noqa: E402
from vulnrange.report.render import to_text  # noqa: E402

from vulnrange.cli import infer_advisory_id  # noqa: E402

# (advisory file, fixture repository, notes)
DEMOS = [
    ("CVE-2024-4242.txt", "multi-branch", "backports on two maintenance lines"),
    ("CVE-2024-9999.txt", "wrong-advisory", "advisory understates the range"),
    ("GHSA-example-fix-unreleased.txt", "fix-never-shipped", "fix exists on a branch only"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep the demo repos")
    args = parser.parse_args()

    base = Path(tempfile.mkdtemp(prefix="vulnrange-demo-"))
    print(f"demo repositories in {base}\n")

    try:
        for advisory_name, scenario, note in DEMOS:
            path, _facts = build_scenario(scenario, base)
            repo = GitRepo(path)
            universe = build_universe(repo)
            text = (ROOT / "examples" / "advisories" / advisory_name).read_text()
            advisory = extract_advisory(
                infer_advisory_id(text, ROOT / "examples" / "advisories" / advisory_name),
                text,
            )
            verification = verify(advisory, repo, universe)
            print(to_text(verification, advisory, universe))
            print(f"({scenario}: {note})\n")
    finally:
        if args.keep:
            print(f"kept: {base}")
        else:
            shutil.rmtree(base, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
