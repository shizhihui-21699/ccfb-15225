"""Command-line interface.

    vulnrange check ADVISORY.txt --repo /path/to/project
    vulnrange check ADVISORY.txt --repo-url https://github.com/owner/project
    vulnrange batch advisories/*.txt --repo-root /srv/mirrors --format json -o out.json

The exit status is part of the contract, so the tool can gate a pipeline:

    0  every advisory was confirmed against history
    1  at least one advisory was disputed or contradicted
    2  usage or environment error (bad path, not a git repo, ...)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from .advisory import extract_advisory
from .analysis.universe import build_universe
from .analysis.verify import verify
from .repo.git import GitError, GitRepo
from .report.render import to_json, to_markdown, to_text

__all__ = ["main", "run_one"]

_MIRROR_RE = re.compile(r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|gitee\.com)/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnrange",
        description=(
            "Extract affected-version ranges from vulnerability advisories and "
            "verify them against a git repository's release history."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="verify one advisory")
    check.add_argument("advisory", type=Path, help="advisory text file")
    _add_repo_args(check)
    _add_output_args(check)
    check.add_argument(
        "--advisory-id",
        default="",
        help="override the vulnerability ID used in reports",
    )
    check.add_argument(
        "--require-fix-evidence",
        action="store_true",
        help="treat a missing fix commit as an error instead of a warning",
    )
    check.add_argument(
        "--no-discover",
        action="store_true",
        help="do not search commit messages when the advisory names no commit",
    )

    batch = sub.add_parser("batch", help="verify many advisories in one run")
    batch.add_argument("advisories", nargs="+", type=Path)
    _add_repo_args(batch, required=False)
    _add_output_args(batch)
    batch.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "directory holding one checkout per package name; when given, "
            "--repo/--repo-url are not required"
        ),
    )
    batch.add_argument(
        "--summary",
        action="store_true",
        help="print only the one-line summary per advisory",
    )

    return p


def _add_repo_args(p: argparse.ArgumentParser, *, required: bool = True) -> None:
    g = p.add_mutually_exclusive_group(required=required)
    g.add_argument("--repo", type=Path, help="path to a local git checkout")
    g.add_argument(
        "--repo-url",
        metavar="URL",
        help="git URL to clone (shallow, into a temporary directory)",
    )


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="output format (default: text)",
    )
    p.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")
    p.add_argument(
        "--fail-on",
        choices=["never", "disputed", "contradicted"],
        default="disputed",
        help="exit non-zero when a result reaches this status (default: disputed)",
    )


# ---------------------------------------------------------------------------
# Repository acquisition
# ---------------------------------------------------------------------------
def _clone(url: str) -> tuple[GitRepo, tempfile.TemporaryDirectory]:
    """Clone into a temporary directory.

    The clone is deliberately *not* blob-filtered or shallow: backport
    detection runs ``git patch-id`` over historical commits, and a partial
    clone would silently degrade to "no backports found".  A correct answer is
    worth the bandwidth here.
    """
    tmp = tempfile.TemporaryDirectory(prefix="vulnrange-")
    try:
        proc = subprocess.run(
            ["git", "clone", "--quiet", "--no-single-branch", url, tmp.name],
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            check=False,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        tmp.cleanup()
        raise GitError(f"could not clone {url}: {exc}") from exc
    if proc.returncode != 0:
        tmp.cleanup()
        raise GitError(f"could not clone {url}: {proc.stderr.strip()}")
    return GitRepo(tmp.name), tmp


def _mirror_candidates(url: str, repo_root: Path) -> list[Path]:
    m = _MIRROR_RE.match(url)
    if not m:
        return []
    owner, name = m.group("owner"), m.group("repo")
    name = name.removesuffix(".git")
    cands = [
        repo_root / name,
        repo_root / f"{owner}__{name}",
        repo_root / owner / name,
    ]
    return [c for c in cands if c.is_dir()]


# ---------------------------------------------------------------------------
# One advisory
# ---------------------------------------------------------------------------
def run_one(
    advisory_path: Path,
    repo: GitRepo,
    *,
    advisory_id: str = "",
    discover: bool = True,
    require_fix_evidence: bool = False,
):
    text = advisory_path.read_text(encoding="utf-8", errors="replace")
    aid = advisory_id or infer_advisory_id(text, advisory_path)
    advisory = extract_advisory(aid, text)
    universe = build_universe(repo)
    verification = verify(
        advisory,
        repo,
        universe,
        discover=discover,
        require_fix_evidence=require_fix_evidence,
    )
    return advisory, universe, verification


_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{3,7}|GHSA-[\w-]{8,}|OSV-\d{4}-\d+)\b")


def infer_advisory_id(text: str, path: Path) -> str:
    m = _ID_RE.search(text)
    if m:
        return m.group(0)
    stem = path.stem
    m = _ID_RE.search(stem)
    return m.group(0) if m else stem


def _render(advisory, universe, verification, fmt: str) -> str:
    if fmt == "json":
        return to_json(verification, advisory, universe)
    if fmt == "markdown":
        return to_markdown(verification, advisory, universe)
    return to_text(verification, advisory, universe)


def _exit_code(results: list, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    bad = {"disputed", "contradicted"}
    for v in results:
        if v.status in bad:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "batch" and getattr(args, "repo_root", None) is None and (
        args.repo is None and args.repo_url is None
    ):
        parser.error("batch needs either --repo/--repo-url or --repo-root")

    tmp: tempfile.TemporaryDirectory | None = None
    try:
        if args.command == "check":
            if getattr(args, "repo", None) is not None:
                repo = GitRepo(args.repo)
            else:
                repo, tmp = _clone(args.repo_url)
            advisory, universe, verification = run_one(
                args.advisory,
                repo,
                advisory_id=args.advisory_id,
                discover=not args.no_discover,
                require_fix_evidence=args.require_fix_evidence,
            )
            payload = _render(advisory, universe, verification, args.format)
            _emit(payload, args.output)
            return _exit_code([verification], args.fail_on)

        # batch
        if getattr(args, "repo_root", None) is not None:
            return _run_batch_with_root(args)
        if getattr(args, "repo", None) is not None:
            repo = GitRepo(args.repo)
            return _run_batch(args, lambda _path: repo)
        repo, tmp = _clone(args.repo_url)
        return _run_batch(args, lambda _path: repo)
    except GitError as exc:
        print(f"vulnrange: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"vulnrange: file not found: {exc.filename}", file=sys.stderr)
        return 2
    finally:
        if tmp is not None:
            tmp.cleanup()


def _run_batch_with_root(args) -> int:
    results = []
    blocks: list[str] = []
    root: Path = args.repo_root
    for path in args.advisories:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"vulnrange: cannot read {path}: {exc}", file=sys.stderr)
            continue
        url = _extract_repo_url(text)
        repo = None
        if url:
            for cand in _mirror_candidates(url, root):
                try:
                    repo = GitRepo(cand)
                    break
                except GitError:
                    continue
        if repo is None:
            for cand in (root / path.stem, root / infer_advisory_id(text, path)):
                if cand.is_dir():
                    try:
                        repo = GitRepo(cand)
                        break
                    except GitError:
                        continue
        if repo is None:
            print(
                f"vulnrange: no checkout for {path.name} under {root}",
                file=sys.stderr,
            )
            continue
        advisory, universe, verification = run_one(path, repo)
        results.append(verification)
        if args.summary and args.format == "text":
            from .report.render import summary_line

            blocks.append(summary_line(verification))
        else:
            blocks.append(_render(advisory, universe, verification, args.format))
    _emit("\n".join(blocks), args.output)
    return _exit_code(results, args.fail_on)


def _run_batch(args, resolve) -> int:
    results = []
    blocks = []
    for path in args.advisories:
        advisory, universe, verification = run_one(path, resolve(path))
        results.append(verification)
        if args.summary and args.format == "text":
            from .report.render import summary_line

            blocks.append(summary_line(verification))
        else:
            blocks.append(_render(advisory, universe, verification, args.format))
    _emit("\n".join(blocks), args.output)
    return _exit_code(results, args.fail_on)


def _extract_repo_url(text: str) -> str:
    from .advisory.extract import _find_repo_url

    return _find_repo_url(text)


def _emit(payload: str, output: Path | None) -> None:
    if output is None:
        print(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload + "\n", encoding="utf-8")
    print(f"wrote {output}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
