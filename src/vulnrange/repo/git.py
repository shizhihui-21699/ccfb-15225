"""Thin, dependency-free wrapper around the git CLI.

Everything the analysis needs is a read-only query, so this layer is kept
deliberately small: it never mutates a repository and never trusts a path
outside the one it was given.  Command output is parsed with explicit
separators instead of human-facing ``git log`` formatting where possible.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = ["GitError", "GitRepo", "Tag", "Commit"]

_SEP = "\x1f"


class GitError(RuntimeError):
    """A git command failed, or the directory is not a repository."""


@dataclass(frozen=True)
class Tag:
    name: str
    commit: str
    is_annotated: bool = False


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    authored_at: int
    parents: tuple[str, ...]

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1


class GitRepo:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).resolve()
        if not self.path.is_dir():
            raise GitError(f"not a directory: {self.path}")
        try:
            self._run("rev-parse", "--git-dir")
        except GitError as exc:
            raise GitError(f"not a git repository: {self.path}") from exc
        self._ancestor_cache: dict[tuple[str, str], bool] = {}

    # -- plumbing -------------------------------------------------------
    def _run(
        self, *args: str, check: bool = True, text: bool = True
    ) -> str | bytes:
        env = {
            **os.environ,
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.path), *args],
                capture_output=True,
                check=False,
                env=env,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git {args[0]} failed: {exc}") from exc
        if check and proc.returncode != 0:
            raise GitError(
                f"git {' '.join(args)} -> {proc.returncode}: "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
        if text:
            return proc.stdout.decode("utf-8", "replace")
        return proc.stdout

    def _ok(self, *args: str) -> bool:
        try:
            self._run(*args)
            return True
        except GitError:
            return False

    # -- revisions ------------------------------------------------------
    def resolve(self, rev: str) -> str | None:
        try:
            return self._run("rev-parse", "--verify", f"{rev}^{{commit}}").strip()
        except GitError:
            return None

    def tags(self, *, max_tags: int = 5000) -> list[Tag]:
        out = self._run(
            "for-each-ref",
            "--format=%(refname:strip=2)"
            + _SEP
            + "%(objecttype)"
            + _SEP
            + "%(objectname)"
            + _SEP
            + "%(*objectname)",
            "refs/tags",
        )
        tags: list[Tag] = []
        for line in out.splitlines():
            if not line:
                continue
            parts = line.split(_SEP)
            if len(parts) < 4:
                continue
            name, otype, obj, peeled = parts[0], parts[1], parts[2], parts[3]
            commit = peeled or obj
            # Annotated tags point at a tag object; tags on blobs/trees are
            # skipped because they can never be a release commit.
            if otype == "tag" and not peeled:
                continue
            if self.resolve(commit) is None:
                continue
            tags.append(Tag(name=name, commit=commit, is_annotated=otype == "tag"))
            if len(tags) >= max_tags:
                break
        return tags

    def commit(self, rev: str) -> Commit:
        out = self._run(
            "show",
            "-s",
            "--format=%H%x00%ct%x00%P%x00%s",
            rev,
        ).rstrip("\n")
        sha, ct, parents, subject = out.split("\x00", 3)
        return Commit(
            sha=sha,
            subject=subject,
            authored_at=int(ct or 0),
            parents=tuple(p for p in parents.split() if p),
        )

    def merge_base(self, a: str, b: str) -> str | None:
        try:
            return self._run("merge-base", a, b).strip() or None
        except GitError:
            return None

    def is_ancestor(self, maybe_ancestor: str, descendant: str) -> bool:
        """True when ``maybe_ancestor`` is reachable from ``descendant``."""
        key = (maybe_ancestor, descendant)
        cached = self._ancestor_cache.get(key)
        if cached is not None:
            return cached
        a = self.resolve(maybe_ancestor)
        b = self.resolve(descendant)
        if a is None or b is None:
            result = False
        elif a == b:
            result = True
        else:
            result = self._ok("merge-base", "--is-ancestor", a, b)
        self._ancestor_cache[key] = result
        return result

    def is_related(self, a: str, b: str) -> bool:
        return self.merge_base(a, b) is not None

    # -- queries --------------------------------------------------------
    def tags_containing(self, rev: str) -> list[str]:
        try:
            out = self._run("tag", "--contains", rev)
        except GitError:
            return []
        return [t for t in out.splitlines() if t]

    def branches_containing(self, rev: str) -> list[str]:
        try:
            out = self._run(
                "for-each-ref",
                "--contains",
                rev,
                "--format=%(refname:strip=2)",
                "refs/heads",
            )
        except GitError:
            return []
        return [b for b in out.splitlines() if b]

    def log(
        self,
        *,
        grep: str | None = None,
        rev_range: str | None = None,
        limit: int = 200,
        all_refs: bool = True,
    ) -> list[Commit]:
        """Query commits.

        ``grep`` must be a POSIX extended regex.  Git's regex engine has no
        ``\\b``, and a malformed pattern must not abort an analysis, so a
        failing ``--grep`` is retried as a plain case-insensitive substring
        search and the caller filters further in Python if it needs to.
        """
        base = ["log", f"--max-count={limit}", "--format=%H%x00%ct%x00%P%x00%s"]
        tail: list[str] = []
        if rev_range:
            tail.append(rev_range)
        elif all_refs:
            tail.append("--all")

        def parse(out: str) -> list[Commit]:
            commits: list[Commit] = []
            for line in out.splitlines():
                if not line:
                    continue
                sha, ct, parents, subject = line.split("\x00", 3)
                commits.append(
                    Commit(
                        sha, subject, int(ct or 0), tuple(p for p in parents.split() if p)
                    )
                )
            return commits

        if not grep:
            return parse(self._run(*base, *tail))

        for mode in (
            ["--regexp-ignore-case", "--extended-regexp", "--grep", grep],
            ["--fixed-strings", "--regexp-ignore-case", "--grep", grep],
        ):
            try:
                return parse(self._run(*base, *mode, *tail))
            except GitError:
                continue
        return []

    def rev_list(self, start: str, end: str) -> list[str]:
        """Commits reachable from ``end`` but not from ``start``."""
        try:
            out = self._run("rev-list", f"{start}..{end}")
        except GitError:
            return []
        return [c for c in out.splitlines() if c]

    def count_between(self, start: str, end: str) -> int:
        try:
            out = self._run("rev-list", "--count", f"{start}..{end}")
        except GitError:
            return -1
        return int(out.strip() or "0")

    def patch_id(self, rev: str) -> str | None:
        """Stable identity of a change, used to spot backports."""
        try:
            diff = self._run("show", "--pretty=format:", "--patch", rev, text=False)
        except GitError:
            return None
        if not isinstance(diff, bytes) or not diff.strip():
            return None
        try:
            proc = subprocess.run(
                ["git", "patch-id", "--stable"],
                input=diff,
                capture_output=True,
                check=False,
                cwd=str(self.path),
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        first = proc.stdout.decode().split()
        return first[0] if first else None

    def files_changed(self, rev: str) -> list[str]:
        try:
            out = self._run(
                "show", "--pretty=format:", "--name-only", "--no-renames", rev
            )
        except GitError:
            return []
        return [f for f in out.splitlines() if f.strip()]

    def grep_history(self, pattern: str, *, limit: int = 50) -> list[str]:
        """Commits whose *diff* adds or removes lines matching ``pattern``."""
        try:
            out = self._run("log", "--all", "-S", pattern, f"--max-count={limit}", "--format=%H")
        except GitError:
            return []
        return [c for c in out.splitlines() if c]

    def default_branch(self) -> str:
        try:
            ref = self._run("symbolic-ref", "--short", "HEAD").strip()
            if ref:
                return ref
        except GitError:
            pass
        for cand in ("main", "master", "trunk", "develop"):
            if self._ok("rev-parse", "--verify", cand):
                return cand
        return "HEAD"

    def describe(self, rev: str) -> str:
        try:
            return self._run("describe", "--tags", "--always", rev).strip()
        except GitError:
            return rev[:12]


def looks_like_commit_sha(text: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", text.strip().lower()))


def short(sha: str) -> str:
    return sha[:10]
