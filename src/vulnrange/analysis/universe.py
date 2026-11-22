"""The universe of released versions in a repository.

A vulnerability only exists on some *release lines*: ``1.4.x`` is maintained
separately from ``2.x`` and gets its own backports.  An affected range is
therefore a statement per line, and a version is "released" only if a tag or a
branch makes it observable.  This module builds that map once and hands out
cheap lookups, so the verification layer reasons about reality (tags and
commits) rather than about string patterns.

Design notes
------------
* Tags are the source of truth for *released* versions; branches are used to
  identify lines and to find where a fix was applied even if untagged.
* A tag whose version cannot be parsed is kept as "unknown" rather than
  dropped, so the report can say a fix could not be checked against it.
* Release lines are inferred from branch names first (``1.4.x``,
  ``maintenance/2.0``) and from tag version numbers otherwise.  Tag lineage
  alone is ambiguous when a project ships 1.9 and 2.0 in parallel, which is
  exactly the case that matters for security work.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cached_property

from ..repo.git import GitRepo, Tag
from ..versions import Version, VersionSet, extract_version_from_tag
from ..versions.ranges import Interval

__all__ = ["Release", "ReleaseLine", "Universe", "build_universe"]

_LINE_IN_BRANCH = re.compile(
    r"""(?ix)
    (?:^|[/_-])                     # branch path separator
    (?:
        (?P<a>\d+)\.(?P<b>\d+)(?:\.(?P<c>\d+))?(?:\.x)?
      | release[-/_]?(?P<a2>\d+)\.(?P<b2>\d+)
      | v?(?P<a3>\d+)$
    )
    """
)


@dataclass(frozen=True)
class Release:
    version: Version
    tag: str
    commit: str
    line: str
    timestamp: int = 0

    @property
    def sort_key(self):
        return (self.version, self.tag)


@dataclass
class ReleaseLine:
    """One maintained line, e.g. ``1.4.x``."""

    name: str
    releases: list[Release] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)
    branch_tips: dict[str, str] = field(default_factory=dict)

    @property
    def newest(self) -> Release | None:
        return max(self.releases, key=lambda r: r.version) if self.releases else None

    @property
    def oldest(self) -> Release | None:
        return min(self.releases, key=lambda r: r.version) if self.releases else None

    def first_at_or_after(self, v: Version) -> Release | None:
        cands = [r for r in self.releases if r.version >= v]
        return min(cands, key=lambda r: r.version) if cands else None

    def previous_before(self, v: Version) -> Release | None:
        cands = [r for r in self.releases if r.version < v]
        return max(cands, key=lambda r: r.version) if cands else None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "branches": list(self.branches),
            "releases": [
                {"version": r.version.raw, "tag": r.tag, "commit": r.commit}
                for r in sorted(self.releases, key=lambda r: r.version)
            ],
        }


class Universe:
    """Every parsable release tag, grouped by release line."""

    def __init__(
        self,
        repo: GitRepo,
        releases: list[Release],
        lines: dict[str, ReleaseLine],
        unparsed_tags: list[Tag],
        branch_lines: dict[str, str],
    ) -> None:
        self.repo = repo
        self.releases = releases
        self.lines = lines
        self.unparsed_tags = unparsed_tags
        self.branch_lines = branch_lines
        self._by_tag = {r.tag: r for r in releases}
        self._by_commit: dict[str, list[Release]] = defaultdict(list)
        for r in releases:
            self._by_commit[r.commit].append(r)

    # -- lookups --------------------------------------------------------
    @property
    def parsed_tags(self) -> list[str]:
        return [r.tag for r in self.releases]

    def release_for_tag(self, tag: str) -> Release | None:
        r = self._by_tag.get(tag)
        if r is not None:
            return r
        # git may report the peeled name for annotated tags
        return self._by_tag.get(tag.replace("^{}", ""))

    def releases_for_commit(self, commit: str) -> list[Release]:
        return self._by_commit.get(commit, [])

    def line_of_version(self, v: Version) -> str | None:
        """Best guess at the line a *version number* belongs to."""
        key = ".".join(map(str, v.line))
        for name in self.lines:
            if name.split(".")[:2] == key.split(".")[:2]:
                return name
        # No matching line: the version may be newer than anything released.
        return None

    def line_for_tag(self, tag: str) -> str | None:
        r = self.release_for_tag(tag)
        return r.line if r else None

    @cached_property
    def all_versions(self) -> list[Version]:
        return sorted({r.version for r in self.releases})

    def describe(self) -> str:
        return (
            f"{len(self.releases)} release tags in {len(self.lines)} lines "
            f"({', '.join(sorted(self.lines)) or 'none'})"
        )

    def to_dict(self) -> dict:
        return {
            "release_count": len(self.releases),
            "unparsed_tag_count": len(self.unparsed_tags),
            "lines": {k: v.to_dict() for k, v in sorted(self.lines.items())},
        }


def _line_from_branch(branch: str) -> str | None:
    m = _LINE_IN_BRANCH.search(branch)
    if not m:
        return None
    a = m.group("a") or m.group("a2") or m.group("a3")
    b = m.group("b") or m.group("b2")
    if a is None:
        return None
    return f"{a}.{b}.x" if b is not None else f"{a}.x"


def _line_from_version(v: Version) -> str:
    rel = v.release
    if len(rel) >= 3:
        return f"{rel[0]}.{rel[1]}.x"
    if len(rel) == 2:
        return f"{rel[0]}.{rel[1]}.x"
    return f"{rel[0]}.x"


def _common_prefix(releases: list[Release]) -> tuple[int, ...]:
    """Longest common numeric prefix of a set of releases."""
    if not releases:
        return ()
    tuples = [r.version.release for r in releases]
    prefix: list[int] = []
    for i in range(min(len(t) for t in tuples)):
        col = {t[i] for t in tuples}
        if len(col) != 1:
            break
        prefix.append(col.pop())
    return tuple(prefix)


def _cluster_by_ancestry(
    repo: GitRepo, releases: list[Release]
) -> list[list[Release]]:
    """Group releases into independent lines using tag ancestry.

    Two releases are on the same line when one is an ancestor of the other;
    that relation is transitive.  Releases that diverge (neither is an
    ancestor) are on different lines.  With a linear tag history this yields a
    single cluster, which is what a project without maintenance branches has.
    """
    parent = {r.tag: r.tag for r in releases}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i, a in enumerate(releases):
        for b in releases[i + 1 :]:
            if repo.is_ancestor(a.commit, b.commit) or repo.is_ancestor(b.commit, a.commit):
                union(a.tag, b.tag)
    groups: dict[str, list[Release]] = {}
    for r in releases:
        groups.setdefault(find(r.tag), []).append(r)
    return list(groups.values())


def _line_name_for_cluster(cluster: list[Release], index: int, total: int) -> str:
    prefix = _common_prefix(cluster)
    if prefix:
        return ".".join(map(str, prefix)) + ".x"
    newest = max(r.version for r in cluster)
    rel = newest.release
    if len(rel) >= 2:
        return f"{rel[0]}.{rel[1]}.x"
    if rel:
        return f"{rel[0]}.x"
    return f"line-{index}"


def build_universe(repo: GitRepo, *, project_names: tuple[str, ...] = ()) -> Universe:
    """Index every release tag and branch into lines."""
    tags = repo.tags()
    try:
        out = repo._run("for-each-ref", "--format=%(refname:strip=2)", "refs/heads")
        branch_names = [b for b in out.splitlines() if b]
    except Exception:  # pragma: no cover - git failure already surfaced by repo
        branch_names = []

    branch_lines: dict[str, str] = {}
    branch_tips: dict[str, str] = {}
    for b in branch_names:
        line = _line_from_branch(b)
        if line is None:
            continue
        tip = repo.resolve(b)
        if tip is None:
            continue
        branch_lines[b] = line
        branch_tips[b] = tip

    parsed: list[tuple[Tag, Version]] = []
    unparsed: list[Tag] = []
    for t in tags:
        ver = extract_version_from_tag(t.name, project_names)
        if ver is None:
            unparsed.append(t)
            continue
        parsed.append((t, ver))

    # --- assign each tag to a line --------------------------------------
    # 1. A branch whose tip contains the tag and whose name implies the same
    #    line is authoritative.
    assigned: list[Release] = []
    remaining: list[tuple[Tag, Version]] = []
    for t, ver in parsed:
        best: str | None = None
        for b, bline in sorted(branch_lines.items()):
            if not repo.is_ancestor(t.commit, branch_tips[b]):
                continue
            if _line_from_version(ver) != bline:
                # Branch contains the tag but names a different line: only
                # trust it when the tag itself does not pin a line.
                continue
            best = bline
            break
        if best is not None:
            assigned.append(
                Release(ver, t.name, t.commit, best, _commit_time(repo, t.commit))
            )
        else:
            remaining.append((t, ver))

    # 2. For everything else, infer lines from branch containment alone
    #    (a tag may sit on a maintenance branch that has a non-standard name),
    #    then fall back to tag ancestry.
    still: list[tuple[Tag, Version]] = []
    for t, ver in remaining:
        hits = [
            branch_lines[b]
            for b in branch_lines
            if repo.is_ancestor(t.commit, branch_tips[b])
        ]
        if hits:
            assigned.append(
                Release(ver, t.name, t.commit, sorted(hits)[0], _commit_time(repo, t.commit))
            )
        else:
            still.append((t, ver))

    if still:
        provisional = [
            Release(ver, t.name, t.commit, "", _commit_time(repo, t.commit))
            for t, ver in still
        ]
        clusters = _cluster_by_ancestry(repo, provisional)
        for i, cluster in enumerate(sorted(clusters, key=lambda c: max(x.version for x in c))):
            name = _line_name_for_cluster(cluster, i, len(clusters))
            for r in cluster:
                assigned.append(Release(r.version, r.tag, r.commit, name, r.timestamp))

    lines: dict[str, ReleaseLine] = {}
    for r in assigned:
        lines.setdefault(r.line, ReleaseLine(name=r.line)).releases.append(r)
    for b, line in branch_lines.items():
        ln = lines.setdefault(line, ReleaseLine(name=line))
        ln.branches.append(b)
        ln.branch_tips[b] = branch_tips[b]
    for ln in lines.values():
        ln.releases.sort(key=lambda r: r.version)
        ln.branches.sort()

    assigned.sort(key=lambda r: (r.version, r.tag))
    return Universe(repo, assigned, lines, unparsed, branch_lines)


_TIME_CACHE: dict[tuple[str, str], int] = {}


def _commit_time(repo: GitRepo, commit: str) -> int:
    key = (str(repo.path), commit)
    if key in _TIME_CACHE:
        return _TIME_CACHE[key]
    try:
        ts = repo.commit(commit).authored_at
    except Exception:
        ts = 0
    _TIME_CACHE[key] = ts
    return ts


def releases_to_set(releases: list[Release]) -> VersionSet:
    """Exact set of the given release versions (not a continuous interval)."""
    return VersionSet(
        [Interval(lo=r.version, lo_inc=True, hi=r.version, hi_inc=True) for r in releases]
    )
