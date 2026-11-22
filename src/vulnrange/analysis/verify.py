"""Reconcile an advisory's claims against the repository's actual history.

The repository is the arbiter, not the advisory.  Three questions are answered
separately, each with its own evidence:

1. **Is the named fix commit real, and where did it land?**  A commit is in a
   release if and only if it is an ancestor of that release's tag commit;
   ``git merge-base --is-ancestor`` answers that exactly.  Backports have new
   hashes, so equivalence is also tested by stable ``patch-id``.
2. **Which releases are actually affected?**  A release is affected when it
   does not contain the fix (directly or as an equivalent patch) and is at or
   above the version where the vulnerability was introduced.
3. **Does the advisory's stated range agree?**  Every disagreement is reported
   per release tag with the commit and the direction of the error, because
   "advisory too narrow" and "advisory too broad" mean very different things to
   a security team.

When no fix commit can be established, the range is *not* invented: the
verification says so and caps confidence, leaving the advisory's own claim as
the only support.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from ..advisory.model import Advisory, ClaimKind
from ..repo.git import GitRepo
from ..versions import Version, VersionSet
from ..versions.ranges import Interval
from .universe import Release, ReleaseLine, Universe

__all__ = [
    "Finding",
    "FindingKind",
    "FixCommit",
    "LineResult",
    "Verification",
    "verify",
]


class FindingKind(str, Enum):
    FIX_COMMIT_MISSING = "fix_commit_missing"
    FIX_CONFIRMED = "fix_confirmed"
    FIX_REACHES_EARLIER = "fix_reaches_earlier"
    FIX_NOT_IN_CLAIMED_RELEASE = "fix_not_in_claimed_release"
    FIX_NEVER_RELEASED = "fix_never_released"
    BACKPORT_FOUND = "backport_found"
    BACKPORT_MISSING = "backport_missing"
    OVER_DECLARED = "over_declared"
    UNDER_DECLARED = "under_declared"
    RANGE_MATCHES = "range_matches"
    UNVERIFIED = "unverified"
    ADVISORY_CONTRADICTION = "advisory_contradiction"


@dataclass
class Finding:
    kind: FindingKind
    severity: str  # info | warning | error
    message: str
    evidence: list[str] = field(default_factory=list)
    line: str = ""
    version: str = ""
    commit: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "severity": self.severity,
            "message": self.message,
            "evidence": list(self.evidence),
            "line": self.line,
            "version": self.version,
            "commit": self.commit,
        }


@dataclass
class FixCommit:
    """A commit that fixes the vulnerability, and where it was applied."""

    sha: str
    source: str                       # advisory | advisory-bare | discovered
    subject: str = ""
    present: bool = False
    tags: list[str] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)
    earliest: dict[str, Release] = field(default_factory=dict)
    equivalent_of: str = ""           # sha of the upstream commit, for backports
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sha": self.sha,
            "source": self.source,
            "subject": self.subject,
            "present": self.present,
            "tags": list(self.tags),
            "branches": list(self.branches),
            "earliest_release_per_line": {
                k: v.tag for k, v in sorted(self.earliest.items())
            },
            "equivalent_of": self.equivalent_of,
            "evidence": list(self.evidence),
        }


@dataclass
class LineResult:
    """Per release-line reconciliation of declared vs. actual."""

    line: str
    declared_affected: list[str] = field(default_factory=list)
    declared_not_affected: list[str] = field(default_factory=list)
    actual_affected: list[str] = field(default_factory=list)
    actual_fixed: list[str] = field(default_factory=list)
    computed_range: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "declared_affected": list(self.declared_affected),
            "declared_not_affected": list(self.declared_not_affected),
            "actual_affected": list(self.actual_affected),
            "actual_fixed_releases": list(self.actual_fixed),
            "computed_range": self.computed_range,
            "notes": list(self.notes),
        }


@dataclass
class Verification:
    advisory_id: str
    confidence: float = 0.0
    fix_commits: list[FixCommit] = field(default_factory=list)
    lines: dict[str, LineResult] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    resolved_range: VersionSet | None = None
    declared_range: VersionSet | None = None
    notes: list[str] = field(default_factory=list)
    basis: str = ""

    @property
    def status(self) -> str:
        if any(f.kind is FindingKind.ADVISORY_CONTRADICTION for f in self.findings):
            return "contradicted"
        if any(f.severity == "error" for f in self.findings):
            return "disputed"
        if any(f.severity == "warning" for f in self.findings):
            return "partial"
        return "confirmed"

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "status": self.status,
            "confidence": round(self.confidence, 3),
            "basis": self.basis,
            "declared_range": self.declared_range.describe() if self.declared_range else "",
            "resolved_range": self.resolved_range.describe() if self.resolved_range else "",
            "fix_commits": [f.to_dict() for f in self.fix_commits],
            "lines": {k: v.to_dict() for k, v in sorted(self.lines.items())},
            "findings": [f.to_dict() for f in self.findings],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Fix-commit resolution
# ---------------------------------------------------------------------------
def _resolve_fix_commit(repo: GitRepo, universe: Universe, sha: str, *, source: str) -> FixCommit:
    fix = FixCommit(sha=sha, source=source)
    full = repo.resolve(sha)
    if full is None:
        fix.evidence.append(
            f"commit {sha} does not exist in this repository "
            f"(not fetched, rewritten, or belonging to another project)"
        )
        return fix

    fix.present = True
    fix.sha = full
    try:
        fix.subject = repo.commit(full).subject
        fix.evidence.append(f"commit exists: {full[:10]} {fix.subject!r}")
    except Exception:
        fix.evidence.append(f"commit exists: {full[:10]}")

    fix.tags = sorted(repo.tags_containing(full))
    fix.branches = sorted(repo.branches_containing(full))
    if fix.tags:
        fix.evidence.append("released in: " + ", ".join(fix.tags))
    else:
        fix.evidence.append("contained in no release tag")

    for tag in fix.tags:
        rel = universe.release_for_tag(tag)
        if rel is None:
            continue
        cur = fix.earliest.get(rel.line)
        if cur is None or rel.version < cur.version:
            fix.earliest[rel.line] = rel
    return fix


def _find_backports(
    repo: GitRepo, universe: Universe, fix: FixCommit
) -> list[tuple[Release, str]]:
    """Releases on lines the fix does not directly reach that carry the same patch."""
    pid = repo.patch_id(fix.sha)
    if not pid:
        return []
    out: list[tuple[Release, str]] = []
    for line, rl in sorted(universe.lines.items()):
        if line in fix.earliest:
            continue
        match = _earliest_equivalent(repo, rl, pid, skip=fix.sha)
        if match is not None:
            out.append((match, pid))
    return out


def _earliest_equivalent(
    repo: GitRepo, rl: ReleaseLine, pid: str, *, skip: str
) -> Release | None:
    """Earliest release on ``rl`` containing a commit with patch-id ``pid``.

    Walking the line's history once and comparing patch-ids is exact, and the
    candidate set is bounded by the line's own commits.
    """
    if not rl.releases:
        return None
    tip = rl.releases[-1].commit
    candidates = [
        c for c in repo.log(rev_range=f"{tip}", limit=2000) if c.sha != skip
    ]
    matching = [c.sha for c in candidates if repo.patch_id(c.sha) == pid]
    if not matching:
        return None
    for rel in rl.releases:
        if any(repo.is_ancestor(m, rel.commit) for m in matching):
            return rel
    return None


# ---------------------------------------------------------------------------
# Advisory-driven fix discovery
# ---------------------------------------------------------------------------
def _discover_fix_commits(repo: GitRepo, advisory: Advisory, *, limit: int = 4) -> list[tuple[str, str]]:
    """Look for commits that mention the advisory ID or its key terms.

    Discovery is a fallback and always reported as such: a keyword match is
    corroboration, not proof, so the confidence score treats it accordingly.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    ids = set(re.findall(r"\b(?:CVE|GHSA|OSV)-\d{4}-\d{3,7}\b|\bGHSA-[\w-]{8,}\b", advisory.text))
    ident = advisory.advisory_id.strip()
    if re.match(r"^(?:CVE|GHSA|OSV)-", ident, re.I):
        ids.add(ident)
    for i in sorted(ids):
        for c in repo.log(grep=re.escape(i), limit=limit):
            if c.sha not in seen:
                seen.add(c.sha)
                found.append((c.sha, f"commit message references {i}"))
    if found:
        return found

    keywords = _advisory_keywords(advisory)
    if not keywords:
        return []
    # git's own regex engine is POSIX-ERE: no \b, no non-capturing groups.
    fix_words = (
        "fix|fixed|fixes|patch|patched|resolve|resolved|security|vulnerab|"
        "sanitiz|validate|reject|harden"
    )
    topic_words = [re.escape(k) for k in keywords[:4]]
    for c in repo.log(grep=fix_words, limit=limit * 12):
        if not any(re.search(rf"\b{w}\b", c.subject, re.I) for w in topic_words):
            continue
        if c.sha in seen:
            continue
        seen.add(c.sha)
        found.append((c.sha, f"commit subject matches advisory keywords: {c.subject!r}"))
        if len(found) >= limit:
            break
    return found


_STOPWORDS = {
    "the", "a", "an", "in", "of", "and", "or", "for", "to", "with", "when", "was",
    "were", "is", "are", "be", "been", "this", "that", "all", "any", "before",
    "after", "affected", "versions", "version", "releases", "release", "fixed",
    "issue", "vulnerability", "security", "could", "may", "allow", "allows",
    "package", "project", "repo", "repository", "http", "https", "github",
}


def _advisory_keywords(advisory: Advisory) -> list[str]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", advisory.text)
    freq: dict[str, int] = {}
    for w in words:
        lw = w.lower()
        if lw in _STOPWORDS or lw == advisory.package.lower():
            continue
        freq[lw] = freq.get(lw, 0) + 1
    return [w for w, _ in sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))]


# ---------------------------------------------------------------------------
# Range evaluation over actual releases
# ---------------------------------------------------------------------------
@dataclass
class _Actual:
    """What history says about every release, independent of declared lines."""

    fixed_by: dict[str, list[FixCommit]] = field(default_factory=dict)
    introduced: Version | None = None

    def is_fixed(self, rel: Release) -> bool:
        return rel.tag in self.fixed_by

    def is_affected(self, rel: Release) -> bool:
        if self.is_fixed(rel):
            return False
        if self.introduced is not None and rel.version < self.introduced:
            return False
        return True


def _actual_state(
    universe: Universe,
    fixes: list[FixCommit],
    backports: dict[str, list[tuple[Release, str]]],
    introduced: Version | None,
) -> _Actual:
    state = _Actual(introduced=introduced)
    present = [f for f in fixes if f.present]
    for rel in universe.releases:
        who: list[FixCommit] = []
        for f in present:
            if rel.tag in f.tags:
                who.append(f)
        for f in present:
            for brel, _pid in backports.get(f.sha, []):
                if brel.tag == rel.tag:
                    who.append(f)
        if who:
            state.fixed_by[rel.tag] = who
    return state


def _declared_state(
    advisory: Advisory, universe: Universe
) -> tuple[set[str], set[str]]:
    """Tags the advisory claims affected, and tags it claims are not affected."""
    affected: set[str] = set()
    not_affected: set[str] = set()
    for claim in advisory.claims:
        if claim.kind not in {
            ClaimKind.AFFECTED_RANGE,
            ClaimKind.AFFECTED_ALL,
            ClaimKind.NOT_AFFECTED,
        }:
            continue
        vs = claim.version_set
        if vs is None:
            continue
        for rel in universe.releases:
            try:
                inside = vs.contains(rel.version)
            except Exception:
                continue
            if not inside:
                continue
            if claim.kind is ClaimKind.NOT_AFFECTED:
                not_affected.add(rel.tag)
            else:
                affected.add(rel.tag)
    affected -= not_affected
    return affected, not_affected


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def verify(
    advisory: Advisory,
    repo: GitRepo,
    universe: Universe,
    *,
    discover: bool = True,
    require_fix_evidence: bool = False,
) -> Verification:
    """Check ``advisory``'s claims against ``repo``.

    ``require_fix_evidence`` makes the absence of any fix commit an error
    rather than a warning; use it when the workflow demands commit-level proof.
    """
    v = Verification(advisory_id=advisory.advisory_id)
    v.declared_range = advisory.declared_affected

    # ---- 1. the commits the advisory names ------------------------------
    named: dict[str, str] = {}
    for c in advisory.fixed_commits:
        if c.commit:
            named.setdefault(c.commit.lower(), c.detail or "named by advisory")
    fixes = [_resolve_fix_commit(repo, universe, sha, source="advisory") for sha in named]

    # ---- 2. fall back to search when no named commit exists ------------
    if discover and not any(f.present for f in fixes):
        for sha, why in _discover_fix_commits(repo, advisory):
            cand = _resolve_fix_commit(repo, universe, sha, source="discovered")
            if not cand.present:
                continue
            cand.evidence.insert(0, f"found by search — {why}")
            fixes.append(cand)
            break
    v.fix_commits = fixes

    for f in fixes:
        if not f.present:
            v.findings.append(
                Finding(
                    FindingKind.FIX_COMMIT_MISSING,
                    "error",
                    f"advisory names fix commit {f.sha[:12]}, which is not in this "
                    f"repository",
                    evidence=list(f.evidence),
                    commit=f.sha,
                )
            )

    # ---- 3. backports: same patch, other lines --------------------------
    backports: dict[str, list[tuple[Release, str]]] = {}
    for f in fixes:
        if not f.present:
            continue
        found = _find_backports(repo, universe, f)
        if found:
            backports[f.sha] = found
            for rel, pid in found:
                f.earliest.setdefault(rel.line, rel)
                f.evidence.append(
                    f"backport found on line {rel.line}: {rel.tag} "
                    f"({rel.commit[:10]}) has the same patch-id ({pid[:12]})"
                )
                v.findings.append(
                    Finding(
                        FindingKind.BACKPORT_FOUND,
                        "info",
                        f"line {rel.line} was patched separately: {rel.tag} carries "
                        f"the same change as {f.sha[:10]} with a different hash",
                        evidence=[
                            f"{rel.tag} -> {rel.commit[:10]}",
                            f"patch-id {pid} matches {f.sha[:10]}",
                        ],
                        line=rel.line,
                        version=rel.tag,
                        commit=rel.commit,
                    )
                )

    # ---- 4. what history says ------------------------------------------
    introduced = next(
        (c.version for c in advisory.of_kind(ClaimKind.INTRODUCED_VERSION) if c.version),
        None,
    )
    actual = _actual_state(universe, fixes, backports, introduced)
    declared_affected, declared_not_affected = _declared_state(advisory, universe)

    any_fix = any(f.present for f in fixes)
    if any_fix:
        v.basis = "repository history (fix commits + patch-id backports)"
    else:
        v.basis = "advisory text only (no fix commit could be established)"

    # ---- 5. per-line report --------------------------------------------
    for line in sorted(universe.lines):
        rl = universe.lines[line]
        lr = LineResult(line=line)
        lr.declared_affected = [r.tag for r in rl.releases if r.tag in declared_affected]
        lr.declared_not_affected = [
            r.tag for r in rl.releases if r.tag in declared_not_affected
        ]
        if any_fix:
            lr.actual_affected = [r.tag for r in rl.releases if actual.is_affected(r)]
            lr.actual_fixed = [r.tag for r in rl.releases if actual.is_fixed(r)]
            lr.computed_range = _describe_actual(rl, lr.actual_affected)
            _compare_line(v, rl, lr, declared_not_affected)
        else:
            lr.notes.append(
                "no fix commit available: actual affected releases cannot be "
                "derived from history on this line"
            )
        v.lines[line] = lr

    # ---- 6. do the claimed fixed versions contain the fix? -------------
    _check_claimed_fix_versions(v, advisory, universe, fixes, actual, any_fix)

    # ---- 7. resolve the best-supported range ---------------------------
    v.resolved_range = _resolved_range(advisory, universe, actual, any_fix, declared_affected)

    # ---- 8. cross-line sanity and confidence ---------------------------
    _check_unreleased_fix(v, fixes, any_fix)
    if not any_fix:
        # Without a fix commit nothing was actually checked against history, so
        # the result must not read as a confirmation.  A "warning" keeps the
        # status at PARTIAL, which is the honest answer: the advisory's text is
        # the only support for the range.
        v.findings.append(
            Finding(
                FindingKind.UNVERIFIED,
                "error" if require_fix_evidence else "warning",
                "no fix commit could be established, so the affected range was "
                "not checked against repository history",
            )
        )
    v.confidence = _score(v, advisory, fixes, any_fix, universe)
    v.notes.extend(_notes(v, advisory, universe, fixes, any_fix, backports))
    return v


def _describe_actual(rl: ReleaseLine, affected: list[str]) -> str:
    if not affected:
        return "no affected release on this line"
    ordered = [r.tag for r in rl.releases if r.tag in affected]
    if len(ordered) == 1:
        return ordered[0]
    return f"{ordered[0]} .. {ordered[-1]}"


def _compare_line(
    v: Verification,
    rl: ReleaseLine,
    lr: LineResult,
    declared_not_affected: set[str],
) -> None:
    actual_aff = set(lr.actual_affected)
    declared_aff = set(lr.declared_affected)
    not_aff = {t for t in declared_not_affected if t in {r.tag for r in rl.releases}}

    over = [t for t in lr.declared_affected if t not in actual_aff]
    under = [t for t in lr.actual_affected if t not in declared_aff and t not in not_aff]
    wrongly_not = [t for t in lr.declared_not_affected if t in actual_aff]

    if over:
        v.findings.append(
            Finding(
                FindingKind.OVER_DECLARED,
                "error",
                f"{rl.name}: advisory says {_join(over)} affected, but those "
                f"releases already contain the fix",
                evidence=[
                    f"{t} contains the fix commit" for t in over[:6]
                ] + [f"first release with the fix on this line: {lr.actual_fixed[0] if lr.actual_fixed else 'none'}"],
                line=rl.name,
                version=", ".join(over),
            )
        )
    if under:
        fixed_note = (
            f"first release with the fix on this line: {lr.actual_fixed[0]}"
            if lr.actual_fixed
            else "no release on this line contains the fix"
        )
        v.findings.append(
            Finding(
                FindingKind.UNDER_DECLARED,
                "error",
                f"{rl.name}: releases {_join(under)} do not contain the fix but the "
                f"advisory does not list them as affected",
                evidence=[f"{t} does not contain the fix commit" for t in under[:6]]
                + [fixed_note],
                line=rl.name,
                version=", ".join(under),
            )
        )
    if wrongly_not:
        v.findings.append(
            Finding(
                FindingKind.ADVISORY_CONTRADICTION,
                "error",
                f"{rl.name}: advisory says {_join(wrongly_not)} are NOT affected, "
                f"but they do not contain the fix",
                evidence=[f"{t} does not contain the fix commit" for t in wrongly_not[:6]],
                line=rl.name,
                version=", ".join(wrongly_not),
            )
        )
    if not over and not under and not wrongly_not and (lr.declared_affected or lr.actual_affected):
        v.findings.append(
            Finding(
                FindingKind.RANGE_MATCHES,
                "info",
                f"{rl.name}: advisory's affected set matches history "
                f"({lr.computed_range})",
                evidence=[
                    f"declared: {_join(lr.declared_affected) or 'none'}",
                    f"actual: {_join(lr.actual_affected) or 'none'}",
                ],
                line=rl.name,
            )
        )


def _join(tags: list[str]) -> str:
    if len(tags) <= 4:
        return ", ".join(tags)
    return f"{', '.join(tags[:3])} … ({len(tags)} releases)"


def _check_claimed_fix_versions(
    v: Verification,
    advisory: Advisory,
    universe: Universe,
    fixes: list[FixCommit],
    actual: _Actual,
    any_fix: bool,
) -> None:
    claimed = [c for c in advisory.fixed_versions if c.version is not None]
    if not claimed:
        return
    if not any_fix:
        for c in claimed:
            assert c.version is not None
            v.findings.append(
                Finding(
                    FindingKind.UNVERIFIED,
                    "warning",
                    f"advisory says fixed in {c.version.raw}, but no fix commit is "
                    f"available to confirm the claim against history",
                    evidence=[c.evidence[:200]],
                    version=c.version.raw,
                )
            )
        return

    for c in claimed:
        assert c.version is not None
        matching = [r for r in universe.releases if r.version == c.version]
        if not matching:
            # The claimed version may simply not be tagged; say so precisely.
            newer = [r for r in universe.releases if r.version > c.version]
            v.findings.append(
                Finding(
                    FindingKind.UNVERIFIED,
                    "warning",
                    f"advisory says fixed in {c.version.raw}, but no release tag has "
                    f"that version"
                    + (
                        f"; the next release in the repository is {min(newer, key=lambda r: r.version).tag}"
                        if newer
                        else ""
                    ),
                    evidence=[c.evidence[:200]],
                    version=c.version.raw,
                )
            )
            continue
        rel = min(matching, key=lambda r: r.tag)
        fixers = actual.fixed_by.get(rel.tag, [])
        if fixers:
            v.findings.append(
                Finding(
                    FindingKind.FIX_CONFIRMED,
                    "info",
                    f"fix confirmed in {rel.tag} on line {rel.line}",
                    evidence=_evidence_for(fixers),
                    version=rel.tag,
                    line=rel.line,
                    commit=fixers[0].sha,
                )
            )
            continue
        # Not fixed at the claimed version: find where the line *is* fixed.
        line = rel.line
        line_fixed = [
            r for r in universe.lines[line].releases if r.tag in actual.fixed_by
        ]
        earlier = [r for r in line_fixed if r.version < rel.version]
        if earlier:
            first = min(earlier, key=lambda r: r.version)
            v.findings.append(
                Finding(
                    FindingKind.FIX_REACHES_EARLIER,
                    "warning",
                    f"advisory says fixed in {rel.tag}, but the fix is already in "
                    f"{first.tag}; the stated fix version is too high",
                    evidence=_evidence_for(actual.fixed_by[first.tag]),
                    version=rel.tag,
                    line=line,
                    commit=actual.fixed_by[first.tag][0].sha,
                )
            )
        else:
            candidate = min(line_fixed, key=lambda r: r.version) if line_fixed else None
            v.findings.append(
                Finding(
                    FindingKind.FIX_NOT_IN_CLAIMED_RELEASE,
                    "error",
                    f"advisory says fixed in {rel.tag}, but that release does not "
                    f"contain the fix"
                    + (f"; the first fixed release on line {line} is {candidate.tag}" if candidate else ""),
                    evidence=[
                        f"{rel.tag} does not contain the fix commit "
                        f"(git merge-base --is-ancestor)",
                    ] + _evidence_for(fixes, limit=2),
                    version=rel.tag,
                    line=line,
                    commit=fixes[0].sha if fixes else "",
                )
            )


def _evidence_for(fixes: list[FixCommit], limit: int = 4) -> list[str]:
    out: list[str] = []
    for f in fixes:
        out.extend(f.evidence)
        if len(out) >= limit:
            break
    return out[:limit]


def _check_unreleased_fix(v: Verification, fixes: list[FixCommit], any_fix: bool) -> None:
    if not any_fix:
        return
    for f in fixes:
        if f.present and not f.tags and not f.earliest:
            v.findings.append(
                Finding(
                    FindingKind.FIX_NEVER_RELEASED,
                    "warning",
                    f"fix commit {f.sha[:10]} is on a branch but in no release tag: "
                    f"every released version is affected",
                    evidence=list(f.evidence),
                    commit=f.sha,
                )
            )


def _resolved_range(
    advisory: Advisory,
    universe: Universe,
    actual: _Actual,
    any_fix: bool,
    declared_affected: set[str],
) -> VersionSet:
    """The best-supported affected set.

    With history evidence, each line contributes the interval from its oldest
    release (or the introduced version, if later) to its first fixed release.
    Without it, the advisory's own claim stands, and the notes say so.
    """
    if not any_fix:
        return advisory.declared_affected
    out = VersionSet()
    for line, rl in universe.lines.items():
        affected = [r for r in rl.releases if actual.is_affected(r)]
        if not affected:
            continue
        fixed = [r for r in rl.releases if actual.is_fixed(r)]
        lo = affected[0].version
        if fixed:
            hi = min(fixed, key=lambda r: r.version).version
            out = out.union(VersionSet([Interval(lo=lo, lo_inc=True, hi=hi, hi_inc=False)]))
        else:
            out = out.union(VersionSet([Interval(lo=lo, lo_inc=True)]))
    if out.is_empty:
        return advisory.declared_affected
    return out


def _score(
    v: Verification,
    advisory: Advisory,
    fixes: list[FixCommit],
    any_fix: bool,
    universe: Universe,
) -> float:
    claims = [c for c in advisory.claims if c.kind is not ClaimKind.UNPARSED]
    if not claims:
        return 0.0

    # Start from how well the text itself parsed, then let repo evidence move
    # the number.  Errors subtract hard; agreement adds.
    score = 0.45 * sum(c.confidence for c in claims) / len(claims)

    present = [f for f in fixes if f.present]
    if present:
        score += 0.20
        if any(f.tags for f in present):
            score += 0.10
        if any(f.source == "discovered" for f in present):
            score -= 0.08
    matched = sum(1 for f in v.findings if f.kind is FindingKind.RANGE_MATCHES)
    lines = max(1, len(v.lines))
    score += 0.20 * (matched / lines)
    if any(f.kind is FindingKind.BACKPORT_FOUND for f in v.findings):
        score += 0.03

    for f in v.findings:
        if f.severity == "error":
            score -= 0.20
        elif f.kind is FindingKind.UNVERIFIED:
            score -= 0.03
        elif f.kind is FindingKind.FIX_REACHES_EARLIER:
            score -= 0.06
        elif f.kind is FindingKind.FIX_NEVER_RELEASED:
            # The fix exists but no user can run it: the affected set is still
            # bounded by a commit that shipped nowhere.
            score -= 0.12
        elif f.kind is FindingKind.BACKPORT_MISSING:
            score -= 0.05

    if not any_fix:
        score = min(score, 0.5)
    if any(f.kind is FindingKind.ADVISORY_CONTRADICTION for f in v.findings):
        score -= 0.10
    return max(0.02, min(0.99, score))


def _notes(
    v: Verification,
    advisory: Advisory,
    universe: Universe,
    fixes: list[FixCommit],
    any_fix: bool,
    backports: dict[str, list[tuple[Release, str]]],
) -> list[str]:
    notes: list[str] = []
    if not fixes:
        notes.append(
            "advisory named no fix commit and search found none: the affected "
            "range rests on the advisory text alone"
        )
    elif not any_fix:
        notes.append(
            "none of the named fix commits exist in this repository: the range "
            "could not be checked against history"
        )
    else:
        unreleased = [f for f in fixes if f.present and not f.tags]
        if unreleased:
            notes.append(
                f"{len(unreleased)} fix commit(s) are not in any release tag: the "
                f"fix exists only on a branch, so released versions stay affected"
            )
        if backports:
            notes.append(
                "backports were matched by patch-id, not by hash: the fix reached "
                "maintenance lines as separate commits"
            )
        notes.append(
            "affectedness assumes every release before the fix on a line is "
            "vulnerable unless the advisory gives an introduced version"
        )
    if universe.unparsed_tags:
        names = ", ".join(t.name for t in universe.unparsed_tags[:5])
        notes.append(
            f"{len(universe.unparsed_tags)} tag(s) could not be parsed as versions "
            f"and were excluded ({names})"
        )
    for w in advisory.warnings:
        notes.append(f"advisory: {w}")
    return notes
