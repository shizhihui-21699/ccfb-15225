"""Structured representation of an advisory's claims."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..versions import Version, VersionSet


class ClaimKind(str, Enum):
    AFFECTED_RANGE = "affected_range"
    AFFECTED_ALL = "affected_all"
    NOT_AFFECTED = "not_affected"
    FIXED_VERSION = "fixed_version"
    FIXED_COMMIT = "fixed_commit"
    INTRODUCED_VERSION = "introduced_version"
    UNPARSED = "unparsed"


@dataclass
class Claim:
    """One atomic statement extracted from the advisory text.

    ``evidence`` is the exact substring the claim came from, so every output can
    be traced back to the sentence that produced it.
    """

    kind: ClaimKind
    evidence: str
    confidence: float
    span: tuple[int, int] = (0, 0)
    version_set: VersionSet | None = None
    version: Version | None = None
    commit: str = ""
    branch_hint: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "kind": self.kind.value,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 3),
            "span": list(self.span),
        }
        if self.version_set is not None:
            if self.version_set.all_versions and not self.version_set.intervals:
                d["range"] = "all"
            else:
                d["range"] = self.version_set.describe()
                d["range_detail"] = self.version_set.to_dict()
        if self.version is not None:
            d["version"] = self.version.raw
        if self.commit:
            d["commit"] = self.commit
        if self.branch_hint:
            d["branch_hint"] = self.branch_hint
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class Advisory:
    advisory_id: str
    text: str
    package: str = ""
    repo_url: str = ""
    claims: list[Claim] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # -- convenience views ---------------------------------------------
    def of_kind(self, kind: ClaimKind) -> list[Claim]:
        return [c for c in self.claims if c.kind is kind]

    @property
    def affected_claims(self) -> list[Claim]:
        return [
            c
            for c in self.claims
            if c.kind in {ClaimKind.AFFECTED_RANGE, ClaimKind.AFFECTED_ALL}
        ]

    @property
    def fixed_versions(self) -> list[Claim]:
        return self.of_kind(ClaimKind.FIXED_VERSION)

    @property
    def fixed_commits(self) -> list[Claim]:
        return self.of_kind(ClaimKind.FIXED_COMMIT)

    @property
    def declared_affected(self) -> VersionSet:
        """Union of every affected claim, before any repository evidence."""
        out = VersionSet()
        for c in self.affected_claims:
            if c.version_set is not None:
                out = out.union(c.version_set)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "package": self.package,
            "repo_url": self.repo_url,
            "warnings": list(self.warnings),
            "claims": [c.to_dict() for c in self.claims],
        }
