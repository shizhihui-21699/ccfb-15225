"""Affected-version sets expressed as unions of ordered intervals.

A vulnerability's affected set is rarely a single contiguous range: advisories
say "before 2.3.4", "1.0.x through 1.4.x", ">= 3.0, < 3.2.1 except 3.1.7", or
just "all versions".  :class:`VersionSet` models all of these as a canonical
union of half-open/closed intervals so that membership questions — the only
questions that matter for verification — have exact answers.

Closed and open bounds are preserved because the difference between
``< 2.0`` and ``<= 2.0`` is exactly the kind of mistake a human transcription
introduces.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .version import Version

__all__ = [
    "Interval",
    "VersionSet",
    "EMPTY",
    "ALL",
    "IncomparableVersion",
]


class IncomparableVersion(ValueError):
    """Raised when a version cannot be ordered against a set's bounds."""


@dataclass(frozen=True)
class Interval:
    """One interval.  ``None`` means unbounded on that side.

    ``lo_inc`` / ``hi_inc`` say whether the bound value itself is included.
    """

    lo: Version | None = None
    lo_inc: bool = True
    hi: Version | None = None
    hi_inc: bool = False
    lo_src: str = ""
    hi_src: str = ""

    def __str__(self) -> str:
        left = "(-inf" if self.lo is None else f"{'[' if self.lo_inc else '('}{self.lo}"
        right = "+inf)" if self.hi is None else f"{self.hi}{']' if self.hi_inc else ')'}"
        return f"{left}, {right}"

    def contains(self, v: Version) -> bool:
        if self.lo is not None:
            c = _cmp_checked(v, self.lo)
            if c < 0 or (c == 0 and not self.lo_inc):
                return False
        if self.hi is not None:
            c = _cmp_checked(v, self.hi)
            if c > 0 or (c == 0 and not self.hi_inc):
                return False
        return True

    def is_empty(self) -> bool:
        if self.lo is None or self.hi is None:
            return False
        c = _cmp_checked(self.lo, self.hi)
        return c > 0 or (c == 0 and not (self.lo_inc and self.hi_inc))


def _cmp_checked(a: object, b: object) -> int:
    if not isinstance(a, Version) or not isinstance(b, Version):
        raise IncomparableVersion(f"cannot compare {a!r} with {b!r}")
    return a._cmp(b)


def _lower_sort_key(iv: Interval):
    """Unbounded-low intervals first, then by lower bound text."""
    if iv.lo is None:
        return (0, "")
    return (1, iv.lo.raw)


def _touches(a: Interval, b: Interval) -> bool:
    """True when ``b`` starts at or before ``a``'s upper end (overlap or adjacent).

    Adjacency merges only when at least one side includes the shared point;
    two open bounds on the same value leave a real gap of one version.
    """
    if a.hi is None or b.lo is None:
        return True
    c = _cmp_checked(b.lo, a.hi)
    if c < 0:
        return True
    if c == 0:
        return a.hi_inc or b.lo_inc
    return False


def _merge(a: Interval, b: Interval) -> Interval:
    hi, hi_inc, hi_src = a.hi, a.hi_inc, a.hi_src
    if b.hi is None or (a.hi is not None and _cmp_checked(b.hi, a.hi) > 0):
        hi, hi_inc, hi_src = b.hi, b.hi_inc, b.hi_src
    lo, lo_inc, lo_src = a.lo, a.lo_inc, a.lo_src
    if b.lo is None or (a.lo is not None and _cmp_checked(b.lo, a.lo) < 0):
        lo, lo_inc, lo_src = b.lo, b.lo_inc, b.lo_src
    return Interval(lo, lo_inc, hi, hi_inc, lo_src, hi_src)


def _intersect(a: Interval, b: Interval) -> Interval | None:
    lo, lo_inc, lo_src = a.lo, a.lo_inc, a.lo_src
    if b.lo is not None:
        if lo is None:
            lo, lo_inc, lo_src = b.lo, b.lo_inc, b.lo_src
        else:
            c = _cmp_checked(b.lo, lo)
            if c > 0:
                lo, lo_inc, lo_src = b.lo, b.lo_inc, b.lo_src
            elif c == 0:
                lo_inc = lo_inc and b.lo_inc
    hi, hi_inc, hi_src = a.hi, a.hi_inc, a.hi_src
    if b.hi is not None:
        if hi is None:
            hi, hi_inc, hi_src = b.hi, b.hi_inc, b.hi_src
        else:
            c = _cmp_checked(b.hi, hi)
            if c < 0:
                hi, hi_inc, hi_src = b.hi, b.hi_inc, b.hi_src
            elif c == 0:
                hi_inc = hi_inc and b.hi_inc
    out = Interval(lo, lo_inc, hi, hi_inc, lo_src, hi_src)
    return None if out.is_empty() else out


def _join_note(a: str, b: str) -> str:
    return f"{a}; {b}" if a and b else (a or b)


class VersionSet:
    """Canonical union of disjoint, sorted, non-adjacent intervals."""

    __slots__ = ("_ivs", "all_versions", "note")

    def __init__(
        self,
        intervals: Iterable[Interval] = (),
        *,
        all_versions: bool = False,
        note: str = "",
    ) -> None:
        self.all_versions = all_versions
        self.note = note
        self._ivs = self._canonicalise(list(intervals))

    @classmethod
    def everything(cls, note: str = "") -> "VersionSet":
        return cls([], all_versions=True, note=note)

    @classmethod
    def point(cls, v: Version) -> "VersionSet":
        return cls([Interval(lo=v, lo_inc=True, hi=v, hi_inc=True)])

    def _canonicalise(self, ivs: list[Interval]) -> list[Interval]:
        ivs = [iv for iv in ivs if not iv.is_empty()]
        if self.all_versions:
            return []
        if not ivs:
            return []
        ivs.sort(key=_lower_sort_key)
        out: list[Interval] = []
        for iv in ivs:
            if out and _touches(out[-1], iv):
                out[-1] = _merge(out[-1], iv)
            else:
                out.append(iv)
        return out

    # -- queries --------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        return not self.all_versions and not self._ivs

    @property
    def intervals(self) -> tuple[Interval, ...]:
        if self.all_versions and not self._ivs:
            return (Interval(),)
        return tuple(self._ivs)

    def contains(self, v: Version) -> bool:
        if self.all_versions:
            return True
        return any(iv.contains(v) for iv in self._ivs)

    def __contains__(self, v: object) -> bool:
        return isinstance(v, Version) and self.contains(v)

    # -- algebra --------------------------------------------------------
    def union(self, other: "VersionSet") -> "VersionSet":
        note = _join_note(self.note, other.note)
        if self.all_versions or other.all_versions:
            return VersionSet([], all_versions=True, note=note)
        return VersionSet(self._ivs + other._ivs, note=note)

    def intersection(self, other: "VersionSet") -> "VersionSet":
        note = _join_note(self.note, other.note)
        if self.all_versions:
            return VersionSet(other._ivs, all_versions=other.all_versions, note=note)
        if other.all_versions:
            return VersionSet(self._ivs, all_versions=False, note=note)
        out: list[Interval] = []
        for a in self._ivs:
            for b in other._ivs:
                inter = _intersect(a, b)
                if inter is not None:
                    out.append(inter)
        return VersionSet(out, note=note)

    def complement(self) -> "VersionSet":
        if self.all_versions:
            return VersionSet([])
        if not self._ivs:
            return VersionSet.everything()
        out: list[Interval] = []
        prev_hi: Version | None = None
        prev_hi_inc = not self._ivs[0].lo_inc
        for iv in self._ivs:
            if iv.lo is not None:
                out.append(
                    Interval(lo=prev_hi, lo_inc=prev_hi_inc, hi=iv.lo, hi_inc=not iv.lo_inc)
                )
            prev_hi, prev_hi_inc = iv.hi, not iv.hi_inc
        out.append(Interval(lo=prev_hi, lo_inc=prev_hi_inc))
        return VersionSet(out)

    def difference(self, other: "VersionSet") -> "VersionSet":
        return self.intersection(other.complement())

    # -- presentation ---------------------------------------------------
    def describe(self) -> str:
        if self.all_versions:
            return "all versions"
        if not self._ivs:
            return "no versions"
        return " | ".join(str(iv) for iv in self._ivs)

    def __repr__(self) -> str:
        return f"VersionSet({self.describe()})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VersionSet):
            return NotImplemented
        if self.all_versions != other.all_versions:
            return False
        return all(a == b for a, b in zip(self._ivs, other._ivs)) and len(
            self._ivs
        ) == len(other._ivs)

    def __hash__(self) -> int:
        return hash((self.all_versions, tuple(str(iv) for iv in self._ivs)))

    def to_dict(self) -> dict:
        return {
            "all_versions": self.all_versions,
            "note": self.note,
            "intervals": [
                {
                    "lo": iv.lo.raw if iv.lo else None,
                    "lo_inc": iv.lo_inc,
                    "hi": iv.hi.raw if iv.hi else None,
                    "hi_inc": iv.hi_inc,
                    "lo_src": iv.lo_src,
                    "hi_src": iv.hi_src,
                }
                for iv in self._ivs
            ],
        }


EMPTY = VersionSet()
ALL = VersionSet.everything()
