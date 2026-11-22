"""Scheme-tolerant version parsing and ordering.

Advisories and repositories rarely agree on one version scheme: one program
may ship ``1.2.3``, ``1.2.4.Final``, ``2023.10.1``, ``2:1.0-3ubuntu1`` or
``v1.2.3-rc.1``.  This module turns all of them into one comparable form that
keeps the distinctions that matter for vulnerability ranges:

* pre-releases sort *before* the matching release (``1.2.3-rc1 < 1.2.3``);
* post releases sort *after* it (``1.2.3.post1 > 1.2.3``);
* Maven qualifiers such as ``.Final`` / ``.RELEASE``/``.GA`` mean "the release";
* missing components are zero padded, so ``1.2 == 1.2.0``;
* Debian ``~`` and epochs use dpkg ordering when both sides are Debian;
* build metadata (``+build7``) is ignored, as SemVer requires.

Every version keeps a *generic* view of its numeric release and qualifier
tokens.  Comparisons between different schemes use that generic view on both
sides, which keeps the ordering total and symmetric instead of falling back to
string comparison.

Everything is conservative: text that cannot be parsed raises
:class:`InvalidVersion`, so callers can mark input unverifiable instead of
silently guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

__all__ = [
    "InvalidVersion",
    "Version",
    "detect_scheme",
    "extract_version_from_tag",
    "VERSION_TOKEN",
]


class InvalidVersion(ValueError):
    """Raised when text cannot be interpreted as a version."""


# A bounded pattern for "a version-looking token" inside prose.  It requires a
# digit, so words never match, and stops at whitespace/punctuation so trailing
# prose is not swallowed.  The optional suffix covers SemVer pre-releases,
# Debian revisions, Maven qualifiers and Go pseudo-versions.
_NUM = r"\d+"
# A version token must end with an alphanumeric so that sentence punctuation
# ("before 2.4.0.") is not swallowed, and so that "1.2.3." cannot be read as
# "1.2" plus a Maven-style ".3" qualifier.
_VERSION_BODY = (
    rf"{_NUM}(?:\.{_NUM})*(?:\.(?:[xX*]))?"
    r"(?:[-_.+~][0-9A-Za-z](?:[0-9A-Za-z.+~_-]*[0-9A-Za-z])?)?"
)
VERSION_TOKEN = rf"(?:\d+:)?[vV]?{_VERSION_BODY}"

# Qualifier words grouped by ordering stage.  Stage 5 is the release itself,
# so anything below sorts before it and anything above sorts after.
_PRE_RELEASE_RANK = {
    "dev": 0,
    "snapshot": 0,
    "nightly": 0,
    "git": 0,
    "a": 1,
    "alpha": 1,
    "b": 2,
    "beta": 2,
    "m": 2,
    "milestone": 2,
    "rc": 3,
    "cr": 3,
    "pre": 3,
    "preview": 3,
    "ea": 3,
    "eap": 3,
}
_RELEASE_WORDS = {"final", "ga", "release", "stable", "sp0", "linux"}
_POST_RELEASE_RANK = {"post": 6, "sp": 6, "hotfix": 6, "patch": 6, "r": 6, "p": 6}

_RELEASE_STAGE = 5
_UNKNOWN_QUALIFIER_STAGE = 4

_RUN_RE = re.compile(r"\d+|[A-Za-z]+")
_TAG_PREFIX_RE = re.compile(
    r"^(?:refs/tags/)?(?:release[-/_]|rel[-/_]|version[-/_]|tag[-/_])",
    re.I,
)


@dataclass
class _Parsed:
    epoch: int = 0
    release: tuple[int, ...] = ()
    stage: int = _RELEASE_STAGE
    qual_tokens: tuple[tuple[int, int, str], ...] = ()
    scheme: str = "generic"
    deb_upstream: str = ""
    deb_revision: str = ""


def detect_scheme(version_strings: list[str]) -> str:
    """Guess the predominant scheme of a project from its version strings."""
    vals = [s for s in version_strings if s]
    if not vals:
        return "generic"
    lowered = [v.lower() for v in vals]
    if any(re.match(r"^\d+:", v) for v in lowered) or any(
        "~" in v or re.search(r"-\d+(\+deb|ubuntu)", v) for v in lowered
    ):
        return "debian"
    if any(re.search(r"\.(final|release|ga|snapshot)\b", v) for v in lowered):
        return "maven"
    firsts = []
    for v in lowered:
        m = re.match(r"^v?(\d+)", v)
        if m:
            firsts.append(int(m.group(1)))
    if firsts and sum(1 for f in firsts if f >= 2000) * 2 >= len(firsts):
        return "calver"
    return "semver"


def _token_key(tokens: tuple[str, ...]) -> tuple[tuple[int, int, str], ...]:
    out = []
    for tok in tokens:
        if tok.isdigit():
            out.append((0, int(tok), ""))
        else:
            out.append((1, 0, tok.lower()))
    return tuple(out)


def _qualifier_stage_and_tokens(
    tokens: tuple[str, ...],
) -> tuple[int, tuple[tuple[int, int, str], ...]]:
    """Translate qualifier tokens into (stage, comparable tokens).

    ``1.2.3-rc.1`` -> tokens ``("rc", "1")`` -> stage 3.
    ``1.2.3.Final`` -> ``("final",)`` -> stage 5 with no tokens (== release).
    ``1.2.3.sp1`` -> ``("sp", "1")`` -> stage 6.
    Unknown qualifiers land in stage 4, i.e. before the release.
    """
    if not tokens:
        return _RELEASE_STAGE, ()
    head = tokens[0].lower()
    if head in _RELEASE_WORDS:
        return _RELEASE_STAGE, ()
    if head in _PRE_RELEASE_RANK:
        stage = _PRE_RELEASE_RANK[head]
        rest = tokens[1:]
        return stage, (_token_key(rest) if rest else ())
    if head in _POST_RELEASE_RANK:
        return _POST_RELEASE_RANK[head], _token_key(tokens[1:])
    # Unknown alphabetic qualifier: SemVer says a hyphenated identifier is a
    # pre-release, so sort it before the release.
    return _UNKNOWN_QUALIFIER_STAGE, _token_key(tokens)


def _parse_generic(body: str) -> _Parsed:
    runs = list(_RUN_RE.finditer(body))
    if not runs or not runs[0].group(0).isdigit():
        raise InvalidVersion(body)
    release: list[int] = []
    idx = 0
    while idx < len(runs) and runs[idx].group(0).isdigit():
        release.append(int(runs[idx].group(0)))
        idx += 1
    qual_tokens = tuple(r.group(0) for r in runs[idx:])
    stage, keys = _qualifier_stage_and_tokens(qual_tokens)
    return _Parsed(
        release=tuple(release),
        stage=stage,
        qual_tokens=keys,
        scheme="generic",
    )


def _norm(body: str) -> str:
    """Strip noise that should not affect ordering of the *release* number."""
    body = re.sub(r"^[vV](?=\d)", "", body)
    body = re.sub(r"^(?:release|rel|version|tag)[-/_]?", "", body, flags=re.I)
    # SemVer build metadata and PEP 440 local versions never affect precedence.
    body = re.sub(r"\+[0-9A-Za-z][0-9A-Za-z.+_-]*$", "", body)
    return body


def _split_debian(body: str) -> tuple[int, str, str]:
    epoch = 0
    m = re.match(r"^(\d+):(.*)$", body, re.S)
    if m:
        epoch = int(m.group(1))
        body = m.group(2)
    if "-" in body:
        upstream, revision = body.rsplit("-", 1)
        return epoch, upstream, revision
    return epoch, body, "0"


def _deb_order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isdigit():
        return 0
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's version comparison algorithm."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < la and not a[i].isdigit() else 0
            bc = _deb_order(b[j]) if j < lb and not b[j].isdigit() else 0
            if ac != bc:
                return -1 if ac < bc else 1
            if i < la and not a[i].isdigit():
                i += 1
            if j < lb and not b[j].isdigit():
                j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        first_diff = 0
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _pad(release: tuple[int, ...], n: int = 8) -> tuple[int, ...]:
    return release + (0,) * (n - len(release))


def _generic_cmp(x: _Parsed, y: _Parsed) -> int:
    if x.epoch != y.epoch:
        return -1 if x.epoch < y.epoch else 1
    rx, ry = _pad(x.release), _pad(y.release)
    if rx != ry:
        return -1 if rx < ry else 1
    if x.stage != y.stage:
        return -1 if x.stage < y.stage else 1
    if x.qual_tokens != y.qual_tokens:
        return -1 if x.qual_tokens < y.qual_tokens else 1
    return 0


_DEBIAN_HINT = re.compile(r"^\d+:|~|-\d")


def _looks_debian(body: str) -> bool:
    r"""Debian-style versions use epochs, ``~`` and ``-revision``.

    ``-\d`` deliberately requires a digit after the hyphen: ``1.0-3ubuntu1``
    is a revision, whereas ``1.2.3-rc1`` is a SemVer pre-release.
    """
    return bool(_DEBIAN_HINT.search(body))


@total_ordering
class Version:
    """A parsed version with a total order across common schemes."""

    __slots__ = ("raw", "scheme", "_p", "_g")

    def __init__(self, text: str, scheme: str = "auto") -> None:
        raw = (text or "").strip().strip("()[]<>\"'").rstrip(".,;:")
        raw = raw.strip()
        body = _norm(raw)
        if not body or not re.match(r"^\d", re.sub(r"^\d+:", "", body)):
            raise InvalidVersion(text)
        self.raw = raw

        if scheme in {"auto", None}:
            scheme = "debian" if _looks_debian(body) else "generic"
        self.scheme = scheme

        # The generic view is always available (every version we accept starts
        # with a digit), which makes cross-scheme comparisons possible.
        epoch, rest = 0, body
        m = re.match(r"^(\d+):(.*)$", body, re.S)
        if m:
            epoch, rest = int(m.group(1)), m.group(2)
        self._g = _parse_generic(rest)
        self._g.epoch = epoch

        if scheme == "debian":
            d_epoch, upstream, revision = _split_debian(body)
            if not upstream or not upstream[0].isdigit():
                raise InvalidVersion(text)
            self._p = _Parsed(
                epoch=d_epoch,
                release=self._g.release,
                deb_upstream=upstream,
                deb_revision=revision,
                scheme="debian",
            )
        else:
            self._p = self._g

    # -- comparison -----------------------------------------------------
    def _cmp(self, other: "Version") -> int:
        if not isinstance(other, Version):
            return NotImplemented
        if self._p.scheme == "debian" and other._p.scheme == "debian":
            a, b = self._p, other._p
            if a.epoch != b.epoch:
                return -1 if a.epoch < b.epoch else 1
            c = _verrevcmp(a.deb_upstream, b.deb_upstream)
            if c:
                return c
            return _verrevcmp(a.deb_revision, b.deb_revision)
        return _generic_cmp(self._g, other._g)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._cmp(other) == 0

    def __lt__(self, other: "Version") -> bool:
        return self._cmp(other) < 0

    def __hash__(self) -> int:
        p = self._p
        if p.scheme == "debian":
            return hash(("deb", p.epoch, p.deb_upstream, p.deb_revision))
        g = self._g
        stripped = list(g.release)
        while len(stripped) > 1 and stripped[-1] == 0:
            stripped.pop()
        return hash(("gen", g.epoch, tuple(stripped), g.stage, g.qual_tokens))

    # -- informative properties -----------------------------------------
    @property
    def release(self) -> tuple[int, ...]:
        return self._g.release

    @property
    def epoch(self) -> int:
        return self._g.epoch

    @property
    def is_prerelease(self) -> bool:
        return self._g.stage < _RELEASE_STAGE

    @property
    def is_snapshot(self) -> bool:
        return self._g.stage == 0

    @property
    def line(self) -> tuple[int, ...]:
        """A coarse release line (major, minor), used to group versions."""
        rel = list(self._g.release)
        while len(rel) > 1 and rel[-1] == 0:
            rel.pop()
        return tuple(rel[:2])

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"

    def __str__(self) -> str:
        return self.raw


def extract_version_from_tag(
    tag: str, project_names: tuple[str, ...] = ()
) -> Version | None:
    """Turn a git tag name into a Version, or ``None`` if it is not one.

    Handles ``v1.2.3``, ``release-1.2.3``, ``acme-widget-1.2.3`` and plain
    ``1.2.3``.  Tags without a leading digit after the prefix are rejected
    (``nightly``, ``latest``), which keeps moving tags out of the universe.
    """
    name = tag.strip()
    for _ in range(3):
        before = name
        name = _TAG_PREFIX_RE.sub("", name)
        if name == before:
            break
    name = re.sub(r"^[vV](?=\d)", "", name)
    for proj in sorted(project_names, key=len, reverse=True):
        for sep in ("-", "/", "_"):
            prefix = f"{proj}{sep}"
            if name.lower().startswith(prefix.lower()):
                name = name[len(prefix) :]
                break
    name = name.split("^{}", 1)[0].strip()
    if not re.match(r"^\d", name):
        return None
    try:
        return Version(name)
    except InvalidVersion:
        return None
