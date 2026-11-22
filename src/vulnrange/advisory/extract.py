"""Extract affected-version and fix claims from free-form advisory prose.

Advisory prose is not a grammar, so this module is deliberately a set of
ordered, narrow patterns sharing one small set of *semantics*.  Two things it
will not do:

* invent a range when the text does not state one (it records an explicit,
  low-confidence inference instead and flags it in ``Advisory.warnings``);
* lose provenance.  Every claim carries the exact sentence it came from and a
  character span, so a human reviewer can check it in seconds.

Handled shapes, roughly by frequency:

* ``all releases before 2.4.0`` / ``2.4.0 and earlier`` / ``up to and including``
* ``>= 3.0.0, < 3.2.1`` / ``from 3.0.0 to 3.2.1``
* ``1.4.x`` / ``the 1.6 branch`` release-line wildcards
* ``Affected versions:`` / ``Fixed in:`` / ``Not affected:`` section lists
* ``fixed in commit 3f2a1bc`` and ``upgrade to 3.2.1``
* the same statements written in Chinese (``2.0 之前的所有版本``)

Structured advisories list versions under headings; free-form advisories state
them inline.  Both are handled, and a heading's context only applies to a line
that does not carry its own explicit statement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Match

from ..versions import VERSION_TOKEN, InvalidVersion, Version, VersionSet
from ..versions.ranges import Interval
from .model import Advisory, Claim, ClaimKind

__all__ = ["extract_advisory", "segments", "split_sentences"]

_V = VERSION_TOKEN
_VRE = re.compile(_V)
_MASK = "\x00"


def _v(text: str) -> Version:
    return Version(text)


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------
_CVE_RE = re.compile(r"\b(?:CVE|GHSA|OSV|ZDI|GSD|JVNDB|CNVD|VU|CWE)-\S+", re.I)
_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
_URL_RE = re.compile(r"https?://[^\s<>()\"'一-鿿]+|\bwww\.[^\s<>()\"']+")
_ISSUE_RE = re.compile(r"(?:#|\bissue\s+|\bbug\s+|\bticket\s+)\d{2,}\b", re.I)
_HEX_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
_COMMIT_CTX_RE = re.compile(
    r"\b(?:commit|commits|changeset|revision|rev|sha|git|patch|patches|fix(?:ed)?|"
    r"bump|merge|cherry-pick)\b[^.]{0,32}$"
    r"|(?:提交|补丁|修订)\s*$",
    re.I,
)


def _mask(text: str) -> tuple[str, list[tuple[int, int, str]]]:
    """Blank identifiers/dates so version matching cannot see them.

    The masked string has the same length as the input, so every span stays
    valid against the original.  Commit hashes are stripped here too — they
    are hex, which the version pattern would otherwise partly match — and
    returned so the commit rules can run on the original text.
    """
    chars = list(text)
    commits: list[tuple[int, int, str]] = []

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            chars[k] = _MASK

    for rx in (_CVE_RE, _DATE_RE, _URL_RE, _ISSUE_RE):
        for m in rx.finditer(text):
            blank(*m.span())

    for m in _HEX_RE.finditer(text):
        tok = m.group(0)
        has_alpha = any(ch in "abcdef" for ch in tok)
        near = text[max(0, m.start() - 48) : m.start()]
        if has_alpha or _COMMIT_CTX_RE.search(near):
            commits.append((m.start(), m.end(), tok))
            blank(*m.span())
    return "".join(chars), commits


# ---------------------------------------------------------------------------
# Segmentation
# ---------------------------------------------------------------------------
_ABBREV = re.compile(
    r"\b(?:e\.g|i\.e|vs|cf|etc|approx|no|ver|v|fig|sec|ref|inc|ltd|dr|mr|ms)\.$", re.I
)
_BULLET_RE = re.compile(r"^\s*(?:[-*•◦]|\d+[.)]|\(\d+\))\s+")
_HEADING_MD = re.compile(r"^\s*#{1,6}\s+")
_HEADING_COLON = re.compile(r"^(?P<h>[A-Za-z][A-Za-z0-9 /_'()+-]{2,60})\s*[:：]\s*")

_AFFECTED_HDR = re.compile(r"\b(?:affected|vulnerable|impacted)\b", re.I)
_FIXED_HDR = re.compile(
    r"\b(?:fixed|patched|resolution|remediation|solution|mitigation|upgrade|update|"
    r"workaround|patched\s+versions?)\b|修复|解决|缓解|升级",
    re.I,
)
_INTRO_HDR = re.compile(r"\b(?:introduced|regression)\b|引入", re.I)
_NOTAFF_HDR = re.compile(
    r"\b(?:not\s+affected|unaffected|not\s+vulnerable)\b|不受影响", re.I
)
_HEADING_WORDS = re.compile(r"\b(?:versions?|releases?|tags?|branches|series)\b|版本", re.I)

# A line like "Affected versions: 1.0.0, 1.0.1" is a heading and a value.  A
# sentence like "All versions are affected: the runner calls eval" also has a
# colon and the word "versions", but it is prose and must not be split — the
# half before the colon carries the actual claim.  So the label is matched
# against the *shape* of a section label: an optional leading qualifier, a
# classification word, and an optional noun, with nothing else.
_HEADING_LABEL = re.compile(
    r"""^\s*
    (?:
        (?P<not>not\s+)?(?P<aff>affected|vulnerable|impacted)
      | (?P<fix>fixed|patched|resolved|remediation|solution|mitigation|fix)
      | (?P<intro>introduced|regression)
    )
    (?:\s+(?:versions?|releases?|tags?|branches?|series))?
    (?:\s+(?:in|of))?\s*$
    """,
    re.I | re.X,
)


def _heading_context(text: str) -> str | None:
    if _NOTAFF_HDR.search(text):
        return "not_affected"
    if _FIXED_HDR.search(text) and not _AFFECTED_HDR.search(text):
        return "fixed"
    if _INTRO_HDR.search(text):
        return "introduced"
    if _AFFECTED_HDR.search(text):
        return "affected"
    return None


@dataclass(frozen=True)
class Segment:
    """One line of advisory text with its offset and inherited section context."""

    offset: int
    text: str
    context: str | None
    heading: str = ""


def _strip_bullet(s: str) -> tuple[str, int]:
    m = _BULLET_RE.match(s)
    if not m:
        return s, 0
    return s[m.end() :], m.end()


def segments(text: str) -> list[Segment]:
    """Split advisory text into logical segments, carrying heading context.

    Prose is grouped into *paragraphs* rather than lines: advisories hard-wrap
    their text, so a single sentence is routinely split across two lines and a
    line-at-a-time reader turns "the 1.6 branch is / affected up to 1.6.3"
    into two unrelated fragments.  Bullets and headings stay on their own,
    because their isolation is semantic.

    Newlines inside a paragraph are replaced with spaces, so segment offsets
    remain valid against the original text.
    """
    out: list[Segment] = []
    context: str | None = None
    pos = 0
    # Pending paragraph: (absolute start, list of (start, raw line), context)
    pending: tuple[int, list[tuple[int, str]], str | None] | None = None

    def flush() -> None:
        nonlocal pending
        if pending is None:
            return
        start, lines, ctx = pending
        end = lines[-1][0] + len(lines[-1][1])
        # Pad each line out to where the next one begins, so the joined text
        # is exactly as long as the original span and every offset inside it
        # still points at the same character in the source.
        buf = [" "] * (end - start)
        for i, (lstart, lraw) in enumerate(lines):
            rel = lstart - start
            buf[rel : rel + len(lraw)] = lraw
            limit = (lines[i + 1][0] - start) if i + 1 < len(lines) else len(buf)
            for k in range(rel + len(lraw), limit):
                if buf[k] == "\n":
                    buf[k] = " "
        joined = "".join(buf)
        heading = lines[0][1].strip() if len(lines) == 1 else ""
        out.append(Segment(start, joined, ctx, heading))
        pending = None

    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            flush()
            pos += len(raw)
            continue
        body, off = _strip_bullet(stripped)
        is_bullet = off > 0

        if _HEADING_MD.match(stripped):
            flush()
            heading = _HEADING_MD.sub("", stripped).strip()
            hctx = _heading_context(heading)
            if hctx is not None:
                context = hctx
                rest = ""
                m = _HEADING_COLON.match(heading)
                if m:
                    rest = heading[m.end() :].strip()
                    heading = m.group("h")
                if rest:
                    out.append(Segment(pos + line.find(rest), rest, context, heading))
                pos += len(raw)
                continue
            if len(heading) <= 60:
                pos += len(raw)
                continue

        # "Affected versions: 1.0.0, 1.0.1" — heading and value on one line.
        m = _HEADING_COLON.match(body)
        if m and _HEADING_LABEL.match(m.group("h")):
            hctx = _heading_context(m.group("h"))
            if hctx is not None:
                flush()
                context = hctx
                rest = body[m.end() :].strip()
                if rest:
                    out.append(
                        Segment(pos + off + m.end(), rest, context, m.group("h"))
                    )
                pos += len(raw)
                continue

        # Unrecognised short sub-heading: keep the enclosing context.
        if len(body) <= 60 and body.endswith((":", "：")):
            flush()
            hctx = _heading_context(body)
            if hctx is not None:
                context = hctx
            pos += len(raw)
            continue

        if is_bullet:
            flush()
            out.append(Segment(pos + off, body, context))
            pos += len(raw)
            continue

        # A line that is *only* a version (or a comma list of them) is a list
        # item, not prose: structured advisories put one version per line
        # under "Affected versions:".  Joining such lines would turn
        # "1.0.0\n1.0.1" into the single sentence "1.0.0 1.0.1".
        if _ENUM_ONLY_RE.match(body):
            flush()
            out.append(Segment(pos + off, body, context))
            pos += len(raw)
            continue

        # Plain prose: join consecutive lines into one paragraph, but start a
        # new one when the section context changes.
        abs_start = pos + off
        if pending is not None and pending[2] != context:
            flush()
        if pending is None:
            pending = (abs_start, [(abs_start, body)], context)
        else:
            pending[1].append((abs_start, body))
        pos += len(raw)
    flush()
    return out


def split_sentences(text: str) -> list[tuple[int, str]]:
    """Split prose into (offset, sentence) pairs without disturbing offsets."""
    bounds: list[int] = [0]
    for m in re.finditer(r"(?<=[.!?;])\s+", text):
        head = text[bounds[-1] : m.start()].strip()
        if _ABBREV.search(head):
            continue
        bounds.append(m.start())
    bounds.append(len(text))
    out: list[tuple[int, str]] = []
    for a, b in zip(bounds, bounds[1:]):
        seg = text[a:b]
        lead = len(seg) - len(seg.lstrip())
        if seg.strip():
            out.append((a + lead, seg.strip()))
    return out


# ---------------------------------------------------------------------------
# Semantics: every pattern resolves to one of these, and one builder handles
# all of them.  Language-specific alternations therefore never need bespoke
# post-processing.
# ---------------------------------------------------------------------------
class Sem(str, Enum):
    UPPER = "upper"          # one version = exclusive/inclusive upper bound
    LOWER = "lower"          # one version = lower bound
    RANGE = "range"          # two versions = closed interval
    FIXED = "fixed"          # fixed version
    INTRODUCED = "introduced"
    COMMIT = "commit"        # fix commit hash
    ALL = "all"              # all versions
    LINE = "line"            # 1.4.x wildcard -> [1.4.0, 1.5.0)
    BRANCH = "branch"        # "the 1.6 branch"
    NOT_AFFECTED = "not_affected"  # version list asserted NOT affected
    FIXED_LIST = "fixed_list"      # "fixed in 2.2.0 and 1.9.10"
    LINE_LIST = "line_list"        # "2.0.x, 2.1.x"
    DISCRETE = "discrete"          # "releases 2.0.1 and 2.0.2 are affected"
    OPEN_ENDED = "open_ended"      # "all versions are affected, none fixed"


@dataclass(frozen=True)
class Rule:
    name: str
    semantics: Sem
    pattern: re.Pattern[str]
    confidence: float
    priority: int = 50
    version_groups: tuple[str, ...] = ("v",)
    second_groups: tuple[str, ...] = ()
    inclusive: bool = False          # bound includes the version (UPPER/LOWER)
    inclusive_from_match: bool = False  # read "<=" / "=<" out of the match
    # LOWER bounds need the sentence to be about exposure; a bare ">= 2.0"
    # in a changelog is not an affected range.
    needs_affected_wording: bool = False


_NEGATION = re.compile(
    r"\b(?:not|never|isn'?t|aren'?t|wasn'?t|weren'?t)\s+(?:be\s+|been\s+)?"
    r"(?:affected|vulnerable|impacted|exploitable)\b"
    r"|\b(?:does|do|did)\s+not\s+(?:affect|contain|include)\b"
    r"|\bunaffected\b|\bno\s+longer\s+(?:affected|vulnerable)\b"
    r"|不受影响|未被影响|不会受到影响",
    re.I,
)
_AFFECTED_WORDING = re.compile(
    r"\b(?:affected|vulnerable|impacted|exploitable|exposed|susceptible|"
    r"all\s+versions?|every\s+version|any\s+version)\b|受影响|存在漏洞|所有版本",
    re.I,
)

# Chinese upper-bound forms, split by inclusivity.  "2.0 之前" excludes 2.0;
# "2.0 及以下" includes it — treating them the same is a one-version error on
# exactly the boundary security teams care about.
_ZH_UPPER_EXCL = (
    r"(?P<v2>{_V})\s*(?:版本)?\s*(?:之前版本|以前版本|之前|以前)".format(_V=_V)
)
_ZH_UPPER_INCL = r"(?P<v4>{_V})\s*(?:版本)?\s*(?:及以下|以下|及以前)".format(_V=_V)
_ZH_LOWER = r"(?P<v2>{_V})\s*(?:版本)?\s*(?:及)?(?:其)?\s*(?:以上|之后|以后)".format(_V=_V)
_ZH_FIXED_A = r"(?:已)?(?:在|于)\s*(?P<v2>{_V})\s*(?:版本)?\s*(?:中|里)?\s*(?:修复|修正|解决|修补)".format(_V=_V)
_ZH_FIXED_B = r"(?:修复|修正|解决|修补)(?:于|在)\s*(?:版本\s*)?(?P<v3>{_V})".format(_V=_V)
_ZH_INTRO = r"(?P<v2>{_V})\s*(?:版本)?\s*(?:起|开始)?\s*(?:引入|存在|出现)".format(_V=_V)
_ZH_COMMIT = r"(?:修复|修正)(?:提交|commit|补丁|修订)?\s*[:：]?\s*(?P<c2>[0-9a-f]{7,40})"
_ZH_UPGRADE = r"(?:请)?(?:升级|更新)(?:到|至)\s*(?:版本\s*)?(?P<v2>{_V})".format(_V=_V)
_ZH_ALL = r"(?:所有|全部)(?:的)?(?:版本|发行版)"

_ZH_RANGE = (
    r"(?P<vz1>{a})\s*(?:版本)?\s*(?:到|至|~|-|—)\s*(?:版本\s*)?(?P<vz2>{b})".format(a=_V, b=_V)
)

_RULES: tuple[Rule, ...] = (
    # ---- fix commits ----------------------------------------------------
    Rule(
        "fixed_commit_verb",
        Sem.COMMIT,
        re.compile(
            r"\b(?:fixed|patched|corrected|addressed|resolved|remediated|mitigated)\s+"
            r"(?:in|by|with|via|as\s+of)\s+(?:the\s+)?"
            r"(?:commit|commits|changeset|revision|patch|git\s+commit)s?\s+"
            rf"(?P<c>[0-9a-f]{{7,40}})\b|{_ZH_COMMIT}",
            re.I,
        ),
        0.95,
        version_groups=("c", "c2"),
    ),
    Rule(
        "commit_verb",
        Sem.COMMIT,
        re.compile(
            r"\b(?:commit|changeset|revision)\s+(?P<c>[0-9a-f]{7,40})\b[^.]{0,48}?"
            r"\b(?:fixes|fixed|addresses|resolves|patches|mitigates)\b",
            re.I,
        ),
        0.85,
        version_groups=("c",),
    ),
    Rule(
        "commit_backport",
        Sem.COMMIT,
        re.compile(
            r"\b(?:backport(?:ed)?|cherry-picked)\b[^.]{0,48}?\b"
            r"(?:commit\s+)?(?P<c>[0-9a-f]{7,40})\b",
            re.I,
        ),
        0.8,
        version_groups=("c",),
    ),
    # ---- fixed versions -------------------------------------------------
    Rule(
        "fixed_in_version",
        Sem.FIXED,
        re.compile(
            r"\b(?:fixed|patched|corrected|resolved|addressed|remediated|mitigated|"
            r"repaired|solved)\s+(?:in|as\s+of|by|with)\s+(?:the\s+)?"
            rf"(?:release|version|tag|update)?\s*(?:v(?:ersion)?\s*)?(?P<v>{_V})\b"
            rf"|{_ZH_FIXED_A}|{_ZH_FIXED_B}",
            re.I,
        ),
        0.95,
        version_groups=("v", "v2", "v3"),
    ),
    Rule(
        "release_contains_fix",
        Sem.FIXED,
        re.compile(
            rf"\b(?:release|version|tag)\s+(?P<v>{_V})\s+(?:contains|includes|ships|"
            r"incorporates|carries)\s+(?:the\s+|a\s+)?(?:fix|patch|correction|mitigation)\b",
            re.I,
        ),
        0.9,
    ),
    Rule(
        "upgrade_to",
        Sem.FIXED,
        re.compile(
            rf"\b(?:upgrade|update|move|switch)\s+to\s+(?:version\s+|release\s+|tag\s+)?"
            rf"(?:v(?:ersion)?\s*)?(?P<v>{_V})\b|{_ZH_UPGRADE}",
            re.I,
        ),
        0.8,
        version_groups=("v", "v2"),
    ),
    Rule(
        "fixed_in_or_later",
        Sem.FIXED,
        re.compile(
            rf"\b(?:fixed|patched|addressed|resolved)\b[^.]{{0,40}}?\b(?:in|from)\s+"
            rf"(?:v(?:ersion)?\s*)?(?P<v>{_V})\s+(?:and|or)\s+(?:later|above|newer|"
            r"subsequent)\b",
            re.I,
        ),
        0.9,
    ),
    Rule(
        "already_fixed",
        Sem.FIXED,
        re.compile(
            rf"\b(?:already|was|were|is|are)\s+(?:been\s+)?(?:fixed|patched|"
            rf"corrected|addressed|resolved)\s+in\s+(?:v(?:ersion)?\s*)?(?P<v>{_V})\b",
            re.I,
        ),
        0.85,
    ),
    # "fixed in 2.2.0 and 1.9.10" — backports land on several lines at once,
    # so the version after a fix verb is often a list, not a single value.
    Rule(
        "fixed_version_list",
        Sem.FIXED_LIST,
        re.compile(
            rf"\b(?:fixed|patched|corrected|resolved|addressed|remediated|mitigated)\s+"
            rf"(?:in|as\s+of|by|with)\s+(?:the\s+)?(?:releases?|versions?|tags?)?\s*"
            rf"(?P<list>{_V}(?:\s*(?:,|and|&|、|，|和|与)\s*{_V}){{1,}})\b",
            re.I,
        ),
        0.93,
    ),
    # ---- introduced ------------------------------------------------------
    Rule(
        "introduced_in",
        Sem.INTRODUCED,
        re.compile(
            rf"\b(?:introduced|introduces|regressed|regression(?:\s+was)?\s+introduced|"
            r"first\s+appeared|present\s+since|exists?\s+since|since)\s+"
            rf"(?:in|with|by|from|as\s+of)?\s*(?:version\s+|release\s+)?"
            rf"(?:v(?:ersion)?\s*)?(?P<v>{_V})\b|{_ZH_INTRO}",
            re.I,
        ),
        0.8,
        version_groups=("v", "v2"),
    ),
    # ---- explicit "not affected" ----------------------------------------
    Rule(
        "not_affected_version",
        Sem.NOT_AFFECTED,
        re.compile(
            rf"(?P<list>{_V})\s+(?:is|are|was|were)\s+(?:not|never)\s+"
            r"(?:affected|vulnerable|impacted)\b"
            rf"|\b(?:not\s+affected|unaffected)\s*[:：]?\s*(?P<list2>{_V})",
            re.I,
        ),
        0.82,
        version_groups=("list", "list2"),
    ),
    # ---- upper bounds ----------------------------------------------------
    Rule(
        "before",
        Sem.UPPER,
        re.compile(
            r"\b(?:prior\s+to|before|earlier\s+than|older\s+than|lower\s+than|"
            r"less\s+than|preceding|up\s+to\s+but\s+not\s+including)\s+"
            rf"(?:the\s+)?(?:version\s+|release\s+|tag\s+)?(?:v(?:ersion)?\s*)?(?P<v>{_V})\b"
            rf"|{_ZH_UPPER_EXCL}",
            re.I,
        ),
        0.93,
        version_groups=("v", "v2"),
    ),
    Rule(
        "zh_upto_inclusive",
        Sem.UPPER,
        re.compile(_ZH_UPPER_INCL),
        0.9,
        version_groups=("v4",),
        inclusive=True,
    ),
    Rule(
        "and_earlier",
        Sem.UPPER,
        re.compile(
            rf"\b(?:versions?|releases?|tags?)?\s*(?P<v>{_V})\s+(?:and|or)\s+(?:all\s+)?"
            r"(?:earlier|older|previous|prior|below|down)\s*(?:versions?|releases?|tags?)?\b",
            re.I,
        ),
        0.92,
        inclusive=True,
    ),
    Rule(
        "upto_inclusive",
        Sem.UPPER,
        re.compile(
            rf"\b(?:up\s+to\s+and\s+including|including\s+all\s+versions?\s+up\s+to|"
            rf"through\s+and\s+including)\s+(?:version\s+|release\s+|tag\s+)?"
            rf"(?P<v>{_V})\b",
            re.I,
        ),
        0.92,
        inclusive=True,
    ),
    Rule(
        "upto",
        Sem.UPPER,
        re.compile(
            rf"\b(?:up\s+to|until|through|thru)\s+(?:version\s+|release\s+|tag\s+)?"
            rf"(?:v(?:ersion)?\s*)?(?P<v>{_V})\b",
            re.I,
        ),
        0.85,
        inclusive=True,
    ),
    # ---- lower bounds ----------------------------------------------------
    Rule(
        "and_later",
        Sem.LOWER,
        re.compile(
            rf"\b(?:versions?|releases?|tags?)?\s*(?P<v>{_V})\s+(?:and|or)\s+(?:all\s+)?"
            r"(?:later|newer|above|subsequent|following|higher)\s*"
            rf"(?:versions?|releases?|tags?)?\b|{_ZH_LOWER}",
            re.I,
        ),
        0.85,
        version_groups=("v", "v2"),
        inclusive=True,
        needs_affected_wording=True,
    ),
    # ---- operators -------------------------------------------------------
    Rule(
        "operator_lt",
        Sem.UPPER,
        re.compile(rf"(?:(?<=[,(\s])|^)(?:<|<=|=<)\s*(?:v(?:ersion)?\s*)?(?P<v>{_V})\b", re.I),
        0.9,
        inclusive_from_match=True,
    ),
    Rule(
        "operator_gt",
        Sem.LOWER,
        re.compile(rf"(?:(?<=[,(\s])|^)(?:>|>=|=>)\s*(?:v(?:ersion)?\s*)?(?P<v>{_V})\b", re.I),
        0.9,
        inclusive=True,
        needs_affected_wording=True,
    ),
    # ---- ranges ----------------------------------------------------------
    Rule(
        "range_through",
        Sem.RANGE,
        re.compile(
            rf"\b(?:from\s+)?(?P<v>{_V})\s+(?:through|thru|to|up\s+to|until)\s+"
            rf"(?:version\s+|release\s+|tag\s+)?(?P<v2>{_V})\b"
            rf"|{_ZH_RANGE}",
            re.I,
        ),
        0.88,
        version_groups=("v", "vz1"),
        second_groups=("v2", "vz2"),
    ),
    # ---- release lines ---------------------------------------------------
    Rule(
        "line",
        Sem.LINE,
        re.compile(r"(?<![\w.])v?(?P<v>\d+(?:\.\d+){1,3}\.(?:x|X|\*))(?![\w*])"),
        0.82,
    ),
    Rule(
        "branch_line",
        Sem.BRANCH,
        re.compile(
            r"(?<![\w.])v?(?P<v>\d+(?:\.\d+){1,2})\s*(?:\.x\b)?\s+"
            r"(?:release\s+|maintenance\s+)?(?:branch|line|series)\b",
            re.I,
        ),
        0.7,
    ),
    # "Releases 2.0.1 and 2.0.2 are affected" — exact versions, no range.
    Rule(
        "discrete_versions",
        Sem.DISCRETE,
        re.compile(
            rf"\b(?:versions?|releases?|tags?)\s+(?P<list>{_V}"
            rf"(?:\s*(?:,|and|&|、|，|和|与)\s*{_V})+)\b",
            re.I,
        ),
        0.78,
        needs_affected_wording=True,
    ),
    # ---- unqualified "all versions" -------------------------------------
    Rule(
        "all_versions_bare",
        Sem.OPEN_ENDED,
        re.compile(
            r"\b(?:all|every|any)\s+(?:(?:supported|prior|previous|known|released)\s+)?"
            r"(?:versions?|releases?)\b(?:\s+of\s+[^.,;]+)?(?=\s*(?:are\s+affected|"
            r"is\s+affected|are\s+vulnerable|are\s+impacted))"
            r"|(?:所有|全部)(?:的)?(?:版本|发行版)\s*(?:均|都)?(?:受影响|存在漏洞)",
            re.I,
        ),
        0.85,
    ),
    # ---- all versions ----------------------------------------------------
    Rule(
        "all_versions",
        Sem.ALL,
        re.compile(
            r"\b(?:all|every|any)\s+(?:supported\s+|prior\s+|previous\s+|known\s+|"
            rf"released\s+)?(?:versions?|releases?)\b|{_ZH_ALL}",
            re.I,
        ),
        0.85,
    ),
)

_ENUM_ONLY_RE = re.compile(rf"^[\s,;、，和与及./]*(?:{_V}[\s,;、，和与及./]*)+$")
_ENUM_RE = re.compile(rf"(?P<list>{_V}(?:\s*(?:,|and|&|、|，|和|与)\s*{_V})*)")


def _pick(m: Match[str], groups: tuple[str, ...]) -> str | None:
    for g in groups:
        val = m.groupdict().get(g)
        if val:
            return val
    return None


@dataclass(frozen=True)
class _Built:
    """Uniform result of applying a rule; converted to Claims by the caller."""

    kind: ClaimKind
    confidence: float
    version_set: VersionSet | None = None
    version: Version | None = None
    commit: str = ""
    branch_hint: str = ""
    detail: str = ""


def _branch_hint_for(v: Version) -> str:
    rel = v.release
    if len(rel) >= 2:
        return f"{rel[0]}.{rel[1]}.x"
    if rel:
        return f"{rel[0]}.x"
    return ""


def _line_range(token: str) -> VersionSet:
    """``1.2.x`` -> [1.2.0, 1.3.0).  Requires a wildcard."""
    parts = token.rstrip(".,;:)").lstrip("vV").split(".")
    if not any(p.lower() in {"x", "*"} for p in parts):
        raise InvalidVersion(token)
    nums: list[int] = []
    for p in parts:
        if p.lower() in {"x", "*"}:
            break
        if not p.isdigit():
            raise InvalidVersion(token)
        nums.append(int(p))
    if not nums:
        raise InvalidVersion(token)
    lo = Version(".".join(map(str, nums)))
    hi_nums = list(nums)
    hi_nums[-1] += 1
    hi = Version(".".join(map(str, hi_nums)))
    return VersionSet([Interval(lo=lo, lo_inc=True, hi=hi, hi_inc=False)])


def _point(v: Version) -> VersionSet:
    return VersionSet([Interval(lo=v, lo_inc=True, hi=v, hi_inc=True)])


def _apply(
    rule: Rule,
    m: Match[str],
    sentence: str,
    context: str | None,
) -> list[_Built]:
    sem = rule.semantics
    negated = bool(_NEGATION.search(sentence))
    ctx_not_affected = context == "not_affected"

    if sem is Sem.COMMIT:
        tok = _pick(m, rule.version_groups) or ""
        if not tok:
            return []
        return [_Built(ClaimKind.FIXED_COMMIT, rule.confidence, commit=tok)]

    if sem is Sem.NOT_AFFECTED:
        vals = [
            mm.group(0)
            for mm in _VRE.finditer(_pick(m, rule.version_groups) or "")
        ]
        out = []
        for raw in vals:
            try:
                v = _v(raw)
            except InvalidVersion:
                continue
            out.append(
                _Built(
                    ClaimKind.NOT_AFFECTED,
                    rule.confidence,
                    version_set=_point(v),
                    version=v,
                )
            )
        return out

    if sem is Sem.FIXED_LIST:
        out = []
        for mm in _VRE.finditer(m.groupdict()["list"]):
            try:
                v = _v(mm.group(0))
            except InvalidVersion:
                continue
            out.append(
                _Built(
                    ClaimKind.FIXED_VERSION,
                    rule.confidence,
                    version=v,
                    branch_hint=_branch_hint_for(v),
                )
            )
        return out

    if sem is Sem.DISCRETE:
        out = []
        kind = ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE
        for mm in _VRE.finditer(m.groupdict()["list"]):
            try:
                v = _v(mm.group(0))
            except InvalidVersion:
                continue
            out.append(_Built(kind, rule.confidence, version_set=_point(v)))
        return out

    if sem is Sem.ALL:
        if re.search(r"\b(?:not|no|unaffected|patched|fixed)\b", sentence, re.I):
            return []
        kind = ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_ALL
        return [_Built(kind, rule.confidence, version_set=VersionSet.everything())]

    if sem is Sem.LINE:
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE,
                rule.confidence,
                version_set=_line_range(m.groupdict()["v"]),
                branch_hint=m.groupdict()["v"],
            )
        ]

    if sem is Sem.BRANCH:
        lo = _v(m.groupdict()["v"])
        rel = list(lo.release)
        if not rel:
            return []
        rel[-1] += 1
        hi = Version(".".join(map(str, rel)))
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE,
                rule.confidence,
                version_set=VersionSet([Interval(lo=lo, lo_inc=True, hi=hi, hi_inc=False)]),
                branch_hint=m.groupdict()["v"],
                detail="branch/line reference; treated as a coarse affected band",
            )
        ]

    # Every remaining semantics needs a parseable version.
    raw = _pick(m, rule.version_groups)
    if not raw:
        return []
    v = _v(raw)

    if sem is Sem.FIXED:
        return [
            _Built(
                ClaimKind.FIXED_VERSION,
                rule.confidence,
                version=v,
                branch_hint=_branch_hint_for(v),
            )
        ]
    if sem is Sem.INTRODUCED:
        return [_Built(ClaimKind.INTRODUCED_VERSION, rule.confidence, version=v)]

    if sem is Sem.RANGE:
        # The first group that holds a version *other* than the lower bound is
        # the upper bound; "1.0 到 2.0" and "1.0 through 2.0" name different
        # groups but mean the same thing.
        raw2 = None
        for name in rule.second_groups:
            value = m.groupdict().get(name)
            if value and value != raw:
                raw2 = value
                break
        if not raw2:
            return []
        b = _v(raw2)
        lo, hi = (v, b) if v <= b else (b, v)
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE,
                rule.confidence,
                version_set=VersionSet([Interval(lo=lo, lo_inc=True, hi=hi, hi_inc=True)]),
            )
        ]

    if sem is Sem.UPPER:
        inclusive = rule.inclusive or (
            rule.inclusive_from_match
            and ("<=" in m.group(0) or "=<" in m.group(0))
        )
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE,
                rule.confidence,
                version_set=VersionSet([Interval(hi=v, hi_inc=inclusive)]),
            )
        ]

    if sem is Sem.LOWER:
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_RANGE,
                rule.confidence,
                version_set=VersionSet([Interval(lo=v, lo_inc=rule.inclusive)]),
            )
        ]

    if sem is Sem.OPEN_ENDED:
        # "affected: all versions, there is no fixed release" — the sentence
        # says every version, and the repository has to supply the truth.
        if re.search(r"\b(?:not|no)\b", sentence, re.I) and not _NEGATION.search(sentence):
            return []
        return [
            _Built(
                ClaimKind.NOT_AFFECTED if (negated or ctx_not_affected) else ClaimKind.AFFECTED_ALL,
                rule.confidence,
                version_set=VersionSet.everything(),
            )
        ]

    return []


# ---------------------------------------------------------------------------
# Extraction entry point
# ---------------------------------------------------------------------------
def _to_claim(
    built: _Built, sentence: str, base: int, span: tuple[int, int]
) -> Claim:
    return Claim(
        kind=built.kind,
        evidence=sentence,
        confidence=built.confidence,
        span=(base + span[0], base + span[1]),
        version_set=built.version_set,
        version=built.version,
        commit=built.commit,
        branch_hint=built.branch_hint,
        detail=built.detail,
    )


_SEM_PRIORITY = {
    # Specific statements beat generic ones on the same sentence: "1.0.0
    # through 1.9.9" must not also become "everything up to 1.9.9".
    Sem.COMMIT: 100,
    Sem.NOT_AFFECTED: 95,
    Sem.FIXED_LIST: 92,
    Sem.FIXED: 90,
    Sem.INTRODUCED: 85,
    Sem.DISCRETE: 78,
    Sem.RANGE: 72,
    # A line-bounded statement ("the 1.6 branch ... up to 1.6.3") is more
    # specific than the bare bound it contains, and narrower than it too.
    Sem.BRANCH: 66,
    Sem.LINE: 64,
    Sem.UPPER: 40,
    Sem.LOWER: 35,
    Sem.ALL: 5,
    Sem.OPEN_ENDED: 50,
}


_RANGE_SEMANTICS = {Sem.UPPER, Sem.LOWER, Sem.RANGE, Sem.LINE, Sem.BRANCH, Sem.ALL}


def _suppress_redundant(hits: list[_Hit]) -> list[_Hit]:
    """Drop range statements that a stronger statement in the same sentence covers.

    A single sentence often yields several overlapping readings: "all releases
    before 2.4.0" produces both an upper bound and a generic "all releases"
    match, and "1.0.0 through 1.9.9" produces the closed range plus each of its
    endpoints.  Keeping all of them would widen the affected set beyond what
    the sentence says.

    Suppression is by *containment*, not merely by class, so two genuinely
    different ranges in one sentence ("before 2.4.0 ... and 3.0.0 through
    3.1.2") both survive.  Non-range statements — fixed versions, commits,
    "not affected" — are never suppressed.
    """
    # "All releases before 2.4.0" contains a generic "all releases" match
    # alongside the bound that qualifies it.  The bound is the real statement:
    # no set can contain "all versions", so containment alone would keep both.
    # A bare "all versions are affected" with nothing else in the sentence
    # still stands.
    qualified_all = len([h for h in hits if h.semantics in _RANGE_SEMANTICS]) > 1

    keep: list[_Hit] = []
    for hit in hits:
        if hit.semantics not in _RANGE_SEMANTICS:
            keep.append(hit)
            continue
        if hit.semantics is Sem.ALL and qualified_all:
            continue
        dominated = False
        for other in hits:
            if other is hit or other.semantics not in _RANGE_SEMANTICS:
                continue
            if not _strictly_better(other, hit):
                continue
            # A weaker reading that sits *inside* a stronger match is part of
            # that match, not a separate statement: in "3.0.0 through 3.1.2"
            # the "through 3.1.2" tail is not an upper bound on its own.
            if _span_contains(other.span, hit.span) and other.priority > hit.priority:
                dominated = True
                break
            if _covers(other, hit):
                dominated = True
                break
        if not dominated:
            keep.append(hit)
    return keep


def _span_contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _strictly_better(a: _Hit, b: _Hit) -> bool:
    if a.priority != b.priority:
        return a.priority > b.priority
    return a.order < b.order


def _covers(a: _Hit, b: _Hit) -> bool:
    """True when every set in ``b`` is already contained in ``a``'s union."""
    union_a = VersionSet()
    for built in a.built:
        if built.version_set is not None:
            union_a = union_a.union(built.version_set)
    if union_a.is_empty:
        return False
    for built in b.built:
        if built.version_set is None:
            continue
        if built.version_set.is_empty:
            continue
        if not built.version_set.difference(union_a).is_empty:
            return False
    return True


@dataclass(frozen=True)
class _Hit:
    """One rule application against a sentence, before claims are emitted."""

    priority: int
    order: int
    semantics: Sem
    span: tuple[int, int]
    built: list[_Built]


def _refine_line_bounded(hits: list[_Hit]) -> list[_Hit]:
    """Intersect a bound with the release line the same sentence names.

    "The 1.6 branch is affected up to 1.6.3" states ``(-inf, 1.6.3)`` and
    ``[1.6.0, 1.7.0)`` separately; either alone is wrong, and both are
    supported by the text.  When a sentence carries exactly one line/branch
    hint and at least one bound, the result is their intersection.
    """
    line_hits = [h for h in hits if h.semantics in {Sem.LINE, Sem.BRANCH}]
    bound_hits = [h for h in hits if h.semantics in {Sem.UPPER, Sem.LOWER}]
    if len(line_hits) != 1 or not bound_hits:
        return hits
    line_built = line_hits[0].built
    if len(line_built) != 1 or line_built[0].version_set is None:
        return hits
    band = line_built[0].version_set
    out = []
    consumed_line = False
    for h in hits:
        if h is line_hits[0]:
            # Emitted later, and only if no bound could be narrowed: the
            # intersection already carries the line band.
            continue
        if any(h is b for b in bound_hits):
            merged = []
            for b in h.built:
                if b.version_set is None:
                    continue
                vs = b.version_set.intersection(band)
                if vs.is_empty:
                    continue
                merged.append(
                    _Built(
                        b.kind,
                        min(b.confidence, 0.8),
                        version_set=vs,
                        branch_hint=line_built[0].branch_hint,
                        detail=(
                            "bound narrowed to the release line named in the "
                            "same sentence"
                        ),
                    )
                )
            if merged:
                consumed_line = True
                out.append(
                    _Hit(
                        priority=max(line_hits[0].priority, h.priority) + 6,
                        order=h.order,
                        semantics=h.semantics,
                        span=h.span,
                        built=merged,
                    )
                )
                continue
        out.append(h)
    if not consumed_line:
        out.append(line_hits[0])
    return out


def _rule_priority(rule: Rule) -> int:
    base = rule.priority if rule.priority != 50 else _SEM_PRIORITY[rule.semantics]
    return base


def _extract_sentence(
    masked_sent: str,
    orig_sent: str,
    sent_base: int,
    context: str | None,
    claims: list[Claim],
) -> None:
    """Apply the version rules to one sentence, with priority-based suppression."""
    hits: list[_Hit] = []

    chain = _chain_set(masked_sent)
    if chain is not None:
        vs, span = chain
        hits.append(
            _Hit(
                priority=_SEM_PRIORITY[Sem.RANGE] + 5,
                order=-1,
                semantics=Sem.RANGE,
                span=span,
                built=[
                    _Built(
                        ClaimKind.NOT_AFFECTED
                        if _NEGATION.search(masked_sent)
                        else ClaimKind.AFFECTED_RANGE,
                        0.92,
                        version_set=vs,
                    )
                ],
            )
        )

    for order, rule in enumerate(_RULES):
        if rule.semantics is Sem.COMMIT:
            continue
        if chain is not None and rule.name in {"operator_lt", "operator_gt"}:
            continue
        if rule.needs_affected_wording and not (
            _AFFECTED_WORDING.search(masked_sent)
            or _NEGATION.search(masked_sent)
            or context == "affected"
        ):
            continue
        for m in rule.pattern.finditer(masked_sent):
            if _MASK in m.group(0):
                continue
            try:
                built_list = _apply(rule, m, masked_sent, context)
            except (InvalidVersion, ValueError):
                continue
            if built_list:
                hits.append(
                    _Hit(
                        priority=_rule_priority(rule),
                        order=order,
                        semantics=rule.semantics,
                        span=m.span(),
                        built=built_list,
                    )
                )

    if not hits:
        _extract_enum(masked_sent, orig_sent, sent_base, context, claims)
        return

    hits = _refine_line_bounded(hits)
    hits = _suppress_redundant(hits)

    for hit in hits:
        for built in hit.built:
            claims.append(_to_claim(built, orig_sent, sent_base, hit.span))


def _extract_enum(
    masked_sent: str,
    orig_sent: str,
    sent_base: int,
    context: str | None,
    claims: list[Claim],
) -> None:
    """Interpret a bare version list, using section context for meaning."""
    if context not in {"affected", "fixed", "not_affected"}:
        return
    if not _ENUM_ONLY_RE.match(masked_sent):
        return
    m = _ENUM_RE.search(masked_sent)
    if not m:
        return
    negated = bool(_NEGATION.search(masked_sent))
    for mm in _VRE.finditer(m.group("list")):
        try:
            v = _v(mm.group(0))
        except InvalidVersion:
            continue
        span = (m.start("list") + mm.start(), m.start("list") + mm.end())
        if context == "fixed" and not negated:
            kind = ClaimKind.FIXED_VERSION
        elif context == "not_affected" or negated:
            kind = ClaimKind.NOT_AFFECTED
        else:
            kind = ClaimKind.AFFECTED_RANGE
        claims.append(
            Claim(
                kind=kind,
                evidence=orig_sent,
                confidence=0.8 if kind is ClaimKind.FIXED_VERSION else 0.7,
                span=(sent_base + span[0], sent_base + span[1]),
                version=v if kind is ClaimKind.FIXED_VERSION else None,
                version_set=None if kind is ClaimKind.FIXED_VERSION else _point(v),
                branch_hint=_branch_hint_for(v) if kind is ClaimKind.FIXED_VERSION else "",
            )
        )


def extract_advisory(
    advisory_id: str,
    text: str,
    *,
    package: str = "",
    repo_url: str = "",
) -> Advisory:
    """Parse advisory text into an :class:`Advisory` of claims."""
    adv = Advisory(advisory_id=advisory_id, text=text)
    adv.package = package or _find_package(text)
    adv.repo_url = repo_url or _find_repo_url(text)
    masked, commits = _mask(text)

    claims: list[Claim] = []

    for seg in segments(masked):
        if not seg.text.strip():
            continue
        base = seg.offset
        # Commit rules need the original text: hashes were masked out of
        # ``masked`` so the version rules could not misread them as versions.
        original_line = text[base : base + len(seg.text)]
        for rule in _RULES:
            if rule.semantics is not Sem.COMMIT:
                continue
            for m in rule.pattern.finditer(original_line):
                try:
                    for built in _apply(rule, m, original_line, seg.context):
                        claims.append(_to_claim(built, original_line, base, m.span()))
                except (InvalidVersion, ValueError):
                    continue

        sentences = split_sentences(seg.text) or [(0, seg.text)]
        for rel, sent in sentences:
            sent_base = base + rel
            orig_sent = text[sent_base : sent_base + len(sent)]
            _extract_sentence(sent, orig_sent, sent_base, seg.context, claims)

    _dedupe(claims)
    adv.claims = claims
    _attach_bare_commits(adv, commits)
    _postprocess(adv)
    adv.claims.sort(key=lambda c: (c.span, c.kind.value))
    return adv


_CHAIN_TERM = re.compile(rf"(?P<op>>=|=>|<=|=<|>|<|==|=)\s*(?P<v>{_V})")


def _chain_set(text: str) -> tuple[VersionSet, tuple[int, int]] | None:
    terms = list(_CHAIN_TERM.finditer(text))
    if len(terms) < 2:
        return None
    vs = VersionSet.everything()
    for m in terms:
        op = m.group("op")
        try:
            v = _v(m.group("v"))
        except InvalidVersion:
            return None
        if op in {">=", "=>"}:
            iv = Interval(lo=v, lo_inc=True)
        elif op == ">":
            iv = Interval(lo=v, lo_inc=False)
        elif op in {"<=", "=<"}:
            iv = Interval(hi=v, hi_inc=True)
        elif op == "<":
            iv = Interval(hi=v, hi_inc=False)
        else:
            iv = Interval(lo=v, lo_inc=True, hi=v, hi_inc=True)
        vs = vs.intersection(VersionSet([iv]))
    if vs.is_empty:
        return None
    return vs, (terms[0].start(), terms[-1].end())


def _claim_value(c: Claim) -> str:
    if c.version is not None:
        return c.version.raw
    if c.version_set is not None:
        return c.version_set.describe()
    return c.commit


def _dedupe(claims: list[Claim]) -> None:
    """Keep one claim per (kind, value), preferring higher confidence."""
    best: dict[tuple[str, str], Claim] = {}
    order: list[tuple[str, str]] = []
    for c in claims:
        key = (c.kind.value, _claim_value(c))
        cur = best.get(key)
        if cur is None:
            best[key] = c
            order.append(key)
        elif c.confidence > cur.confidence:
            best[key] = c
        elif c.confidence == cur.confidence and len(c.evidence) < len(cur.evidence):
            best[key] = c
    claims[:] = [best[k] for k in order]


def _attach_bare_commits(adv: Advisory, commits: list[tuple[int, int, str]]) -> None:
    known = {c.commit for c in adv.fixed_commits}
    for a, b, tok in commits:
        if tok in known:
            continue
        adv.claims.append(
            Claim(
                kind=ClaimKind.FIXED_COMMIT,
                evidence=adv.text[max(0, a - 60) : b + 60].replace("\n", " ").strip(),
                confidence=0.35,
                span=(a, b),
                commit=tok,
                detail="bare commit reference; no fix verb attached",
            )
        )


def _postprocess(adv: Advisory) -> None:
    # 1. Branch hints: a fix version next to a release-line mention belongs to
    #    that line, e.g. "1.4.x: fixed in 1.4.9".
    line_claims = [c for c in adv.claims if c.branch_hint and c.version_set]
    for c in adv.fixed_versions:
        if c.branch_hint or c.version is None:
            continue
        hint = _branch_hint_for(c.version)
        for lc in line_claims:
            if abs(lc.span[0] - c.span[0]) <= 60 and (
                lc.branch_hint.split(".")[:2] == hint.split(".")[:2]
            ):
                c.branch_hint = hint
                break

    # 2. "Fixed in X" with no stated range: derive the range explicitly, and
    #    mark it as an inference so the report can lower its confidence.
    if not adv.affected_claims:
        fixed = [c for c in adv.fixed_versions if c.version is not None]
        if fixed:
            intro = next(
                (c.version for c in adv.of_kind(ClaimKind.INTRODUCED_VERSION) if c.version),
                None,
            )
            for c in fixed:
                assert c.version is not None
                vs = VersionSet([Interval(lo=intro, lo_inc=True)]).intersection(
                    VersionSet([Interval(hi=c.version, hi_inc=False)])
                )
                adv.claims.append(
                    Claim(
                        kind=ClaimKind.AFFECTED_RANGE,
                        evidence=c.evidence,
                        confidence=0.55,
                        span=c.span,
                        version_set=vs,
                        branch_hint=c.branch_hint,
                        detail=(
                            "inferred from fix version: everything below the fix "
                            "(advisory gives no explicit affected range)"
                        ),
                    )
                )
            adv.warnings.append(
                "advisory states no explicit affected range; it was inferred from "
                "the fixed version and carries low confidence"
            )

    _check_internal_consistency(adv)

    # Anything the parser actually understood counts, including "not affected":
    # an advisory that only rules versions out is still machine-readable.
    has_meaningful = any(c.kind is not ClaimKind.UNPARSED for c in adv.claims)
    if not has_meaningful:
        adv.warnings.append("no machine-readable version or fix claims found")
        adv.claims.append(
            Claim(
                kind=ClaimKind.UNPARSED,
                evidence=adv.text[:200].replace("\n", " "),
                confidence=0.0,
                detail="could not extract any version-range or fix claim",
            )
        )


def _check_internal_consistency(adv: Advisory) -> None:
    """Flag contradictions that a repository is not needed to see.

    A claim that names a release line ("the 1.4 branch … up to 1.4.9") is only
    compared with fixes on that line: a fix on 1.9.10 legitimately sits below a
    2.2.x bound, because it is the fix for the 1.9 branch.  A claim with no
    line, such as "all versions before 2.4.0", is global and is compared with
    every fix.
    """
    for fc in adv.fixed_versions:
        f = fc.version
        if f is None:
            continue
        f_line = fc.branch_hint
        for a in adv.affected_claims:
            vs = a.version_set
            if vs is None:
                continue
            if vs.all_versions:
                adv.warnings.append(
                    f"advisory claims all versions are affected but also names fix "
                    f"{f.raw}"
                )
                continue
            if a.branch_hint and f_line and a.branch_hint != f_line:
                continue
            last = _max_upper(vs)
            if last is not None and f < last:
                where = f" on line {f_line}" if f_line else ""
                adv.warnings.append(
                    f"internal contradiction: fix version {f.raw} is below the "
                    f"upper affected bound {last.raw}{where}"
                )
    intro = [c.version for c in adv.of_kind(ClaimKind.INTRODUCED_VERSION) if c.version]
    for fc in adv.fixed_versions:
        f = fc.version
        if f is None:
            continue
        for i in intro:
            if i > f:
                adv.warnings.append(
                    f"internal contradiction: introduced {i.raw} is above fix {f.raw}"
                )


def _max_upper(vs: VersionSet) -> Version | None:
    best: Version | None = None
    for iv in vs.intervals:
        if iv.hi is not None and (best is None or iv.hi > best):
            best = iv.hi
    return best


_PKG_RES = (
    re.compile(
        r"^\s*(?:package|project|component|product|module|library|软件包|组件|项目)"
        r"\s*[:\-：]\s*(?P<p>[\w.@/+:-]+)",
        re.M | re.I,
    ),
    re.compile(
        r"\b(?:in|of|for)\s+(?:the\s+)?(?P<p>[A-Za-z][\w.-]{1,40})\s+"
        r"(?:package|library|module|project)\b",
        re.I,
    ),
)
_REPO_RE = re.compile(
    r"https?://(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|"
    r"gitee\.com)/[\w.-]+/[\w.-]+|https?://[\w.-]+/[\w./-]+\.git\b",
    re.I,
)


def _find_package(text: str) -> str:
    for rx in _PKG_RES:
        m = rx.search(text)
        if m:
            return m.group("p")
    return ""


def _find_repo_url(text: str) -> str:
    m = _REPO_RE.search(text)
    if not m:
        return ""
    return m.group(0).rstrip("/").removesuffix(".git")
