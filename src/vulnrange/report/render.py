"""Render verification results for humans and for machines.

Two audiences read this output.  A security engineer triaging a queue needs a
short verdict plus the *reason*; an automation pipeline needs stable JSON.  The
text report therefore leads with the verdict and confidence, then the evidence
in decreasing order of importance, and never omits the caveats — a report that
hides its uncertainty is worse than no report in this domain.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from ..advisory.model import Advisory
from ..analysis.universe import Universe
from ..analysis.verify import Verification

__all__ = ["to_json", "to_markdown", "to_text", "summary_line"]

_SEVERITY_ICON = {"info": " ", "warning": "!", "error": "x"}
_STATUS_LABEL = {
    "confirmed": "CONFIRMED",
    "partial": "PARTIAL",
    "disputed": "DISPUTED",
    "contradicted": "CONTRADICTED",
}


def summary_line(verification: Verification) -> str:
    return (
        f"{verification.advisory_id}: {_STATUS_LABEL.get(verification.status, verification.status)}"
        f"  confidence={verification.confidence:.2f}"
        f"  range={verification.resolved_range.describe() if verification.resolved_range else '?'}"
    )


def to_json(
    verification: Verification,
    advisory: Advisory | None = None,
    universe: Universe | None = None,
) -> str:
    """Stable, machine-readable result."""
    payload = verification.to_dict()
    if advisory is not None:
        payload["advisory"] = advisory.to_dict()
    if universe is not None:
        payload["repository"] = universe.to_dict()
    payload["generator"] = "vulnrange"
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _group(findings: Iterable) -> dict[str, list]:
    out: dict[str, list] = {"error": [], "warning": [], "info": []}
    for f in findings:
        out.setdefault(f.severity, []).append(f)
    return out


def to_text(
    verification: Verification,
    advisory: Advisory | None = None,
    universe: Universe | None = None,
    *,
    width: int = 78,
) -> str:
    v = verification
    lines: list[str] = []
    rule = "=" * width

    lines.append(rule)
    lines.append(f"{v.advisory_id}  —  {_STATUS_LABEL.get(v.status, v.status)}")
    lines.append(rule)
    lines.append(f"confidence : {v.confidence:.2f}  ({_confidence_words(v.confidence)})")
    lines.append(f"basis      : {v.basis or 'n/a'}")
    if v.declared_range is not None:
        lines.append(f"declared   : {v.declared_range.describe()}")
    if v.resolved_range is not None:
        lines.append(f"resolved   : {v.resolved_range.describe()}")

    if advisory is not None and advisory.claims:
        lines.append("")
        lines.append("Claims from the advisory")
        lines.append("-" * width)
        for c in advisory.claims:
            value = _claim_value(c)
            line = f"  {c.kind.value:<20} {value:<26} conf={c.confidence:.2f}"
            lines.append(line)
        if advisory.warnings:
            lines.append("")
            for w in advisory.warnings:
                lines.append(f"  ! advisory: {w}")

    if v.fix_commits:
        lines.append("")
        lines.append("Fix commits")
        lines.append("-" * width)
        for f in v.fix_commits:
            state = "verified" if f.present else "NOT FOUND"
            lines.append(f"  {f.sha[:12]}  [{state}]  {f.subject}")
            if f.tags:
                lines.append(f"      released in: {', '.join(f.tags)}")
            elif f.present:
                lines.append("      released in: (no release tag)")
            for line_name, rel in sorted(f.earliest.items()):
                lines.append(f"      line {line_name}: first fixed release {rel.tag}")
            for e in f.evidence:
                if "patch-id" in e or "found by search" in e or "does not exist" in e:
                    lines.append(f"      · {e}")

    if v.lines:
        lines.append("")
        lines.append("Per release line")
        lines.append("-" * width)
        for name, lr in sorted(v.lines.items()):
            lines.append(f"  {name}")
            lines.append(
                f"      advisory affected : {_brief(lr.declared_affected)}"
            )
            if lr.actual_affected or lr.actual_fixed:
                lines.append(
                    f"      history affected  : {_brief(lr.actual_affected)}"
                )
                if lr.actual_fixed:
                    lines.append(f"      first fixed       : {lr.actual_fixed[0]}")
            for note in lr.notes:
                lines.append(f"      note: {note}")

    grouped = _group(v.findings)
    lines.append("")
    lines.append("Findings")
    lines.append("-" * width)
    if not v.findings:
        lines.append("  (none)")
    for severity in ("error", "warning", "info"):
        for f in grouped.get(severity, []):
            label = {"error": "ERROR", "warning": "WARN ", "info": "NOTE "}[severity]
            lines.append(f"  [{label}] {f.message}")
            for e in f.evidence:
                lines.append(f"           · {e}")
    if v.notes:
        lines.append("")
        lines.append("Caveats")
        lines.append("-" * width)
        for n in v.notes:
            lines.append(f"  - {n}")
    lines.append("")
    return "\n".join(lines)


def _confidence_words(score: float) -> str:
    if score >= 0.8:
        return "high — text parsed cleanly and history agrees"
    if score >= 0.6:
        return "moderate — supported by history with caveats"
    if score >= 0.4:
        return "low — the advisory's text is the main support"
    return "very low — claims are unverified or contradicted"


def _brief(tags: list[str], limit: int = 5) -> str:
    if not tags:
        return "(none)"
    if len(tags) <= limit:
        return ", ".join(tags)
    return f"{', '.join(tags[: limit - 1])} … ({len(tags)} total)"


def _claim_value(c) -> str:
    if c.version is not None:
        return c.version.raw
    if c.version_set is not None:
        return c.version_set.describe()
    return c.commit or "?"


def to_markdown(
    verification: Verification,
    advisory: Advisory | None = None,
    universe: Universe | None = None,
    *,
    generated_at: str | None = None,
) -> str:
    v = verification
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = [
        f"# {v.advisory_id} — {_STATUS_LABEL.get(v.status, v.status)}",
        "",
        f"*Generated {now} by vulnrange.*",
        "",
        "| | |",
        "|---|---|",
        f"| Confidence | **{v.confidence:.2f}** ({_confidence_words(v.confidence)}) |",
        f"| Basis | {v.basis or 'n/a'} |",
    ]
    if v.declared_range is not None:
        out.append(f"| Declared range | `{v.declared_range.describe()}` |")
    if v.resolved_range is not None:
        out.append(f"| Resolved range | `{v.resolved_range.describe()}` |")
    out.append("")

    if v.lines:
        out += ["## Release lines", ""]
        out += [
            "| line | advisory says affected | history says affected | first fixed |",
            "|---|---|---|---|",
        ]
        for name, lr in sorted(v.lines.items()):
            out.append(
                f"| `{name}` | {_md_list(lr.declared_affected)} | "
                f"{_md_list(lr.actual_affected)} | "
                f"{lr.actual_fixed[0] if lr.actual_fixed else '—'} |"
            )
        out.append("")

    if v.fix_commits:
        out += ["## Fix commits", ""]
        for f in v.fix_commits:
            mark = "verified" if f.present else "**not found**"
            out.append(f"- `{f.sha[:12]}` ({mark}) — {f.subject}")
            if f.tags:
                out.append(f"  - first release containing it: {', '.join(f.tags)}")
            for line_name, rel in sorted(f.earliest.items()):
                out.append(f"  - line `{line_name}`: first fixed release `{rel.tag}`")
            for e in f.evidence:
                # Skip evidence already shown as a line/release above.
                if e.startswith("released in:"):
                    continue
                out.append(f"  - {e}")
        out.append("")

    if v.findings:
        out += ["## Findings", ""]
        for severity in ("error", "warning", "info"):
            bucket = [f for f in v.findings if f.severity == severity]
            if not bucket:
                continue
            for f in bucket:
                out.append(f"- **{severity.upper()}** — {f.message}")
                for e in f.evidence:
                    out.append(f"  - {e}")
        out.append("")

    if advisory is not None and advisory.claims:
        out += ["## Extracted claims", "", "| kind | value | confidence | evidence |", "|---|---|---|---|"]
        for c in advisory.claims:
            out.append(
                f"| {c.kind.value} | `{_claim_value(c)}` | {c.confidence:.2f} | "
                f"{_md_escape(c.evidence[:120])} |"
            )
        out.append("")

    if v.notes:
        out += ["## Caveats", ""]
        out += [f"- {n}" for n in v.notes]
        out.append("")
    return "\n".join(out)


def _md_list(tags: list[str]) -> str:
    if not tags:
        return "—"
    if len(tags) <= 6:
        return ", ".join(f"`{t}`" for t in tags)
    return f"`{tags[0]}` … `{tags[-1]}` ({len(tags)})"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
