"""Advisory text -> claims."""

from __future__ import annotations

import pytest

from vulnrange.advisory import ClaimKind, extract_advisory
from vulnrange.advisory.extract import split_sentences
from vulnrange.versions import Version


def claims_of(adv, kind):
    return adv.of_kind(kind)


def ranges(adv):
    return sorted(c.version_set.describe() for c in adv.affected_claims)


def contains(adv, version: str) -> bool:
    return Version(version) in adv.declared_affected


class TestBeforeAndEarlier:
    @pytest.mark.parametrize(
        "text",
        [
            "All releases before 2.4.0 are affected.",
            "Versions 2.4.0 and earlier are vulnerable.",
            "Affected up to and including 2.4.0.",
            "固定于 2.4.0 之前的所有版本受影响.",
            "版本 2.4.0 及以下 均受影响",
        ],
    )
    def test_upper_bound(self, text: str) -> None:
        adv = extract_advisory("T", text)
        assert adv.affected_claims, text
        assert contains(adv, "1.0.0")
        # Only the "before" forms exclude 2.4.0 itself.
        if "before" in text or "之前" in text:
            assert not contains(adv, "2.4.0")
        else:
            assert contains(adv, "2.4.0")
        assert not contains(adv, "2.4.1")

    def test_earlier_wording_is_inclusive(self) -> None:
        adv = extract_advisory("T", "Versions 2.4.0 and earlier are affected.")
        assert contains(adv, "2.4.0")
        assert not contains(adv, "2.4.1")


class TestRanges:
    def test_operator_chain(self) -> None:
        adv = extract_advisory("T", "In versions >= 3.0.0 and < 3.2.1 the parser overflows.")
        assert contains(adv, "3.0.0")
        assert contains(adv, "3.2.0")
        assert not contains(adv, "3.2.1")
        assert not contains(adv, "2.9.9")

    def test_through_range(self) -> None:
        adv = extract_advisory("T", "Acme 1.0.0 through 1.9.9 is affected.")
        assert contains(adv, "1.0.0")
        assert contains(adv, "1.9.9")
        assert not contains(adv, "1.10.0")

    def test_comma_chain(self) -> None:
        adv = extract_advisory("T", "Affected: >=1.2.0, <1.4.2")
        assert contains(adv, "1.2.0")
        assert not contains(adv, "1.4.2")
        assert not contains(adv, "1.1.9")


class TestLines:
    def test_wildcard_line(self) -> None:
        adv = extract_advisory("T", "Affected versions: 1.4.x")
        assert contains(adv, "1.4.0")
        assert contains(adv, "1.4.99")
        assert not contains(adv, "1.5.0")

    def test_branch_named_line(self) -> None:
        adv = extract_advisory("T", "The 1.6 branch is affected up to 1.6.3.")
        assert contains(adv, "1.6.0")
        assert contains(adv, "1.6.3")
        assert not contains(adv, "1.6.4")
        assert not contains(adv, "1.5.9")

    def test_multiple_lines(self) -> None:
        adv = extract_advisory("T", "Affected versions:\n- 1.4.x\n- 2.0.x\n")
        assert contains(adv, "1.4.2")
        assert contains(adv, "2.0.1")
        assert not contains(adv, "1.6.0")
        assert not contains(adv, "2.1.0")


class TestFixed:
    def test_fixed_version(self) -> None:
        adv = extract_advisory("T", "All versions before 2.4.0 are affected. Fixed in 2.4.0.")
        fixed = claims_of(adv, ClaimKind.FIXED_VERSION)
        assert [c.version.raw for c in fixed] == ["2.4.0"]

    def test_fixed_version_list(self) -> None:
        adv = extract_advisory("T", "Fixed in 2.2.0 and 1.9.10.")
        assert {c.version.raw for c in adv.fixed_versions} == {"2.2.0", "1.9.10"}

    def test_fixed_commit(self) -> None:
        adv = extract_advisory("T", "The issue is fixed in commit 3f2a1bc99d.")
        assert [c.commit for c in adv.fixed_commits] == ["3f2a1bc99d"]

    def test_chinese_fix_commit(self) -> None:
        adv = extract_advisory("T", "该问题已修复,修复提交 abcdef1234567。")
        assert "abcdef1234567" in {c.commit for c in adv.fixed_commits}

    def test_upgrade_advice(self) -> None:
        adv = extract_advisory("T", "Users should upgrade to 3.2.1.")
        assert [c.version.raw for c in adv.fixed_versions] == ["3.2.1"]

    def test_release_contains_fix(self) -> None:
        adv = extract_advisory("T", "Release 1.4.9 contains the fix.")
        assert [c.version.raw for c in adv.fixed_versions] == ["1.4.9"]


class TestNegation:
    def test_not_affected_version(self) -> None:
        adv = extract_advisory("T", "Versions 3.1.7 are not affected.")
        assert [c.version.raw for c in claims_of(adv, ClaimKind.NOT_AFFECTED)] == ["3.1.7"]

    def test_negated_sentence_does_not_become_affected(self) -> None:
        adv = extract_advisory("T", "Versions before 1.0 are not affected.")
        assert not adv.affected_claims
        assert claims_of(adv, ClaimKind.NOT_AFFECTED)

    def test_not_affected_section(self) -> None:
        text = "## Not affected\n1.0.0\n1.0.1\n"
        adv = extract_advisory("T", text)
        assert not adv.affected_claims
        got = {c.version_set.describe() for c in claims_of(adv, ClaimKind.NOT_AFFECTED)}
        assert got == {"[1.0.0, 1.0.0]", "[1.0.1, 1.0.1]"}


class TestSections:
    def test_fixed_in_section(self) -> None:
        text = "## Affected versions\n1.0.0\n1.0.1\n\n## Fixed in\n1.0.2\n"
        adv = extract_advisory("T", text)
        assert contains(adv, "1.0.0")
        assert not contains(adv, "1.0.2")
        assert [c.version.raw for c in adv.fixed_versions] == ["1.0.2"]

    def test_same_line_heading(self) -> None:
        adv = extract_advisory("T", "Affected versions: 1.0.0, 1.0.1")
        assert contains(adv, "1.0.0")
        assert contains(adv, "1.0.1")
        assert not contains(adv, "1.0.2")

    def test_heading_context_does_not_leak_into_explicit_line(self) -> None:
        text = "## Affected versions\nAll releases before 2.0\n"
        adv = extract_advisory("T", text)
        assert contains(adv, "1.9")


class TestHardWrapping:
    def test_sentence_split_across_lines(self) -> None:
        text = "The 1.6 branch is\naffected up to 1.6.3.\n"
        adv = extract_advisory("T", text)
        assert contains(adv, "1.6.0")
        assert not contains(adv, "1.6.4")


class TestInference:
    def test_range_inferred_from_fix_is_flagged(self) -> None:
        adv = extract_advisory("T", "Fixed in 2.4.0.")
        assert adv.affected_claims
        assert contains(adv, "2.3.9")
        assert not contains(adv, "2.4.0")
        # Inference must be visible, not silent.
        assert any("inferred" in w for w in adv.warnings)
        assert all(c.confidence <= 0.6 for c in adv.affected_claims)

    def test_inference_respects_introduced(self) -> None:
        adv = extract_advisory("T", "Introduced in 2.0.0. Fixed in 2.4.0.")
        assert contains(adv, "2.1.0")
        assert not contains(adv, "1.9.9")
        assert not contains(adv, "2.4.0")


class TestContradictions:
    def test_fix_below_upper_bound_warns(self) -> None:
        adv = extract_advisory(
            "T", "All versions before 2.4.0 are affected. Fixed in 2.3.0."
        )
        assert any("contradiction" in w for w in adv.warnings)

    def test_all_versions_plus_fix_warns(self) -> None:
        adv = extract_advisory("T", "All versions are affected. Fixed in 2.0.1.")
        assert any("all versions" in w for w in adv.warnings)


class TestNoise:
    def test_cve_and_dates_do_not_become_versions(self) -> None:
        text = (
            "See CVE-2024-1234 (published 2024-01-15) for details. "
            "The issue affects 1.0.0."
        )
        adv = extract_advisory("T", text)
        versions = {
            c.version.raw for c in adv.fixed_versions + adv.of_kind(ClaimKind.INTRODUCED_VERSION)
        }
        assert "2024-01-15" not in versions
        assert "2024" not in versions

    def test_url_is_ignored(self) -> None:
        text = "Details at https://example.invalid/v1.2.3/notes. Affected: 1.0.x"
        adv = extract_advisory("T", text)
        assert contains(adv, "1.0.5")

    def test_issue_numbers_are_not_versions(self) -> None:
        adv = extract_advisory("T", "Reported in issue #12345. Affected: 2.0.0 and later")
        assert contains(adv, "2.5")
        assert "12345" not in {c.version.raw for c in adv.claims if c.version}

    def test_unparseable_text_yields_unparsed_claim(self) -> None:
        adv = extract_advisory("T", "Something is wrong with the software.")
        assert claims_of(adv, ClaimKind.UNPARSED)
        assert adv.warnings

    def test_evidence_spans_are_valid(self) -> None:
        text = "Package: x\n\nAll releases before 2.4.0 are affected."
        adv = extract_advisory("T", text)
        for c in adv.claims:
            a, b = c.span
            assert 0 <= a <= b <= len(text)
            assert c.evidence in text

    def test_package_and_repo_detected(self) -> None:
        text = "Package: acme-widget\nRepo: https://github.com/acme/widget\nFixed in 1.2.3"
        adv = extract_advisory("T", text)
        assert adv.package == "acme-widget"
        assert adv.repo_url == "https://github.com/acme/widget"


class TestSplitSentences:
    def test_offsets_are_absolute(self) -> None:
        text = "First one. Second one!"
        parts = split_sentences(text)
        assert [s for _, s in parts] == ["First one.", "Second one!"]
        for off, sent in parts:
            assert text[off : off + len(sent)] == sent

    def test_abbreviation_does_not_split(self) -> None:
        text = "E.g. version 1.0 is old. Fixed later."
        assert len(split_sentences(text)) == 2


class TestMultipleStatementsInOneSentence:
    """One sentence may state several genuinely different ranges."""

    def test_two_ranges_are_both_kept(self) -> None:
        adv = extract_advisory(
            "T",
            "All releases before 2.4.0 are affected, and 3.0.0 through 3.1.2 as well.",
        )
        assert contains(adv, "2.3.0")
        assert contains(adv, "3.1.2")
        assert not contains(adv, "2.5.0")

    def test_closed_range_is_not_widened_to_an_open_bound(self) -> None:
        adv = extract_advisory("T", "Affected: 1.0.0 through 1.9.9")
        assert not contains(adv, "0.9.0")
        assert contains(adv, "1.5.0")
        assert contains(adv, "1.9.9")

    def test_range_plus_extra_range(self) -> None:
        adv = extract_advisory("T", ">= 1.0.0, < 1.4.2 and 2.0.0 to 2.1.0 are affected.")
        assert contains(adv, "1.2.0")
        assert contains(adv, "2.0.5")
        assert not contains(adv, "1.9.0")

    def test_all_versions_still_works_alone(self) -> None:
        adv = extract_advisory("T", "All versions are affected. Fixed in 1.0.0.")
        assert adv.declared_affected.describe() == "all versions"

    def test_generic_all_is_dropped_when_a_bound_qualifies_it(self) -> None:
        adv = extract_advisory("T", "All releases before 2.4.0 are affected.")
        assert not contains(adv, "2.5.0")
        assert contains(adv, "1.0.0")


class TestMoreProseShapes:
    """Shapes seen in real advisories, kept here so regressions are visible."""

    def test_chinese_range(self) -> None:
        adv = extract_advisory("T", "影响 1.0 到 2.0 的版本")
        assert contains(adv, "1.0")
        assert contains(adv, "2.0")
        assert not contains(adv, "2.0.1")

    def test_all_versions_sentence_with_colon_is_not_a_heading(self) -> None:
        # "All versions are affected: the runner calls eval" — the clause
        # before the colon is the claim and must not be discarded.
        adv = extract_advisory("T", "All versions are affected: the runner calls eval.")
        assert adv.declared_affected.describe() == "all versions"

    def test_dash_separated_discrete_versions(self) -> None:
        adv = extract_advisory("T", "Versions 1.0.0, 1.0.1 and 1.0.2 are affected.")
        for v in ("1.0.0", "1.0.1", "1.0.2"):
            assert contains(adv, v)
        assert not contains(adv, "1.0.3")

    def test_not_affected_only_advisory_is_parsed(self) -> None:
        adv = extract_advisory("T", "Versions 1.0.0 and 1.0.1 are not affected.")
        assert not adv.affected_claims
        assert not claims_of(adv, ClaimKind.UNPARSED)

    def test_long_branch_style_version(self) -> None:
        adv = extract_advisory("T", "up to and including 1.2.3.4.5.6.7")
        assert contains(adv, "1.2.3.4.5.6.7")
        assert not contains(adv, "1.2.3.4.5.6.8")
