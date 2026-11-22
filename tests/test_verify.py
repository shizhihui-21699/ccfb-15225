"""End-to-end verification against real git histories.

Each test builds a repository whose history has the shape security work
actually encounters — backports with different hashes, a fix that never
shipped, an advisory that understates the range — and asserts what the
verifier reports.

Fixtures name their fix commit with the advisory's CVE ID, so a test can
choose which evidence path to exercise: naming the commit in the advisory, or
letting the verifier discover it from the commit message.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from build_fixtures import build_scenario  # noqa: E402

from vulnrange.advisory import extract_advisory
from vulnrange.analysis.universe import build_universe
from vulnrange.analysis.verify import FindingKind, verify
from vulnrange.repo.git import GitRepo
from vulnrange.versions import Version

pytestmark = pytest.mark.slow

# The CVE/GHSA IDs that each fixture's fix commit mentions.
FIXTURE_IDS = {
    "multi-branch": "CVE-2024-4242",
    "fix-never-shipped": "GHSA-2222-3333-4444",
    "wrong-advisory": "CVE-2024-9999",
    "calver": "CVE-2024-7777",
    "missing-fix-commit": "CVE-2024-5555",
    "epoch-debian": "CVE-2024-6666",
}


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    base = tmp_path_factory.mktemp("repos")
    return {
        name: build_scenario(name, base)
        for name in (
            "multi-branch",
            "fix-never-shipped",
            "wrong-advisory",
            "calver",
            "missing-fix-commit",
            "epoch-debian",
        )
    }


def analyse(fixtures, name, text, advisory_id=None):
    path, facts = fixtures[name]
    repo = GitRepo(path)
    universe = build_universe(repo)
    adv = extract_advisory(advisory_id or FIXTURE_IDS[name], text)
    return verify(adv, repo, universe), adv, facts, universe


def kinds(v):
    return {f.kind for f in v.findings}


def errors(v):
    return [f for f in v.findings if f.severity == "error"]


class TestMultiBranch:
    """One upstream fix, cherry-picked to two maintenance lines."""

    TEXT = (
        "All releases before 1.4.9 are affected on the 1.4 branch.\n"
        "The 1.6 branch is affected up to 1.6.3.\n"
        "Releases 2.0.1 and 2.0.2 are also affected.\n"
        "Fixed in commit {sha}.\n"
    )

    def text(self, facts):
        return self.TEXT.format(sha=facts["fix_main"])

    def test_history_is_indexed_into_three_lines(self, fixtures) -> None:
        _, _, _, universe = analyse(fixtures, "multi-branch", "x")
        assert sorted(universe.lines) == ["1.4.x", "1.6.x", "2.0.x"]
        assert universe.lines["1.4.x"].releases[-1].tag == "1.4.9"

    def test_backports_are_found_by_patch_id(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        v, _, _, _ = analyse(fixtures, "multi-branch", self.text(facts))
        assert FindingKind.BACKPORT_FOUND in kinds(v)
        fix = v.fix_commits[0]
        assert fix.earliest["1.4.x"].tag == "1.4.9"
        assert fix.earliest["2.0.x"].tag == "2.0.3"
        # The backports really are different commit objects.
        assert facts["fix_1_4"] != facts["fix_main"] != facts["fix_2_0"]
        assert v.lines["1.4.x"].actual_fixed == ["1.4.9"]

    def test_affected_sets_match_history(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        v, _, _, _ = analyse(fixtures, "multi-branch", self.text(facts))
        assert v.lines["1.4.x"].actual_affected[-1] == "1.4.8"
        assert v.lines["1.6.x"].actual_affected[-1] == "1.6.3"
        assert v.lines["2.0.x"].actual_affected == ["2.0.1", "2.0.2"]
        assert v.status == "confirmed"

    def test_resolved_range_is_per_line(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        v, _, _, _ = analyse(fixtures, "multi-branch", self.text(facts))
        assert v.resolved_range is not None
        for tag, expected in [
            ("1.4.8", True), ("1.4.9", False),
            ("1.6.3", True), ("1.6.4", False),
            ("2.0.2", True), ("2.0.3", False),
        ]:
            assert (Version(tag) in v.resolved_range) is expected, tag

    def test_evidence_is_attached(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        v, _, _, _ = analyse(fixtures, "multi-branch", self.text(facts))
        for f in v.findings:
            if f.kind is FindingKind.BACKPORT_FOUND:
                assert any("patch-id" in e for e in f.evidence)
        assert v.confidence > 0.6
        assert "repository history" in v.basis

    def test_advisory_naming_backport_hash_also_works(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        text = (
            "All releases before 1.4.9 are affected on the 1.4 branch. "
            "The 1.6 branch is affected up to 1.6.3. "
            f"Fixed in commit {facts['fix_1_4']}."
        )
        v, _, _, _ = analyse(fixtures, "multi-branch", text)
        assert v.lines["1.4.x"].actual_fixed == ["1.4.9"]
        # Starting from the 1.4 backport, the other lines are equivalent patches.
        assert v.lines["1.6.x"].actual_fixed == ["1.6.4"]

    def test_discovery_via_cve_id_needs_no_commit(self, fixtures) -> None:
        v, _, _, _ = analyse(
            fixtures, "multi-branch", "All releases before 1.6.4 are affected. Fixed in 1.6.4."
        )
        present = [f for f in v.fix_commits if f.present]
        assert present and present[0].source == "discovered"
        assert v.lines["1.6.x"].actual_fixed == ["1.6.4"]


class TestUnderstatedAdvisory:
    """The advisory claims only 1.0.x; the 1.1.x line is affected too."""

    TEXT = "All versions before 1.0.2 are affected. Fixed in 1.0.2."

    def test_missing_line_is_reported(self, fixtures) -> None:
        v, _, _, _ = analyse(fixtures, "wrong-advisory", self.TEXT)
        under = [f for f in v.findings if f.kind is FindingKind.UNDER_DECLARED]
        assert under, [f.message for f in v.findings]
        assert "1.1.0" in under[0].version or "1.1.1" in under[0].version

    def test_status_and_confidence_reflect_disagreement(self, fixtures) -> None:
        v, _, _, _ = analyse(fixtures, "wrong-advisory", self.TEXT)
        assert v.status == "disputed"
        assert v.confidence < 0.75

    def test_comparing_declared_and_actual_is_possible(self, fixtures) -> None:
        v, _, _, _ = analyse(fixtures, "wrong-advisory", self.TEXT)
        line = v.lines["1.x"]
        assert line.declared_affected == ["1.0.0", "1.0.1"]
        assert line.actual_affected == ["1.0.0", "1.0.1", "1.1.0", "1.1.1"]
        assert line.actual_fixed == ["1.1.2"]


class TestOverstatedAdvisory:
    def test_over_declared_release_is_reported(self, fixtures) -> None:
        text = (
            "Versions 1.0.0, 1.0.1, 1.1.0, 1.1.1 and 1.1.2 are affected. "
            "Fixed in 1.1.2."
        )
        v, _, _, _ = analyse(fixtures, "wrong-advisory", text)
        over = [f for f in v.findings if f.kind is FindingKind.OVER_DECLARED]
        assert over
        assert "1.1.2" in over[0].version


class TestFixNeverShipped:
    def test_all_releases_affected_and_fix_unreleased(self, fixtures) -> None:
        _, facts = fixtures["fix-never-shipped"]
        text = f"All versions are affected. Fixed in commit {facts['fix']}."
        v, _, _, _ = analyse(fixtures, "fix-never-shipped", text)
        assert FindingKind.FIX_NEVER_RELEASED in kinds(v)
        assert v.lines["1.x"].actual_fixed == []
        assert v.lines["1.x"].actual_affected == ["1.0.0", "1.0.1", "1.1.0"]
        assert v.confidence < 0.8

    def test_claiming_a_release_that_lacks_the_fix_is_an_error(self, fixtures) -> None:
        _, facts = fixtures["fix-never-shipped"]
        text = "All versions before 1.1.0 are affected. Fixed in 1.1.0."
        v, _, _, _ = analyse(fixtures, "fix-never-shipped", text)
        assert errors(v), [f.message for f in v.findings]
        assert FindingKind.FIX_NOT_IN_CLAIMED_RELEASE in kinds(v)


class TestMissingCommit:
    def test_nonexistent_commit_is_an_error_with_low_confidence(self, fixtures) -> None:
        text = (
            "All versions before 1.0.1 are affected. "
            "Fixed in commit deadbeefdeadbeefdeadbeefdeadbeefdeadbeef."
        )
        v, _, _, _ = analyse(fixtures, "missing-fix-commit", text)
        assert FindingKind.FIX_COMMIT_MISSING in kinds(v)
        missing = [f for f in v.findings if f.kind is FindingKind.FIX_COMMIT_MISSING][0]
        assert missing.severity == "error"
        assert v.basis.startswith("advisory text only")
        assert v.confidence <= 0.5
        assert not any(f.present for f in v.fix_commits)

    def test_no_commit_means_no_invented_history(self, fixtures) -> None:
        text = "All versions before 1.0.1 are affected. Fixed in commit 0123456789abcdef."
        v, _, _, _ = analyse(fixtures, "missing-fix-commit", text)
        # Without a fix in history, no release can be asserted affected.
        assert v.lines["1.0.x"].actual_affected == []
        assert any("advisory text alone" in n or "could not be checked" in n for n in v.notes)


class TestDiscovery:
    def test_fix_found_from_commit_message(self, fixtures) -> None:
        text = "All versions before 1.1.2 are affected. Fixed in 1.1.2."
        v, _, facts, _ = analyse(fixtures, "wrong-advisory", text, "CVE-2024-9999")
        present = [f for f in v.fix_commits if f.present]
        assert present
        assert present[0].source == "discovered"
        assert present[0].sha.startswith(facts["fix"])
        assert v.basis.startswith("repository history")

    def test_discovered_fix_lowers_confidence_vs_named(self, fixtures) -> None:
        _, facts = fixtures["wrong-advisory"]
        named = (
            "All versions before 1.1.2 are affected. "
            f"Fixed in commit {facts['fix']}."
        )
        v_named, _, _, _ = analyse(fixtures, "wrong-advisory", named)
        v_found, _, _, _ = analyse(
            fixtures, "wrong-advisory",
            "All versions before 1.1.2 are affected. Fixed in 1.1.2.",
        )
        assert v_named.confidence >= v_found.confidence

    def test_uninformative_text_discovers_nothing(self, fixtures) -> None:
        # "All versions before 1.0.2" names no topic and no identifier, so the
        # verifier must not guess a fix commit from vague words.
        v, _, _, _ = analyse(fixtures, "calver", "Affected: all versions. Fixed in 2024.03.1.",
                             "CVE-0000-0000")
        assert not any(f.present for f in v.fix_commits)
        assert v.basis.startswith("advisory text only")


class TestCalver:
    def test_calendar_versions(self, fixtures) -> None:
        text = "Versions 2024.01.0 through 2024.03.0 are affected. Fixed in 2024.03.1."
        v, _, _, _ = analyse(fixtures, "calver", text)
        assert v.lines["2024.x"].actual_affected == [
            "2024.01.0", "2024.02.0", "2024.03.0",
        ]
        assert v.lines["2024.x"].actual_fixed[0] == "2024.03.1"
        assert v.status == "confirmed"

    def test_prerelease_after_the_fix_is_unaffected(self, fixtures) -> None:
        text = "Versions 2024.01.0 through 2024.03.0 are affected. Fixed in 2024.03.1."
        v, _, _, universe = analyse(fixtures, "calver", text)
        assert "2024.04.0-rc1" in universe.parsed_tags
        # The rc was tagged after the fix, so it contains it.  It is also
        # sorted below 2024.04.0, so "fixed in 2024.03.1" applies to it.
        assert "2024.04.0-rc1" in v.lines["2024.x"].actual_fixed
        assert Version("2024.04.0-rc1") not in {Version(t) for t in v.lines["2024.x"].actual_affected}


class TestDebian:
    def test_revision_ordering_in_range(self, fixtures) -> None:
        _, facts = fixtures["epoch-debian"]
        text = f"Versions before 1.0.0-1 are affected. Fixed in commit {facts['fix']}."
        v, _, _, _ = analyse(fixtures, "epoch-debian", text)
        assert v.lines["1.0.x"].actual_affected == ["0.9.0-1", "0.9.0-2", "0.9.0-10"]

    def test_revision_ordering_without_commit_evidence(self, fixtures) -> None:
        v, adv, _, _ = analyse(fixtures, "epoch-debian", "Versions before 1.0.0-1 are affected.")
        declared = adv.declared_affected
        assert Version("0.9.0-10") in declared
        assert Version("1.0.0-1") not in declared
        assert v.confidence <= 0.5


class TestNoFalsePositives:
    def test_global_range_catches_a_backpatched_release(self, fixtures) -> None:
        # "All releases before 1.6.4" is a *global* claim, but 1.4.9 already
        # carries the backport, so the global claim over-reaches onto 1.4.x.
        # Catching this is the point of checking ranges against history: a
        # reader of the advisory would wrongly upgrade 1.4.8 -> 1.4.9 for no
        # reason, and a scanner would wrongly flag 1.4.9.
        text = "All releases before 1.6.4 are affected. Fixed in 1.6.4."
        v, _, _, _ = analyse(fixtures, "multi-branch", text)
        over = [f for f in errors(v) if f.kind is FindingKind.OVER_DECLARED]
        assert over, [f.message for f in v.findings]
        assert over[0].line == "1.4.x"
        assert "1.4.9" in over[0].version
        assert v.lines["1.6.x"].actual_fixed == ["1.6.4"]

    def test_line_scoped_advisories_produce_no_errors(self, fixtures) -> None:
        text = (
            "All releases before 1.6.4 are affected on the 1.6 branch. "
            "All releases before 1.4.9 are affected on the 1.4 branch. "
            "Releases 2.0.1 and 2.0.2 are affected."
        )
        v, _, _, _ = analyse(fixtures, "multi-branch", text)
        assert not errors(v), [f.message for f in errors(v)]
        assert v.status == "confirmed"
        assert v.confidence > 0.75

    def test_matching_advisory_is_confirmed(self, fixtures) -> None:
        text = (
            "All releases before 1.6.4 are affected on the 1.6 branch. "
            "All releases before 1.4.9 are affected on the 1.4 branch. "
            "Releases 2.0.1 and 2.0.2 are affected."
        )
        v, _, _, _ = analyse(fixtures, "multi-branch", text)
        assert FindingKind.RANGE_MATCHES in kinds(v)


class TestReportShape:
    def test_verification_serialises_with_evidence(self, fixtures) -> None:
        _, facts = fixtures["multi-branch"]
        v, _, _, _ = analyse(
            fixtures, "multi-branch",
            "All releases before 1.4.9 are affected on the 1.4 branch. "
            f"Fixed in commit {facts['fix_main']}.",
        )
        d = v.to_dict()
        assert d["status"] in {"confirmed", "partial", "disputed"}
        assert d["confidence"] > 0
        assert d["fix_commits"][0]["evidence"]
        assert "1.4.x" in d["lines"]
        for f in d["findings"]:
            assert f["kind"] and f["message"]


class TestHonesty:
    """A result must never look better than the evidence behind it."""

    def test_no_fix_evidence_is_never_confirmed(self, fixtures) -> None:
        v, _, _, _ = analyse(
            fixtures, "multi-branch",
            "All releases before 1.4.9 are affected on the 1.4 branch.",
            "CVE-0000-00000",
        )
        assert not any(f.present for f in v.fix_commits)
        assert v.status == "partial"
        assert FindingKind.UNVERIFIED in kinds(v)
        assert v.confidence <= 0.5
        # The advisory's own range is preserved as the resolved answer.
        assert v.resolved_range is not None
        assert Version("1.4.8") in v.resolved_range

    def test_require_fix_evidence_turns_absence_into_an_error(self, fixtures) -> None:
        path, _facts = fixtures["multi-branch"]
        repo = GitRepo(path)
        universe = build_universe(repo)
        adv = extract_advisory(
            "CVE-0000-00000",
            "All releases before 1.4.9 are affected on the 1.4 branch.",
        )
        v = verify(adv, repo, universe, discover=False, require_fix_evidence=True)
        assert v.status == "disputed"
        assert any(f.severity == "error" for f in v.findings)

    def test_unverifiable_claim_is_named_not_smoothed(self, fixtures) -> None:
        v, _, _, _ = analyse(
            fixtures, "multi-branch",
            "All releases before 1.6.4 are affected. Fixed in 1.6.4.",
            "CVE-0000-00000",
        )
        messages = " ".join(f.message for f in v.findings)
        assert "no fix commit" in messages or "not checked" in messages
