"""Report rendering and CLI behaviour."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from build_fixtures import build_scenario  # noqa: E402

from vulnrange.advisory import extract_advisory
from vulnrange.analysis.universe import build_universe
from vulnrange.analysis.verify import verify
from vulnrange.cli import main, run_one
from vulnrange.report.render import summary_line, to_json, to_markdown, to_text

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    base = tmp_path_factory.mktemp("report")
    path, facts = build_scenario("multi-branch", base)
    text = (
        "# CVE-2024-4242\n\n"
        "All releases before 1.4.9 are affected on the 1.4 branch.\n"
        "The 1.6 branch is affected up to 1.6.3.\n"
        "Releases 2.0.1 and 2.0.2 are also affected.\n"
        f"Fixed in commit {facts['fix_main']}.\n"
    )
    adv_file = path.parent / "advisory.txt"
    adv_file.write_text(text, encoding="utf-8")
    repo = __import__("vulnrange.repo.git", fromlist=["GitRepo"]).GitRepo(path)
    universe = build_universe(repo)
    advisory = extract_advisory("CVE-2024-4242", text)
    verification = verify(advisory, repo, universe)
    return {
        "path": path,
        "adv_file": adv_file,
        "advisory": advisory,
        "verification": verification,
        "universe": universe,
        "facts": facts,
    }


class TestTextReport:
    def test_leads_with_verdict_and_confidence(self, scenario) -> None:
        text = to_text(scenario["verification"], scenario["advisory"], scenario["universe"])
        head = text.splitlines()[:6]
        assert any("CONFIRMED" in line for line in head)
        assert any("confidence" in line for line in head)
        assert any("basis" in line for line in head)

    def test_contains_evidence(self, scenario) -> None:
        text = to_text(scenario["verification"], scenario["advisory"], scenario["universe"])
        assert "patch-id" in text
        assert "1.4.9" in text
        assert "Per release line" in text

    def test_fix_shas_are_shortened_but_full_in_json(self, scenario) -> None:
        text = to_text(scenario["verification"], scenario["advisory"])
        assert scenario["facts"]["fix_main"][:12] in text
        payload = json.loads(to_json(scenario["verification"], scenario["advisory"]))
        assert payload["fix_commits"][0]["sha"] == scenario["facts"]["fix_main"]

    def test_summary_line_is_one_line(self, scenario) -> None:
        line = summary_line(scenario["verification"])
        assert "\n" not in line
        assert "CVE-2024-4242" in line
        assert "confidence=" in line


class TestJsonReport:
    def test_schema_is_stable(self, scenario) -> None:
        payload = json.loads(
            to_json(scenario["verification"], scenario["advisory"], scenario["universe"])
        )
        for key in (
            "advisory_id", "status", "confidence", "basis", "declared_range",
            "resolved_range", "fix_commits", "lines", "findings", "notes",
            "advisory", "repository",
        ):
            assert key in payload, key
        assert isinstance(payload["findings"], list)
        assert set(payload["lines"]) == {"1.4.x", "1.6.x", "2.0.x"}
        assert payload["repository"]["release_count"] == 18

    def test_unicode_survives(self, scenario) -> None:
        adv = extract_advisory("CVE-2024-4242", "2.0 之前的所有版本都受影响。修复于 2.0。")
        repo = scenario["verification"]
        payload = to_json(repo, adv)
        assert "2.0 之前" in payload


class TestMarkdownReport:
    def test_has_tables_and_findings(self, scenario) -> None:
        md = to_markdown(scenario["verification"], scenario["advisory"], scenario["universe"])
        assert md.startswith("# CVE-2024-4242")
        assert "| line |" in md
        assert "## Findings" in md
        assert "## Caveats" in md

    def test_pipes_in_evidence_are_escaped(self, scenario) -> None:
        md = to_markdown(scenario["verification"], scenario["advisory"])
        # Every table row must have a balanced number of cells.
        for row in md.splitlines():
            if row.startswith("| ") and not row.startswith("|---"):
                assert row.count("|") >= 3


class TestCli:
    def test_check_exit_zero_on_confirmed(self, scenario, capsys) -> None:
        code = main([
            "check", str(scenario["adv_file"]), "--repo", str(scenario["path"]),
        ])
        assert code == 0
        out = capsys.readouterr().out
        assert "CONFIRMED" in out

    def test_check_json_to_file(self, scenario, tmp_path, capsys) -> None:
        out_file = tmp_path / "report.json"
        code = main([
            "check", str(scenario["adv_file"]), "--repo", str(scenario["path"]),
            "--format", "json", "-o", str(out_file),
        ])
        assert code == 0
        payload = json.loads(out_file.read_text())
        assert payload["status"] == "confirmed"

    def test_exit_one_when_disputed(self, tmp_path, capsys) -> None:
        base = tmp_path / "repos"
        path, _facts = build_scenario("wrong-advisory", base)
        adv = tmp_path / "adv.txt"
        # The CVE ID is what lets the verifier find the fix commit in history;
        # the advisory understates the range, so the result must be disputed.
        adv.write_text(
            "# CVE-2024-9999\n\nAll versions before 1.0.2 are affected. Fixed in 1.0.2.",
            encoding="utf-8",
        )
        code = main(["check", str(adv), "--repo", str(path)])
        assert code == 1
        assert "DISPUTED" in capsys.readouterr().out

    def test_fail_on_never(self, tmp_path) -> None:
        base = tmp_path / "repos"
        path, _facts = build_scenario("wrong-advisory", base)
        adv = tmp_path / "adv.txt"
        adv.write_text(
            "# CVE-2024-9999\n\nAll versions before 1.0.2 are affected. Fixed in 1.0.2.",
            encoding="utf-8",
        )
        assert main([
            "check", str(adv), "--repo", str(path), "--fail-on", "never",
        ]) == 0

    def test_bad_repo_is_usage_error(self, tmp_path, capsys) -> None:
        adv = tmp_path / "adv.txt"
        adv.write_text("Fixed in 1.0.0", encoding="utf-8")
        code = main(["check", str(adv), "--repo", str(tmp_path / "nope")])
        assert code == 2
        assert "vulnrange:" in capsys.readouterr().err

    def test_missing_advisory_is_usage_error(self, scenario, capsys) -> None:
        code = main(["check", str(scenario["path"] / "absent.txt"), "--repo", str(scenario["path"])])
        assert code == 2

    def test_batch_with_repo(self, scenario, tmp_path, capsys) -> None:
        second = tmp_path / "second.txt"
        second.write_text(
            "All releases before 1.6.4 are affected on the 1.6 branch. Fixed in 1.6.4.",
            encoding="utf-8",
        )
        code = main([
            "batch", str(scenario["adv_file"]), str(second),
            "--repo", str(scenario["path"]), "--summary",
        ])
        out = capsys.readouterr().out
        assert out.count("confidence=") == 2
        assert code == 0

    def test_advisory_id_override(self, scenario, capsys) -> None:
        main([
            "check", str(scenario["adv_file"]), "--repo", str(scenario["path"]),
            "--advisory-id", "CVE-9999-0001",
        ])
        assert "CVE-9999-0001" in capsys.readouterr().out

    def test_require_fix_evidence_flag(self, tmp_path, capsys) -> None:
        base = tmp_path / "repos"
        path, _facts = build_scenario("calver", base)
        adv = tmp_path / "adv.txt"
        adv.write_text(
            "Versions 2024.01.0 through 2024.03.0 are affected. Fixed in 2024.03.1.",
            encoding="utf-8",
        )
        # No CVE in the text or filename, so discovery cannot identify a fix.
        code = main([
            "check", str(adv), "--repo", str(path), "--require-fix-evidence",
            "--advisory-id", "CVE-0000-0000", "--no-discover",
        ])
        out = capsys.readouterr().out
        assert code == 1
        assert "no fix commit could be established" in out


class TestRunOne:
    def test_returns_all_three_objects(self, scenario) -> None:
        advisory, universe, verification = run_one(
            scenario["adv_file"],
            __import__("vulnrange.repo.git", fromlist=["GitRepo"]).GitRepo(scenario["path"]),
        )
        assert advisory.advisory_id == "CVE-2024-4242"
        assert universe.releases
        assert verification.status == "confirmed"
