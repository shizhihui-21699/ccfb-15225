"""Build realistic git repositories for the test suite.

Security work is full of history shapes that a synthetic single-branch repo
never exercises: a fix on main that must be cherry-picked to a maintenance
branch (different hash, same patch), a fix that exists on a branch but never
shipped, tags on annotated tag objects, and a maintenance line that is simply
forgotten.  Each scenario here produces one of those, deterministically, so
the verifier can be tested against history that behaves like the real thing.

Every repo is created with fixed author/committer identity and fixed timestamps
so `git` output is reproducible.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "RepoBuilder",
    "Scenario",
    "SCENARIOS",
    "build_scenario",
]

_ENV = {
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "author@example.invalid",
    "GIT_COMMITTER_NAME": "Test Committer",
    "GIT_COMMITTER_EMAIL": "committer@example.invalid",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_DATE": "2024-01-01T00:00:00 +0000",
    "GIT_COMMITTER_DATE": "2024-01-01T00:00:00 +0000",
}


class RepoBuilder:
    """Small, explicit git driver for building fixtures."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self._tick = 0
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test Author")
        self.git("config", "user.email", "author@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")

    def git(self, *args: str, check: bool = True) -> str:
        env = {
            **os.environ,
            **_ENV,
            "GIT_AUTHOR_DATE": f"2024-01-{1 + self._tick // 24:02d}T{self._tick % 24:02d}:00:00 +0000",
            "GIT_COMMITTER_DATE": f"2024-01-{1 + self._tick // 24:02d}T{self._tick % 24:02d}:00:00 +0000",
        }
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed in {self.path}: {proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    def commit(self, message: str, *, files: dict[str, str] | None = None) -> str:
        self._tick += 1
        for name, content in (files or {"README.md": f"# demo\n\n{message}\n"}).items():
            p = self.path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message, "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def tag(self, name: str, *, annotated: bool = False, ref: str = "HEAD") -> str:
        if annotated:
            self.git("tag", "-a", name, "-m", f"release {name}", ref)
        else:
            self.git("tag", name, ref)
        return self.git("rev-parse", f"{ref}^{{commit}}")

    def branch(self, name: str, *, start: str = "HEAD") -> None:
        self.git("checkout", "-q", "-B", name, start)

    def checkout(self, ref: str) -> None:
        self.git("checkout", "-q", ref)

    def cherry_pick(self, sha: str) -> str:
        self._tick += 1
        self.git("cherry-pick", "-x", sha)
        return self.git("rev-parse", "HEAD")

    def merge(self, branch: str, message: str = "Merge branch") -> str:
        self._tick += 1
        self.git("merge", "--no-ff", "-q", "-m", message, branch)
        return self.git("rev-parse", "HEAD")


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    build: object  # Callable[[Path], dict] -> returns facts for assertions


def _scenario_multi_branch(tmp: Path) -> dict:
    """One fix, cherry-picked onto two maintenance lines.

    * ``1.4.x`` branched off before 1.6; the fix was backported as ``1.4.9``.
    * ``2.0.x`` branched off before the fix; the fix was backported as ``2.0.3``.
    * main carries the fix and shipped it as ``1.6.4``.

    All three fixes are the *same patch* with different hashes, so a verifier
    that only compares commit IDs sees three unrelated commits.  Matching by
    ``patch-id`` is what ties them together.
    """
    vuln = "def parse(s):\n    return s\n"
    fixed = (
        "def parse(s):\n"
        "    if s.count('(') != s.count(')'):\n"
        "        raise ValueError\n"
        "    return s\n"
    )
    b = RepoBuilder(tmp)
    b.commit("initial import", files={"parse.py": vuln})
    b.tag("1.4.0", annotated=True)
    for v in ("1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.4.7", "1.4.8"):
        b.commit(f"chore: bump {v}", files={"CHANGELOG": v})
        b.tag(v)

    b.branch("1.4.x", start="HEAD")
    b.checkout("main")
    b.commit("feat: app rewrite", files={"app.py": "import parse  # v2\n"})
    b.tag("1.6.0")
    for v in ("1.6.1", "1.6.2", "1.6.3"):
        b.commit(f"chore: bump {v}", files={"CHANGELOG": v})
        b.tag(v)

    # 2.0.x forks here, before the fix, and is tagged from a separate history.
    b.branch("2.0.x", start="HEAD")
    b.commit("feat: 2.0 api", files={"api.py": "VERSION = '2.0'\n"})
    b.tag("2.0.1")
    b.commit("chore: bump 2.0.2", files={"CHANGELOG": "2.0.2"})
    b.tag("2.0.2")

    b.checkout("main")
    b.commit("fix: reject unbalanced input (CVE-2024-4242)", files={"parse.py": fixed})
    fix_main = b.git("rev-parse", "HEAD")
    b.tag("1.6.4")

    b.checkout("1.4.x")
    fix_14 = b.cherry_pick(fix_main)
    b.tag("1.4.9")

    b.checkout("2.0.x")
    fix_20 = b.cherry_pick(fix_main)
    b.tag("2.0.3")

    b.checkout("main")
    b.branch("1.6.x", start="1.6.4")
    b.branch("2.0.x", start="2.0.3")

    return {
        "fix_main": fix_main,
        "fix_1_4": fix_14,
        "fix_2_0": fix_20,
        "affected": {
            "1.4.x": [f"1.4.{i}" for i in range(9)],
            "1.6.x": ["1.6.0", "1.6.1", "1.6.2", "1.6.3"],
            "2.0.x": ["2.0.1", "2.0.2"],
        },
        "fixed": {"1.4.x": "1.4.9", "1.6.x": "1.6.4", "2.0.x": "2.0.3"},
    }


def _scenario_fix_never_shipped(tmp: Path) -> dict:
    """The fix exists on main but was never tagged: every release is affected."""
    b = RepoBuilder(tmp)
    b.commit("initial", files={"app.py": "def run(cmd):\n    return eval(cmd)\n"})
    for v in ("1.0.0", "1.0.1", "1.1.0"):
        b.commit(f"chore: bump {v}", files={"CHANGELOG": v})
        b.tag(v)
    b.commit("fix: remove eval (GHSA-2222-3333-4444)", files={"app.py": "def run(cmd):\n    raise NotImplementedError\n"})
    fix = b.git("rev-parse", "HEAD")
    b.commit("docs: notes", files={"README.md": "# notes\n"})
    return {
        "fix": fix,
        "affected": {"1.0.x": ["1.0.0", "1.0.1"], "1.1.x": ["1.1.0"]},
        "fixed": {},
    }


def _scenario_wrong_advisory(tmp: Path) -> dict:
    """Advisory understates the range: it says only 1.0.x, but 1.1.x is hit too."""
    b = RepoBuilder(tmp)
    b.commit("initial", files={"core.py": "A = 1\n"})
    b.tag("1.0.0")
    b.commit("chore", files={"CHANGELOG": "1.0.1"})
    b.tag("1.0.1")
    b.commit("feat", files={"core.py": "A = 2\n"})
    b.tag("1.1.0")
    b.commit("chore", files={"CHANGELOG": "1.1.1"})
    b.tag("1.1.1")
    b.commit("fix: bounds check (CVE-2024-9999)", files={"core.py": "A = 2\nassert A < 3\n"})
    fix = b.git("rev-parse", "HEAD")
    b.tag("1.1.2")
    return {
        "fix": fix,
        "affected": {"1.0.x": ["1.0.0", "1.0.1"], "1.1.x": ["1.1.0", "1.1.1"]},
        "fixed": {"1.1.x": "1.1.2"},
    }


def _scenario_calver(tmp: Path) -> dict:
    """Calendar versioning, plus a pre-release tag that must sort below release."""
    b = RepoBuilder(tmp)
    b.commit("initial", files={"tool.py": "X = 0\n"})
    for tag in ("2024.01.0", "2024.02.0", "2024.03.0"):
        b.commit(f"chore: {tag}", files={"CHANGELOG": tag})
        b.tag(tag)
    b.commit("fix: escaping (CVE-2024-7777)", files={"tool.py": "X = 1\n"})
    fix = b.git("rev-parse", "HEAD")
    b.tag("2024.03.1")
    b.commit("chore: next", files={"CHANGELOG": "next"})
    b.tag("2024.04.0-rc1")
    return {
        "fix": fix,
        "affected": {"2024.03.x": ["2024.01.0", "2024.02.0", "2024.03.0"]},
        "fixed": {"2024.03.x": "2024.03.1"},
    }


def _scenario_missing_fix_commit(tmp: Path) -> dict:
    """The advisory names a commit that does not exist in this repo."""
    b = RepoBuilder(tmp)
    b.commit("initial", files={"lib.py": "Y = 0\n"})
    b.tag("0.9.0")
    b.tag("1.0.0")
    b.commit("fix: something", files={"lib.py": "Y = 1\n"})
    fix = b.git("rev-parse", "HEAD")
    b.tag("1.0.1")
    return {
        "fix": fix,
        "affected": {"1.0.x": ["0.9.0", "1.0.0"]},
        "fixed": {"1.0.x": "1.0.1"},
    }


def _scenario_epoch_debian(tmp: Path) -> dict:
    """Debian-style versions with an upstream revision and ``~rc`` ordering.

    Git refuses ``:`` in tag names, so Debian epochs live in the versions as
    ``1.0.0-1`` / ``1.0.0-2`` here; epoch handling itself is unit-tested in
    ``tests/test_versions.py``.
    """
    b = RepoBuilder(tmp)
    b.commit("initial", files={"x": "1"})
    b.tag("0.9.0-1")
    b.tag("0.9.0-2")
    b.tag("0.9.0-10")
    b.commit("fix: crash", files={"x": "2"})
    fix = b.git("rev-parse", "HEAD")
    b.tag("1.0.0-1")
    return {
        "fix": fix,
        "affected": {"1.0.x": ["0.9.0-1", "0.9.0-2", "0.9.0-10"]},
        "fixed": {"1.0.x": "1.0.0-1"},
    }


SCENARIOS: dict[str, Scenario] = {
    "multi-branch": Scenario(
        "multi-branch",
        "one fix on main, backported to 1.4.x, plus a separate 2.0.x fix",
        _scenario_multi_branch,
    ),
    "fix-never-shipped": Scenario(
        "fix-never-shipped",
        "fix exists on a branch but in no release tag",
        _scenario_fix_never_shipped,
    ),
    "wrong-advisory": Scenario(
        "wrong-advisory",
        "advisory understates the affected range",
        _scenario_wrong_advisory,
    ),
    "calver": Scenario(
        "calver",
        "calendar versions and a pre-release tag",
        _scenario_calver,
    ),
    "missing-fix-commit": Scenario(
        "missing-fix-commit",
        "advisory names a commit absent from the repository",
        _scenario_missing_fix_commit,
    ),
    "epoch-debian": Scenario(
        "epoch-debian",
        "Debian epochs and revisions",
        _scenario_epoch_debian,
    ),
}


def build_scenario(name: str, dest: Path) -> tuple[Path, dict]:
    try:
        scen = SCENARIOS[name]
    except KeyError:
        raise KeyError(f"unknown scenario {name!r}; choose from {sorted(SCENARIOS)}") from None
    path = Path(dest) / name
    facts = scen.build(path)  # type: ignore[operator]
    return path, facts
