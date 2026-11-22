"""vulnrange — extract and verify affected-version ranges from advisories.

The pipeline is three steps, each usable on its own:

    from vulnrange.advisory import extract_advisory
    from vulnrange.repo.git import GitRepo
    from vulnrange.analysis.universe import build_universe
    from vulnrange.analysis.verify import verify

    advisory = extract_advisory("CVE-2024-4242", text)
    repo = GitRepo("/path/to/checkout")
    result = verify(advisory, repo, build_universe(repo))
    print(result.status, result.confidence, result.resolved_range)
"""

from .advisory import Advisory, Claim, ClaimKind, extract_advisory
from .analysis.universe import Universe, build_universe
from .analysis.verify import Finding, FindingKind, Verification, verify
from .repo.git import GitError, GitRepo
from .versions import Version, VersionSet

__version__ = "0.1.0"

__all__ = [
    "Advisory",
    "Claim",
    "ClaimKind",
    "extract_advisory",
    "Universe",
    "build_universe",
    "Finding",
    "FindingKind",
    "Verification",
    "verify",
    "GitError",
    "GitRepo",
    "Version",
    "VersionSet",
    "__version__",
]
