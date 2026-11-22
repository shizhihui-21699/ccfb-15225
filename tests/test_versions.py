"""Version parsing and ordering across schemes."""

from __future__ import annotations

import pytest

from vulnrange.versions import (
    InvalidVersion,
    Version,
    VersionSet,
    extract_version_from_tag,
)
from vulnrange.versions.ranges import Interval


def v(text: str) -> Version:
    return Version(text)


class TestOrdering:
    @pytest.mark.parametrize(
        ("low", "high"),
        [
            ("1.2.3", "1.2.4"),
            ("1.2.3", "1.10.0"),
            ("1.2", "1.2.1"),
            ("1.9.9", "1.10.0"),
            ("1.2.3-rc1", "1.2.3"),
            ("1.2.3-rc1", "1.2.3-rc2"),
            ("1.2.3-alpha", "1.2.3-beta"),
            ("1.2.3-beta", "1.2.3-rc1"),
            ("1.2.3-dev", "1.2.3-alpha"),
            ("1.2.3-SNAPSHOT", "1.2.3"),
            ("1.2.3", "1.2.3.post1"),
            ("1.2.3", "1.2.3.1"),
            ("2.0", "2.0.0.1"),
            ("2023.9.30", "2023.10.1"),
            ("2024.1.0", "2024.02.0"),
        ],
    )
    def test_ascending(self, low: str, high: str) -> None:
        assert v(low) < v(high)
        assert v(high) > v(low)
        assert not (v(low) == v(high))

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            ("1.2", "1.2.0"),
            ("1.2.3", "v1.2.3"),
            ("1.2.3", "1.2.3.0"),
            ("1.2.3", "1.2.3+build7"),
            ("1.2.3.Final", "1.2.3"),
            ("1.2.3-RELEASE", "1.2.3"),
            ("1.2.3.GA", "1.2.3"),
        ],
    )
    def test_equal(self, a: str, b: str) -> None:
        assert v(a) == v(b)
        assert hash(v(a)) == hash(v(b))

    def test_ordering_is_total_and_symmetric(self) -> None:
        vals = [
            "0.9", "1.0", "1.0.0", "1.0.1", "1.0.1-rc1", "1.0.1.post1",
            "2:0.1", "2024.1", "1.0.Final", "1.0-2ubuntu1", "0.9.9",
        ]
        parsed = [v(x) for x in vals]
        for a in parsed:
            for b in parsed:
                assert (a < b) == (b > a)
                assert (a == b) == (b == a)
                if a != b:
                    assert (a < b) != (b < a)

    def test_sort(self) -> None:
        raw = ["1.10.0", "1.2.3", "1.2.3-rc1", "1.2.4", "1.2"]
        assert [x.raw for x in sorted(map(Version, raw))] == [
            "1.2", "1.2.3-rc1", "1.2.3", "1.2.4", "1.10.0",
        ]


class TestDebian:
    def test_tilde_sorts_before_release(self) -> None:
        assert v("1.0~rc1") < v("1.0")
        assert v("1.0~~") < v("1.0~rc1")
        assert v("1.0~rc1") < v("1.0~rc2")
        assert v("1.0~rc1") < v("1.0.1")
        assert v("1.0") < v("1.0.1")

    def test_revision_and_epoch_use_dpkg_order(self) -> None:
        assert v("1.0-3ubuntu2") < v("1.0-3ubuntu10")
        assert v("1.0-1") < v("1.0-2")
        assert v("2:0.5") > v("1:99.0")
        assert v("1:1.0") > v("0:9.9")

    def test_revision_is_not_a_prerelease(self) -> None:
        # dpkg: "-1" is a revision, so 0.9.0-10 > 0.9.0-2
        assert v("0.9.0-2") < v("0.9.0-10")
        assert v("0.9.0-10") < v("1.0.0-1")


class TestInvalid:
    @pytest.mark.parametrize("text", ["", "abc", "nightly", "v", "-1.0", "latest"])
    def test_rejects_non_versions(self, text: str) -> None:
        with pytest.raises(InvalidVersion):
            Version(text)


class TestTagExtraction:
    @pytest.mark.parametrize(
        ("tag", "expected"),
        [
            ("v1.2.3", "1.2.3"),
            ("1.2.3", "1.2.3"),
            ("release-1.2.3", "1.2.3"),
            ("RELEASE_1.2.3", "1.2.3"),
            ("version/2.0.0", "2.0.0"),
            ("rel-0.9.0", "0.9.0"),
            ("2024.01.0", "2024.01.0"),
            ("1.0.0-rc1", "1.0.0-rc1"),
        ],
    )
    def test_parses(self, tag: str, expected: str) -> None:
        got = extract_version_from_tag(tag)
        assert got is not None
        assert got.raw == expected

    def test_strips_project_prefix(self) -> None:
        assert extract_version_from_tag("acme-widget-1.4.9", ("acme-widget",)).raw == "1.4.9"

    @pytest.mark.parametrize("tag", ["nightly", "latest", "main", "latest-release"])
    def test_rejects_moving_tags(self, tag: str) -> None:
        assert extract_version_from_tag(tag) is None


class TestVersionSet:
    def test_upper_bound_exclusive(self) -> None:
        s = VersionSet([Interval(hi=v("2.4.0"), hi_inc=False)])
        assert v("2.3.9") in s
        assert v("2.4.0") not in s
        assert v("0.0.1") in s

    def test_upper_bound_inclusive(self) -> None:
        s = VersionSet([Interval(hi=v("2.4.0"), hi_inc=True)])
        assert v("2.4.0") in s
        assert v("2.4.1") not in s

    def test_closed_interval(self) -> None:
        s = VersionSet([Interval(lo=v("3.0.0"), hi=v("3.2.1"))])
        assert v("3.0.0") in s
        assert v("3.2.0") in s
        assert v("3.2.1") not in s
        assert v("2.9.9") not in s

    def test_union_merges_adjacent(self) -> None:
        a = VersionSet([Interval(lo=v("1.0"), hi=v("2.0"))])
        b = VersionSet([Interval(lo=v("2.0"), hi=v("3.0"))])
        merged = a.union(b)
        assert len(merged.intervals) == 1
        assert v("2.0") in merged

    def test_union_keeps_real_gaps(self) -> None:
        # [1.0, 2.0) and [2.0.1, 3.0): versions strictly between 2.0 and 2.0.1
        # exist (2.0.0.1), so the gap is real and must not be merged.
        a = VersionSet([Interval(lo=v("1.0"), hi=v("2.0"))])
        b = VersionSet([Interval(lo=v("2.0.1"), hi=v("3.0"))])
        assert len(a.union(b).intervals) == 2
        assert v("1.5") in a.union(b)
        assert v("2.0") not in a.union(b)
        assert v("2.0.1") in a.union(b)

    def test_union_merges_when_one_side_includes_the_shared_point(self) -> None:
        a = VersionSet([Interval(lo=v("1.0"), hi=v("2.0"), hi_inc=True)])
        b = VersionSet([Interval(lo=v("2.0"), hi=v("3.0"))])
        assert len(a.union(b).intervals) == 1

    def test_intersection(self) -> None:
        a = VersionSet([Interval(hi=v("2.4.0"))])
        b = VersionSet([Interval(lo=v("1.6.0"), lo_inc=True, hi=v("1.7.0"))])
        got = a.intersection(b)
        assert v("1.6.5") in got
        assert v("2.0.0") not in got
        assert v("1.5.0") not in got

    def test_complement_and_difference(self) -> None:
        s = VersionSet([Interval(lo=v("1.0"), hi=v("2.0"))])
        comp = s.complement()
        assert v("0.9") in comp
        assert v("2.0") in comp
        assert v("1.5") not in comp
        assert s.difference(s).is_empty

    def test_all_versions(self) -> None:
        assert v("0.0.1") in VersionSet.everything()
        assert VersionSet.everything().describe() == "all versions"

    def test_discrete_points(self) -> None:
        s = VersionSet([Interval(lo=v("2.0.1"), hi=v("2.0.1"), hi_inc=True)])
        assert v("2.0.1") in s
        assert v("2.0.2") not in s


class TestCrossSchemeSymmetry:
    """Different schemes must still form one consistent order."""

    SAMPLES = [
        "1.0", "1.0.0", "1.0.1", "1.0.Final", "1.0-rc1", "1.0-2ubuntu1",
        "1:0.9", "2:0.1", "2024.01.0", "2019.9.9", "1.0.post1", "1.0~rc1",
    ]

    def test_all_pairs_are_ordered_consistently(self) -> None:
        parsed = [Version(s) for s in self.SAMPLES]
        for a in parsed:
            for b in parsed:
                if a < b:
                    assert b > a
                    assert not a == b
                elif a == b:
                    assert b == a
                    assert not a < b
                else:
                    assert b < a

    def test_sorting_is_idempotent(self) -> None:
        # Several samples are equal by design ("1.0" == "1.0.0" == "1.0.Final"),
        # so the comparison is over equivalence classes, not raw strings.
        parsed = [Version(s) for s in self.SAMPLES]
        once = sorted(parsed)
        twice = sorted(reversed(once))
        assert [x.raw for x in once] == [x.raw for x in twice] or all(
            a == b for a, b in zip(once, twice)
        )
        assert all(a == b for a, b in zip(once, twice))
