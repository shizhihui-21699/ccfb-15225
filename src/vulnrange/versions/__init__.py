"""Scheme-tolerant version parsing, ordering and range algebra."""

from .ranges import ALL, EMPTY, Interval, IncomparableVersion, VersionSet
from .version import (
    VERSION_TOKEN,
    InvalidVersion,
    Version,
    detect_scheme,
    extract_version_from_tag,
)

__all__ = [
    "ALL",
    "EMPTY",
    "Interval",
    "IncomparableVersion",
    "VersionSet",
    "VERSION_TOKEN",
    "InvalidVersion",
    "Version",
    "detect_scheme",
    "extract_version_from_tag",
]
