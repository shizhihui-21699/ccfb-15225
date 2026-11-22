"""Advisory parsing and its data model."""

from .extract import extract_advisory, segments, split_sentences
from .model import Advisory, Claim, ClaimKind

__all__ = [
    "Advisory",
    "Claim",
    "ClaimKind",
    "extract_advisory",
    "segments",
    "split_sentences",
]
