"""Text and structured text content binding verifiers.

Handles C2PATextManifestWrapper (text/plain, text/markdown) and
structured text delimiters (SVG, XHTML).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from c2pa_conformance.crypto.hashing import (
    ExclusionRange,
    compare_hash,
    compute_hash,
    is_algorithm_supported,
)


@dataclass
class TextHashResult:
    """Result of text or structured text hash verification."""

    is_valid: bool
    status_code: str
    message: str
    algorithm: str = ""
    wrapper_count: int = 0


class TextHashError(Exception):
    """Raised when text hash verification encounters an unrecoverable error."""


# C2PATextManifestWrapper magic header bytes (C2PA v2.4 spec)
_TEXT_WRAPPER_MAGIC = b"C2PATXT\x00"

# Structured text PEM-style delimiters
_STRUCTURED_BEGIN = b"-----BEGIN C2PA MANIFEST-----"
_STRUCTURED_END = b"-----END C2PA MANIFEST-----"


def find_text_wrappers(asset_bytes: bytes) -> list[tuple[int, int]]:
    """Find all C2PATextManifestWrapper instances in asset bytes.

    Each wrapper starts at the magic header and extends to the start of the
    next wrapper (or end of file).  Returns a list of (start, end) byte
    offsets - one tuple per wrapper found.
    """
    wrappers: list[tuple[int, int]] = []
    pos = 0
    while True:
        idx = asset_bytes.find(_TEXT_WRAPPER_MAGIC, pos)
        if idx == -1:
            break
        next_idx = asset_bytes.find(_TEXT_WRAPPER_MAGIC, idx + len(_TEXT_WRAPPER_MAGIC))
        end = next_idx if next_idx != -1 else len(asset_bytes)
        wrappers.append((idx, end))
        pos = idx + len(_TEXT_WRAPPER_MAGIC)
    return wrappers


def find_structured_delimiters(asset_bytes: bytes) -> list[tuple[int, int]]:
    """Find structured text delimiter blocks in asset bytes.

    Looks for paired -----BEGIN C2PA MANIFEST----- / -----END C2PA MANIFEST-----
    delimiters.  Returns a list of (start, end) byte offsets covering the full
    delimiter block including the end marker.
    """
    blocks: list[tuple[int, int]] = []
    pos = 0
    while True:
        begin_idx = asset_bytes.find(_STRUCTURED_BEGIN, pos)
        if begin_idx == -1:
            break
        end_idx = asset_bytes.find(_STRUCTURED_END, begin_idx)
        if end_idx == -1:
            break
        block_end = end_idx + len(_STRUCTURED_END)
        blocks.append((begin_idx, block_end))
        pos = block_end
    return blocks


def verify_text_hash(
    asset_bytes: bytes,
    assertion_data: dict[str, Any],
) -> TextHashResult:
    """Verify a C2PATextManifestWrapper data hash.

    Steps:
    1. Validate algorithm and declared hash.
    2. Find wrapper(s) in asset bytes.
    3. Require exactly one wrapper.
    4. Compute hash excluding wrapper bytes.
    5. Compare against declared hash.

    Args:
        asset_bytes: The complete raw asset file bytes.
        assertion_data: Parsed assertion data dict with "alg" and "hash" keys.

    Returns:
        TextHashResult with match/mismatch/error status.
    """
    alg = assertion_data.get("alg")
    if not alg or not is_algorithm_supported(str(alg)):
        return TextHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported or missing algorithm: {alg}",
        )

    declared = assertion_data.get("hash")
    if not declared or not isinstance(declared, bytes):
        return TextHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message="Missing or invalid 'hash' field",
        )

    wrappers = find_text_wrappers(asset_bytes)

    if not wrappers:
        return TextHashResult(
            is_valid=False,
            status_code="manifest.text.corruptedWrapper",
            message="No C2PATextManifestWrapper found in asset",
            wrapper_count=0,
        )

    if len(wrappers) > 1:
        return TextHashResult(
            is_valid=False,
            status_code="manifest.text.multipleWrappers",
            message=f"Found {len(wrappers)} wrappers, expected exactly 1",
            wrapper_count=len(wrappers),
        )

    start, end = wrappers[0]
    exclusion = ExclusionRange(start=start, length=end - start)
    computed = compute_hash(asset_bytes, str(alg), [exclusion])

    if compare_hash(computed, declared):
        return TextHashResult(
            is_valid=True,
            status_code="assertion.dataHash.match",
            message="Text hash matches",
            algorithm=str(alg),
            wrapper_count=1,
        )
    return TextHashResult(
        is_valid=False,
        status_code="assertion.dataHash.mismatch",
        message="Text hash mismatch",
        algorithm=str(alg),
        wrapper_count=1,
    )


def verify_structured_text_hash(
    asset_bytes: bytes,
    assertion_data: dict[str, Any],
) -> TextHashResult:
    """Verify a structured text (SVG/XHTML) data hash.

    Steps:
    1. Validate algorithm and declared hash.
    2. Find delimiter block(s) in asset bytes.
    3. Require exactly one block.
    4. Compute hash excluding delimiter block bytes.
    5. Compare against declared hash.

    Args:
        asset_bytes: The complete raw asset file bytes.
        assertion_data: Parsed assertion data dict with "alg" and "hash" keys.

    Returns:
        TextHashResult with match/mismatch/error status.
    """
    alg = assertion_data.get("alg")
    if not alg or not is_algorithm_supported(str(alg)):
        return TextHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported or missing algorithm: {alg}",
        )

    declared = assertion_data.get("hash")
    if not declared or not isinstance(declared, bytes):
        return TextHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message="Missing or invalid 'hash' field",
        )

    blocks = find_structured_delimiters(asset_bytes)

    if not blocks:
        return TextHashResult(
            is_valid=False,
            status_code="manifest.structuredText.noManifest",
            message="No structured text delimiter block found in asset",
        )

    if len(blocks) > 1:
        return TextHashResult(
            is_valid=False,
            status_code="manifest.structuredText.multipleReferences",
            message=f"Found {len(blocks)} delimiter blocks, expected exactly 1",
        )

    start, end = blocks[0]
    exclusion = ExclusionRange(start=start, length=end - start)
    computed = compute_hash(asset_bytes, str(alg), [exclusion])

    if compare_hash(computed, declared):
        return TextHashResult(
            is_valid=True,
            status_code="assertion.dataHash.match",
            message="Structured text hash matches",
            algorithm=str(alg),
            wrapper_count=1,
        )
    return TextHashResult(
        is_valid=False,
        status_code="assertion.dataHash.mismatch",
        message="Structured text hash mismatch",
        algorithm=str(alg),
        wrapper_count=1,
    )
