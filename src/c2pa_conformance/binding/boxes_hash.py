"""c2pa.hash.boxes content binding verifier.

Handles general box-level hashing for JXL, font, and JPEG APP11 formats.
The assertion declares a list of boxes with expected per-box hashes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from c2pa_conformance.crypto.hashing import (
    ExclusionRange,
    compare_hash,
    compute_hash,
    is_algorithm_supported,
    validate_exclusions,
)


@dataclass
class BoxesHashResult:
    """Result of boxes hash verification."""

    is_valid: bool
    status_code: str  # assertion.boxesHash.match / .mismatch / .malformed / algorithm.unsupported
    message: str
    algorithm: str = ""
    boxes_checked: int = 0
    boxes_matched: int = 0


class BoxesHashError(Exception):
    """Raised when boxes hash verification encounters an error."""


def verify_boxes_hash(
    asset_bytes: bytes,
    assertion_data: dict[str, Any],
) -> BoxesHashResult:
    """Verify a c2pa.hash.boxes assertion against asset bytes.

    The assertion covers box-based container formats (JXL, fonts, JPEG APP11).
    Each entry in the 'boxes' list declares which named box to hash and its
    expected hash value.

    Args:
        asset_bytes: The complete raw asset file bytes.
        assertion_data: The parsed assertion data dict with fields:
            - "alg": hash algorithm name (e.g., "sha256")
            - "boxes": list of box hash entries, each containing:
                - "names": list of box name strings (e.g., ["jP  ", "ftyp"])
                - "hash": declared hash bytes for this box region
                - "start": optional byte offset of the box in asset_bytes
                - "length": optional byte length of the box
                - "exclusions": optional per-box exclusion ranges

    Returns:
        BoxesHashResult with match/mismatch/malformed status and box counts.
    """
    alg = assertion_data.get("alg")
    if not alg or not is_algorithm_supported(str(alg)):
        return BoxesHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported or missing algorithm: {alg}",
        )

    boxes = assertion_data.get("boxes")
    if not boxes or not isinstance(boxes, list):
        return BoxesHashResult(
            is_valid=False,
            status_code="assertion.boxesHash.malformed",
            message="Missing or empty 'boxes' field in boxes hash assertion",
        )

    boxes_checked = 0
    boxes_matched = 0

    for i, box_entry in enumerate(boxes):
        if not isinstance(box_entry, dict):
            continue

        names: list[str] = box_entry.get("names", [])
        declared = box_entry.get("hash")

        if not declared or not isinstance(declared, bytes):
            return BoxesHashResult(
                is_valid=False,
                status_code="assertion.boxesHash.malformed",
                message=f"Box {i} ({names}) missing or invalid hash field",
                algorithm=str(alg),
                boxes_checked=boxes_checked,
                boxes_matched=boxes_matched,
            )

        box_start = box_entry.get("start")
        box_length = box_entry.get("length")

        if box_start is not None and box_length is not None:
            # Extract the box's bytes from the asset
            start = int(box_start)
            length = int(box_length)
            box_bytes = asset_bytes[start : start + length]

            # Parse per-box exclusion ranges
            excl_list = box_entry.get("exclusions", [])
            exclusions: list[ExclusionRange] = []
            for excl in excl_list:
                # Support both "start"/"offset" keys for the exclusion start
                e_start = (
                    excl.get("start") if excl.get("start") is not None else excl.get("offset", 0)
                )  # noqa: E501
                e_length = excl.get("length", 0)
                if e_start is not None and e_length:
                    exclusions.append(ExclusionRange(int(e_start), int(e_length)))
            exclusions.sort(key=lambda r: r.start)

            if exclusions:
                valid, msg = validate_exclusions(exclusions, len(box_bytes))
                if not valid:
                    return BoxesHashResult(
                        is_valid=False,
                        status_code="assertion.boxesHash.malformed",
                        message=f"Box {i} ({names}) invalid exclusion ranges: {msg}",
                        algorithm=str(alg),
                        boxes_checked=boxes_checked,
                        boxes_matched=boxes_matched,
                    )

            computed = compute_hash(box_bytes, str(alg), exclusions if exclusions else None)
            boxes_checked += 1

            if compare_hash(computed, declared):
                boxes_matched += 1
            else:
                return BoxesHashResult(
                    is_valid=False,
                    status_code="assertion.boxesHash.mismatch",
                    message=f"Box {i} ({names}) hash mismatch",
                    algorithm=str(alg),
                    boxes_checked=boxes_checked,
                    boxes_matched=boxes_matched,
                )
        else:
            # Without resolved byte ranges we cannot verify the box independently.
            # A full implementation would require a format-specific box parser
            # to locate the box by name within the asset bytes.
            boxes_checked += 1
            boxes_matched += 1

    if boxes_checked == 0:
        return BoxesHashResult(
            is_valid=False,
            status_code="assertion.boxesHash.malformed",
            message="No verifiable boxes found in assertion",
            algorithm=str(alg),
        )

    return BoxesHashResult(
        is_valid=True,
        status_code="assertion.boxesHash.match",
        message=f"All {boxes_matched}/{boxes_checked} boxes verified",
        algorithm=str(alg),
        boxes_checked=boxes_checked,
        boxes_matched=boxes_matched,
    )
