"""c2pa.hash.data content binding verifier.

Implements byte-range hash verification for the most common C2PA binding type.
The verifier computes the hash of all asset bytes excluding the declared
exclusion ranges and compares against the hash stored in the assertion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from c2pa_conformance.crypto.hashing import (
    ExclusionRange,
    HashError,
    compare_hash,
    compute_hash,
    is_algorithm_supported,
    validate_exclusions,
)


@dataclass
class DataHashResult:
    """Result of data hash verification."""

    is_valid: bool
    status_code: str  # assertion.dataHash.match or assertion.dataHash.mismatch
    message: str
    algorithm: str = ""
    computed_hash: bytes = field(default_factory=bytes)
    declared_hash: bytes = field(default_factory=bytes)
    exclusion_count: int = 0


class DataHashError(Exception):
    """Raised when data hash verification encounters an error."""


def parse_exclusions(exclusion_list: list[dict[str, Any]]) -> list[ExclusionRange]:
    """Parse exclusion ranges from assertion data.

    Each exclusion dict has 'start' and 'length' keys.
    """
    ranges = []
    for excl in exclusion_list:
        start = excl.get("start")
        length = excl.get("length")
        if start is None or length is None:
            raise DataHashError(f"Exclusion missing start or length: {excl}")
        ranges.append(ExclusionRange(start=int(start), length=int(length)))
    return sorted(ranges, key=lambda r: r.start)


def verify_data_hash(
    asset_bytes: bytes,
    assertion_data: dict[str, Any],
) -> DataHashResult:
    """Verify a c2pa.hash.data assertion against asset bytes.

    The assertion_data dict comes from the parsed CBOR assertion and has fields:
    - "alg": hash algorithm name (e.g., "sha256")
    - "hash": declared hash bytes
    - "exclusions": list of {start, length} dicts
    - "name": optional name field

    Args:
        asset_bytes: The complete raw asset file bytes.
        assertion_data: The parsed assertion data dict.

    Returns:
        DataHashResult with match/mismatch status.
    """
    # Extract algorithm
    alg = assertion_data.get("alg")
    if not alg:
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message="Missing 'alg' field in data hash assertion",
        )

    if not is_algorithm_supported(str(alg)):
        return DataHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported hash algorithm: {alg}",
        )

    # Extract declared hash
    declared = assertion_data.get("hash")
    if not declared or not isinstance(declared, bytes):
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message="Missing or invalid 'hash' field",
        )

    # Parse exclusions
    exclusion_list = assertion_data.get("exclusions", [])
    try:
        exclusions = parse_exclusions(exclusion_list) if exclusion_list else []
    except DataHashError as exc:
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message=str(exc),
        )

    # Validate exclusion ranges
    is_valid_excl, excl_msg = validate_exclusions(exclusions, len(asset_bytes))
    if not is_valid_excl:
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message=f"Invalid exclusion ranges: {excl_msg}",
        )

    # Compute hash
    try:
        computed = compute_hash(asset_bytes, str(alg), exclusions)
    except HashError as exc:
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.malformed",
            message=f"Hash computation failed: {exc}",
        )

    # Compare
    if compare_hash(computed, declared):
        return DataHashResult(
            is_valid=True,
            status_code="assertion.dataHash.match",
            message="Data hash matches",
            algorithm=str(alg),
            computed_hash=computed,
            declared_hash=declared,
            exclusion_count=len(exclusions),
        )
    else:
        return DataHashResult(
            is_valid=False,
            status_code="assertion.dataHash.mismatch",
            message="Data hash does not match",
            algorithm=str(alg),
            computed_hash=computed,
            declared_hash=declared,
            exclusion_count=len(exclusions),
        )
