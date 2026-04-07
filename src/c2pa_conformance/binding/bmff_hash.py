"""c2pa.hash.bmff content binding verifier.

Handles BMFF box-level hashing with xpath-based exclusion ranges,
and Merkle tree verification for streaming BMFF content.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from c2pa_conformance.crypto.hashing import (
    ExclusionRange,
    compare_hash,
    compute_hash,
    get_hash_algorithm,
    is_algorithm_supported,
    validate_exclusions,
)


@dataclass
class BmffHashResult:
    """Result of BMFF hash verification."""

    is_valid: bool
    status_code: str  # assertion.bmffHash.match / .mismatch / .malformed / algorithm.unsupported
    message: str
    algorithm: str = ""


class BmffHashError(Exception):
    """Raised when BMFF hash verification encounters an error."""


def verify_bmff_hash(asset_bytes: bytes, assertion_data: dict[str, Any]) -> BmffHashResult:
    """Verify a c2pa.hash.bmff assertion against asset bytes.

    If the assertion has a 'blocks' field, uses Merkle tree verification.
    Otherwise uses standard hash with exclusion ranges.

    Args:
        asset_bytes: The complete raw asset file bytes.
        assertion_data: The parsed assertion data dict with fields:
            - "alg": hash algorithm name (e.g., "sha256")
            - "hash": declared hash bytes (root hash for Merkle, direct hash otherwise)
            - "exclusions": optional list of exclusion dicts (standard path)
            - "block_size": int, required for Merkle path
            - "blocks": list of leaf hash bytes, triggers Merkle path

    Returns:
        BmffHashResult with match/mismatch/malformed status.
    """
    alg = assertion_data.get("alg")
    if not alg or not is_algorithm_supported(str(alg)):
        return BmffHashResult(
            is_valid=False,
            status_code="algorithm.unsupported",
            message=f"Unsupported or missing algorithm: {alg}",
        )

    declared = assertion_data.get("hash")
    if not declared or not isinstance(declared, bytes):
        return BmffHashResult(
            is_valid=False,
            status_code="assertion.bmffHash.malformed",
            message="Missing or invalid 'hash' field in BMFF hash assertion",
        )

    # Merkle tree variant triggered by presence of 'blocks' key
    blocks = assertion_data.get("blocks")
    if blocks is not None:
        return _verify_merkle(asset_bytes, str(alg), declared, assertion_data)

    return _verify_standard(asset_bytes, str(alg), declared, assertion_data)


def _verify_standard(
    asset_bytes: bytes,
    alg: str,
    declared: bytes,
    assertion_data: dict[str, Any],
) -> BmffHashResult:
    """Standard BMFF hash: compute hash with byte-level exclusion ranges.

    BMFF exclusions use xpath paths, but at verification time they should
    have been resolved to byte offsets. If we have raw exclusions with
    'start'/'length', use them directly. xpath-only exclusions require a
    format-specific box parser (not implemented here) and are skipped.
    """
    exclusion_list = assertion_data.get("exclusions", [])
    exclusions: list[ExclusionRange] = []

    for excl in exclusion_list:
        start = excl.get("start")
        length = excl.get("length")
        if start is not None and length is not None:
            exclusions.append(ExclusionRange(start=int(start), length=int(length)))
        # xpath-only exclusions without resolved byte ranges are not verifiable here

    exclusions.sort(key=lambda r: r.start)

    if exclusions:
        valid, msg = validate_exclusions(exclusions, len(asset_bytes))
        if not valid:
            return BmffHashResult(
                is_valid=False,
                status_code="assertion.bmffHash.malformed",
                message=f"Invalid exclusion ranges: {msg}",
            )

    computed = compute_hash(asset_bytes, alg, exclusions if exclusions else None)

    if compare_hash(computed, declared):
        return BmffHashResult(
            is_valid=True,
            status_code="assertion.bmffHash.match",
            message="BMFF hash matches",
            algorithm=alg,
        )
    return BmffHashResult(
        is_valid=False,
        status_code="assertion.bmffHash.mismatch",
        message="BMFF hash mismatch",
        algorithm=alg,
    )


def _verify_merkle(
    asset_bytes: bytes,
    alg: str,
    declared_root: bytes,
    assertion_data: dict[str, Any],
) -> BmffHashResult:
    """Merkle tree verification for streaming BMFF.

    Steps:
    1. Validate block_size and blocks fields.
    2. Compute leaf hashes from asset_bytes in block_size chunks.
    3. Verify each computed leaf matches the corresponding declared leaf.
    4. Build the Merkle tree from declared leaves and verify root.
    """
    block_size = assertion_data.get("block_size")
    if not isinstance(block_size, int) or block_size <= 0:
        return BmffHashResult(
            is_valid=False,
            status_code="assertion.bmffHash.malformed",
            message=f"Invalid or missing block_size: {block_size}",
        )

    blocks = assertion_data.get("blocks", [])
    declared_leaves = [b for b in blocks if isinstance(b, bytes)]

    if not declared_leaves:
        return BmffHashResult(
            is_valid=False,
            status_code="assertion.bmffHash.malformed",
            message="Empty or invalid blocks array in BMFF Merkle assertion",
        )

    hash_alg = get_hash_algorithm(alg)

    # Compute leaf hashes by splitting asset_bytes into block_size chunks
    computed_leaves: list[bytes] = []
    offset = 0
    while offset < len(asset_bytes):
        end = min(offset + block_size, len(asset_bytes))
        chunk = asset_bytes[offset:end]
        h = hashlib.new(hash_alg.hashlib_name, chunk)
        computed_leaves.append(h.digest())
        offset = end

    if len(computed_leaves) != len(declared_leaves):
        return BmffHashResult(
            is_valid=False,
            status_code="assertion.bmffHash.mismatch",
            message=(
                f"Leaf count mismatch: {len(computed_leaves)} computed "
                f"vs {len(declared_leaves)} declared"
            ),
            algorithm=alg,
        )

    for i, (computed_leaf, declared_leaf) in enumerate(zip(computed_leaves, declared_leaves)):
        if not compare_hash(computed_leaf, declared_leaf):
            return BmffHashResult(
                is_valid=False,
                status_code="assertion.bmffHash.mismatch",
                message=f"Leaf {i} hash mismatch",
                algorithm=alg,
            )

    computed_root = _compute_merkle_root(declared_leaves, hash_alg.hashlib_name)
    if compare_hash(computed_root, declared_root):
        return BmffHashResult(
            is_valid=True,
            status_code="assertion.bmffHash.match",
            message="Merkle tree verified",
            algorithm=alg,
        )
    return BmffHashResult(
        is_valid=False,
        status_code="assertion.bmffHash.mismatch",
        message="Merkle root mismatch",
        algorithm=alg,
    )


def _compute_merkle_root(leaves: list[bytes], hash_name: str) -> bytes:
    """Compute Merkle root from leaf hashes using binary tree construction.

    When the number of nodes at a level is odd, the last node is paired
    with itself (duplicated) to form the parent.
    """
    if not leaves:
        return hashlib.new(hash_name, b"").digest()
    if len(leaves) == 1:
        return leaves[0]

    current_level = list(leaves)
    while len(current_level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            h = hashlib.new(hash_name)
            h.update(left)
            h.update(right)
            next_level.append(h.digest())
        current_level = next_level
    return current_level[0]
