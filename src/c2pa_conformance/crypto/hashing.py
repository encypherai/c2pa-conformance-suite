"""Hash algorithm registry and byte-range hash computation with exclusion ranges.

Implements C2PA v2.4 content binding hash computation: all asset bytes are
hashed except those covered by declared exclusion ranges (which contain the
embedded JUMBF manifest store).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


class HashError(Exception):
    """Raised when hash computation fails."""


@dataclass
class HashAlgorithm:
    """A supported hash algorithm."""

    c2pa_name: str  # e.g., "sha256"
    hashlib_name: str  # e.g., "sha256"
    digest_size: int  # bytes (32 for SHA-256, 48 for SHA-384, 64 for SHA-512)


# C2PA v2.4 allowed hash algorithms
HASH_ALGORITHMS: dict[str, HashAlgorithm] = {
    "sha256": HashAlgorithm("sha256", "sha256", 32),
    "sha384": HashAlgorithm("sha384", "sha384", 48),
    "sha512": HashAlgorithm("sha512", "sha512", 64),
}


@dataclass
class ExclusionRange:
    """A byte range to exclude from hashing."""

    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length


def get_hash_algorithm(name: str) -> HashAlgorithm:
    """Look up a hash algorithm by C2PA name.

    Returns HashAlgorithm or raises HashError if unsupported.
    """
    alg = HASH_ALGORITHMS.get(name)
    if alg is None:
        raise HashError(f"Unsupported hash algorithm: {name}")
    return alg


def is_algorithm_supported(name: str) -> bool:
    """Check if a hash algorithm is in the C2PA allowed list."""
    return name in HASH_ALGORITHMS


def validate_exclusions(
    exclusions: list[ExclusionRange],
    asset_size: int,
) -> tuple[bool, str]:
    """Validate exclusion ranges are well-formed.

    Checks:
    1. All start values are non-negative
    2. All length values are positive
    3. Ranges are sorted by start offset
    4. Ranges don't overlap
    5. Ranges don't extend beyond asset_size

    Returns (is_valid, error_message).
    """
    if not exclusions:
        return True, ""

    for i, excl in enumerate(exclusions):
        if excl.start < 0:
            return False, f"Exclusion {i} has negative start offset: {excl.start}"
        if excl.length <= 0:
            return False, f"Exclusion {i} has non-positive length: {excl.length}"
        if excl.end > asset_size:
            return (
                False,
                f"Exclusion {i} extends beyond asset size ({excl.end} > {asset_size})",
            )

    for i in range(1, len(exclusions)):
        prev = exclusions[i - 1]
        curr = exclusions[i]
        if curr.start < prev.start:
            return (
                False,
                f"Exclusion {i} is not sorted: start {curr.start} < previous start {prev.start}",
            )
        if curr.start < prev.end:
            return (
                False,
                f"Exclusion {i} overlaps with exclusion {i - 1}: "
                f"start {curr.start} < previous end {prev.end}",
            )

    return True, ""


def compute_hash(
    data: bytes,
    algorithm: str,
    exclusions: list[ExclusionRange] | None = None,
) -> bytes:
    """Compute hash of data with optional exclusion ranges.

    Hashes all bytes in `data` EXCEPT those covered by exclusion ranges.
    Exclusion ranges must be sorted by start offset and non-overlapping.

    Args:
        data: The complete asset bytes.
        algorithm: C2PA algorithm name (e.g., "sha256").
        exclusions: Byte ranges to skip during hashing.

    Returns:
        The computed hash digest.
    """
    alg = get_hash_algorithm(algorithm)
    h = hashlib.new(alg.hashlib_name)

    if not exclusions:
        h.update(data)
        return h.digest()

    # Hash bytes between exclusion ranges
    pos = 0
    for excl in exclusions:
        if excl.start > pos:
            h.update(data[pos : excl.start])
        pos = excl.end

    # Hash remaining bytes after last exclusion
    if pos < len(data):
        h.update(data[pos:])

    return h.digest()


def compare_hash(computed: bytes, declared: bytes) -> bool:
    """Constant-time hash comparison."""
    return hmac.compare_digest(computed, declared)
