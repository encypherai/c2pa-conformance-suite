"""Comprehensive tests for hash computation infrastructure and DataHash verifier.

Covers:
- Hash algorithm registry (get_hash_algorithm, is_algorithm_supported)
- Exclusion range validation (validate_exclusions)
- Hash computation with and without exclusion ranges (compute_hash, compare_hash)
- c2pa.hash.data assertion verifier (verify_data_hash, parse_exclusions)
"""

from __future__ import annotations

import hashlib

import pytest

from c2pa_conformance.binding.data_hash import (
    DataHashError,
    DataHashResult,
    parse_exclusions,
    verify_data_hash,
)
from c2pa_conformance.crypto.hashing import (
    ExclusionRange,
    HashAlgorithm,
    HashError,
    compare_hash,
    compute_hash,
    get_hash_algorithm,
    is_algorithm_supported,
    validate_exclusions,
)

# ---------------------------------------------------------------------------
# Hash algorithm tests
# ---------------------------------------------------------------------------


def test_get_algorithm_sha256() -> None:
    alg = get_hash_algorithm("sha256")
    assert isinstance(alg, HashAlgorithm)
    assert alg.c2pa_name == "sha256"
    assert alg.hashlib_name == "sha256"
    assert alg.digest_size == 32


def test_get_algorithm_sha384() -> None:
    alg = get_hash_algorithm("sha384")
    assert isinstance(alg, HashAlgorithm)
    assert alg.c2pa_name == "sha384"
    assert alg.hashlib_name == "sha384"
    assert alg.digest_size == 48


def test_get_algorithm_sha512() -> None:
    alg = get_hash_algorithm("sha512")
    assert isinstance(alg, HashAlgorithm)
    assert alg.c2pa_name == "sha512"
    assert alg.hashlib_name == "sha512"
    assert alg.digest_size == 64


def test_get_algorithm_unsupported() -> None:
    with pytest.raises(HashError, match="Unsupported hash algorithm"):
        get_hash_algorithm("md5")


def test_is_algorithm_supported() -> None:
    assert is_algorithm_supported("sha256") is True
    assert is_algorithm_supported("sha384") is True
    assert is_algorithm_supported("sha512") is True
    assert is_algorithm_supported("md5") is False
    assert is_algorithm_supported("sha1") is False
    assert is_algorithm_supported("") is False


# ---------------------------------------------------------------------------
# Exclusion validation tests
# ---------------------------------------------------------------------------


def test_validate_exclusions_valid() -> None:
    exclusions = [
        ExclusionRange(start=10, length=20),
        ExclusionRange(start=50, length=30),
    ]
    valid, msg = validate_exclusions(exclusions, asset_size=200)
    assert valid is True
    assert msg == ""


def test_validate_exclusions_negative_start() -> None:
    exclusions = [ExclusionRange(start=-1, length=10)]
    valid, msg = validate_exclusions(exclusions, asset_size=100)
    assert valid is False
    assert "negative start" in msg


def test_validate_exclusions_overlapping() -> None:
    # Range 0 covers [10, 30), range 1 starts at 25 -- overlap
    exclusions = [
        ExclusionRange(start=10, length=20),
        ExclusionRange(start=25, length=10),
    ]
    valid, msg = validate_exclusions(exclusions, asset_size=200)
    assert valid is False
    assert "overlap" in msg


def test_validate_exclusions_out_of_bounds() -> None:
    exclusions = [ExclusionRange(start=90, length=20)]  # end = 110 > 100
    valid, msg = validate_exclusions(exclusions, asset_size=100)
    assert valid is False
    assert "asset size" in msg


def test_validate_exclusions_unsorted() -> None:
    exclusions = [
        ExclusionRange(start=50, length=10),
        ExclusionRange(start=10, length=10),
    ]
    valid, msg = validate_exclusions(exclusions, asset_size=200)
    assert valid is False
    assert "sorted" in msg


def test_validate_exclusions_empty() -> None:
    valid, msg = validate_exclusions([], asset_size=100)
    assert valid is True
    assert msg == ""


def test_validate_exclusions_zero_length() -> None:
    exclusions = [ExclusionRange(start=10, length=0)]
    valid, msg = validate_exclusions(exclusions, asset_size=100)
    assert valid is False
    assert "non-positive length" in msg


# ---------------------------------------------------------------------------
# Hash computation tests
# ---------------------------------------------------------------------------


def test_compute_hash_no_exclusions() -> None:
    data = b"Hello, C2PA world!"
    result = compute_hash(data, "sha256")
    expected = hashlib.sha256(data).digest()
    assert result == expected
    assert len(result) == 32


def test_compute_hash_with_exclusion() -> None:
    # data = [AAA | BBBBB | CCC]
    # exclude the middle BBBBB block -> hash(AAA + CCC)
    prefix = b"AAA"
    excluded = b"BBBBB"
    suffix = b"CCC"
    data = prefix + excluded + suffix

    exclusions = [ExclusionRange(start=len(prefix), length=len(excluded))]
    result = compute_hash(data, "sha256", exclusions)

    expected = hashlib.sha256(prefix + suffix).digest()
    assert result == expected


def test_compute_hash_with_multiple_exclusions() -> None:
    # Segments: A | X | B | Y | C  where X and Y are excluded
    a = b"AAAA"
    x = b"XXXX"
    b_ = b"BBB"
    y = b"YY"
    c = b"CCCCC"
    data = a + x + b_ + y + c

    exclusions = [
        ExclusionRange(start=len(a), length=len(x)),
        ExclusionRange(start=len(a) + len(x) + len(b_), length=len(y)),
    ]
    result = compute_hash(data, "sha256", exclusions)

    expected = hashlib.sha256(a + b_ + c).digest()
    assert result == expected


def test_compute_hash_exclusion_at_start() -> None:
    excluded = b"EXCLUDED"
    rest = b"the rest of the data"
    data = excluded + rest

    exclusions = [ExclusionRange(start=0, length=len(excluded))]
    result = compute_hash(data, "sha256", exclusions)

    expected = hashlib.sha256(rest).digest()
    assert result == expected


def test_compute_hash_exclusion_at_end() -> None:
    body = b"the body of the asset"
    excluded = b"TAIL"
    data = body + excluded

    exclusions = [ExclusionRange(start=len(body), length=len(excluded))]
    result = compute_hash(data, "sha256", exclusions)

    expected = hashlib.sha256(body).digest()
    assert result == expected


def test_compute_hash_sha384() -> None:
    data = b"test data for sha384"
    result = compute_hash(data, "sha384")
    assert len(result) == 48
    expected = hashlib.sha384(data).digest()
    assert result == expected


def test_compute_hash_sha512() -> None:
    data = b"test data for sha512"
    result = compute_hash(data, "sha512")
    assert len(result) == 64
    expected = hashlib.sha512(data).digest()
    assert result == expected


def test_compare_hash_match() -> None:
    digest = hashlib.sha256(b"same").digest()
    assert compare_hash(digest, digest) is True


def test_compare_hash_mismatch() -> None:
    a = hashlib.sha256(b"aaa").digest()
    b = hashlib.sha256(b"bbb").digest()
    assert compare_hash(a, b) is False


# ---------------------------------------------------------------------------
# Data hash verifier tests
# ---------------------------------------------------------------------------


def _make_assertion(
    asset: bytes,
    alg: str = "sha256",
    exclusions: list[ExclusionRange] | None = None,
) -> dict:
    """Build a valid assertion_data dict whose hash is correct for asset."""
    computed = compute_hash(asset, alg, exclusions)
    excl_list = [{"start": e.start, "length": e.length} for e in exclusions] if exclusions else []
    return {
        "alg": alg,
        "hash": computed,
        "exclusions": excl_list,
    }


def test_verify_data_hash_match() -> None:
    asset = b"A C2PA-signed JPEG asset bytes here."
    assertion = _make_assertion(asset)
    result = verify_data_hash(asset, assertion)

    assert isinstance(result, DataHashResult)
    assert result.is_valid is True
    assert result.status_code == "assertion.dataHash.match"
    assert result.algorithm == "sha256"
    assert result.exclusion_count == 0
    assert result.computed_hash == result.declared_hash


def test_verify_data_hash_mismatch() -> None:
    asset = b"Original asset bytes."
    assertion = _make_assertion(asset)

    tampered = bytearray(asset)
    tampered[5] ^= 0xFF  # flip bits in one byte
    result = verify_data_hash(bytes(tampered), assertion)

    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.mismatch"
    assert result.computed_hash != result.declared_hash


def test_verify_data_hash_with_exclusions() -> None:
    prefix = b"JPEG header bytes"
    manifest_store = b"<JUMBF manifest store goes here>"
    suffix = b"JPEG image data after the manifest"
    asset = prefix + manifest_store + suffix

    exclusions = [ExclusionRange(start=len(prefix), length=len(manifest_store))]
    assertion = _make_assertion(asset, exclusions=exclusions)

    result = verify_data_hash(asset, assertion)
    assert result.is_valid is True
    assert result.status_code == "assertion.dataHash.match"
    assert result.exclusion_count == 1


def test_verify_data_hash_missing_algorithm() -> None:
    assertion: dict = {"hash": b"\x00" * 32, "exclusions": []}
    result = verify_data_hash(b"data", assertion)
    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.malformed"
    assert "alg" in result.message


def test_verify_data_hash_unsupported_algorithm() -> None:
    assertion = {"alg": "md5", "hash": b"\x00" * 16, "exclusions": []}
    result = verify_data_hash(b"data", assertion)
    assert result.is_valid is False
    assert result.status_code == "algorithm.unsupported"


def test_verify_data_hash_missing_hash() -> None:
    assertion: dict = {"alg": "sha256", "exclusions": []}
    result = verify_data_hash(b"data", assertion)
    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.malformed"
    assert "hash" in result.message


def test_verify_data_hash_invalid_exclusions() -> None:
    asset = b"some asset data of reasonable length"
    # Build a correct hash first, then swap in overlapping exclusions
    assertion = _make_assertion(asset)
    assertion["exclusions"] = [
        {"start": 5, "length": 10},
        {"start": 10, "length": 10},  # overlaps with first
    ]
    result = verify_data_hash(asset, assertion)
    assert result.is_valid is False
    assert result.status_code == "assertion.dataHash.malformed"
    assert "Invalid exclusion ranges" in result.message


def test_verify_data_hash_empty_content() -> None:
    asset = b""
    computed = hashlib.sha256(b"").digest()
    assertion = {"alg": "sha256", "hash": computed, "exclusions": []}
    result = verify_data_hash(asset, assertion)
    assert result.is_valid is True
    assert result.status_code == "assertion.dataHash.match"


# ---------------------------------------------------------------------------
# parse_exclusions edge cases
# ---------------------------------------------------------------------------


def test_parse_exclusions_sorts_by_start() -> None:
    raw = [
        {"start": 50, "length": 10},
        {"start": 10, "length": 5},
    ]
    parsed = parse_exclusions(raw)
    assert parsed[0].start == 10
    assert parsed[1].start == 50


def test_parse_exclusions_missing_key_raises() -> None:
    raw = [{"start": 10}]  # missing 'length'
    with pytest.raises(DataHashError, match="missing start or length"):
        parse_exclusions(raw)


def test_parse_exclusions_empty_list() -> None:
    assert parse_exclusions([]) == []
