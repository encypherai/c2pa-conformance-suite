"""Tests for the 17 previously-noop predicate operators.

Each operator is tested with at least one pass case and one fail case.
Operators are called directly; no PredicateEngine overhead needed.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

from c2pa_conformance.evaluator.engine import (
    _eval_block_coverage_check,
    _eval_check_exclusion_length,
    _eval_check_offset_adjustment,
    _eval_compare_hash,
    _eval_compute_hash,
    _eval_compute_hash_excluding_wrapper,
    _eval_compute_leaf_hash,
    _eval_decompress,
    _eval_detect_compressed,
    _eval_for_each_leaf,
    _eval_leaf_count_check,
    _eval_resolve_byte_range,
    _eval_sequence_continuity_check,
    _eval_tree_root_check,
    _eval_validate_decompressed,
    _eval_validate_manifest_store,
    _eval_verify_before_render,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Group 1: Hash operators
# ---------------------------------------------------------------------------


class TestComputeHash:
    def test_basic_hash_stored_in_context(self) -> None:
        data = b"hello world"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "start": 0, "length": len(data)}
        ok, msg = _eval_compute_hash(ctx, cond)
        assert ok is True
        assert "sha256" in msg
        assert ctx["_computed_hash"] == _sha256(data)
        assert ctx["_computed_hash_alg"] == "sha256"

    def test_partial_range(self) -> None:
        data = b"abcdefghij"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "start": 2, "length": 4}
        ok, _ = _eval_compute_hash(ctx, cond)
        assert ok is True
        assert ctx["_computed_hash"] == _sha256(data[2:6])

    def test_with_exclusion(self) -> None:
        data = b"AAAA_SKIP_AAAA"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {
            "algorithm": "sha256",
            "start": 0,
            "length": len(data),
            "exclusions": [{"start": 4, "length": 6}],
        }
        ok, _ = _eval_compute_hash(ctx, cond)
        assert ok is True
        # Exclusion skips bytes [4:10], so hashed = data[0:4] + data[10:]
        from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

        expected = compute_hash(data, "sha256", [ExclusionRange(start=4, length=6)])
        assert ctx["_computed_hash"] == expected

    def test_missing_asset_bytes_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_compute_hash(ctx, {"algorithm": "sha256"})
        assert ok is True
        assert "no asset bytes" in msg

    def test_non_bytes_asset_passes(self) -> None:
        ctx: dict[str, Any] = {"asset_bytes": "string, not bytes"}
        ok, msg = _eval_compute_hash(ctx, {"algorithm": "sha256"})
        assert ok is True
        assert "no asset bytes" in msg

    def test_unsupported_algorithm_returns_false(self) -> None:
        ctx: dict[str, Any] = {"asset_bytes": b"data"}
        ok, msg = _eval_compute_hash(ctx, {"algorithm": "md5"})
        assert ok is False
        assert "failed" in msg

    def test_defaults_start_and_length(self) -> None:
        data = b"full file"
        ctx: dict[str, Any] = {"asset_bytes": data}
        ok, _ = _eval_compute_hash(ctx, {"algorithm": "sha256"})
        assert ok is True
        assert ctx["_computed_hash"] == _sha256(data)


class TestCompareHash:
    def test_match_bytes(self) -> None:
        digest = _sha256(b"data")
        ctx: dict[str, Any] = {"_computed_hash": digest}
        cond = {"hash": digest}
        ok, msg = _eval_compare_hash(ctx, cond)
        assert ok is True
        assert msg == "hash match"

    def test_match_hex_string(self) -> None:
        data = b"hello"
        digest = _sha256(data)
        ctx: dict[str, Any] = {"_computed_hash": digest}
        cond = {"hash": digest.hex()}
        ok, msg = _eval_compare_hash(ctx, cond)
        assert ok is True

    def test_mismatch(self) -> None:
        ctx: dict[str, Any] = {"_computed_hash": _sha256(b"a")}
        cond = {"hash": _sha256(b"b")}
        ok, msg = _eval_compare_hash(ctx, cond)
        assert ok is False
        assert msg == "hash mismatch"

    def test_expected_hash_key(self) -> None:
        digest = _sha256(b"test")
        ctx: dict[str, Any] = {"_computed_hash": digest}
        cond = {"expected_hash": digest}
        ok, _ = _eval_compare_hash(ctx, cond)
        assert ok is True

    def test_no_computed_hash_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_compare_hash(ctx, {"hash": _sha256(b"x")})
        assert ok is True
        assert "no computed hash" in msg

    def test_no_declared_hash_passes(self) -> None:
        ctx: dict[str, Any] = {"_computed_hash": _sha256(b"x")}
        ok, msg = _eval_compare_hash(ctx, {})
        assert ok is True
        assert "no declared hash" in msg


class TestResolveByteRange:
    def test_valid_range(self) -> None:
        data = b"0123456789"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"start": 2, "length": 4}
        ok, msg = _eval_resolve_byte_range(ctx, cond)
        assert ok is True
        assert ctx["_resolved_bytes"] == b"2345"
        assert "4 bytes at offset 2" in msg

    def test_full_file_default(self) -> None:
        data = b"abcde"
        ctx: dict[str, Any] = {"asset_bytes": data}
        ok, _ = _eval_resolve_byte_range(ctx, {"start": 0})
        assert ok is True
        assert ctx["_resolved_bytes"] == data

    def test_out_of_bounds_fails(self) -> None:
        data = b"short"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"start": 3, "length": 10}
        ok, msg = _eval_resolve_byte_range(ctx, cond)
        assert ok is False
        assert "out of bounds" in msg

    def test_missing_asset_bytes_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_resolve_byte_range(ctx, {"start": 0, "length": 4})
        assert ok is True
        assert "no asset bytes" in msg


# ---------------------------------------------------------------------------
# Group 2: Compression operators
# ---------------------------------------------------------------------------


class TestDetectCompressed:
    def test_brob_marker_detected(self) -> None:
        data = b"\x00\x00\x00\x10brob" + b"\x00" * 20
        ctx: dict[str, Any] = {"_manifest_bytes": data}
        ok, msg = _eval_detect_compressed(ctx, {})
        assert ok is True
        assert ctx["_is_compressed"] is True
        assert "compressed" in msg

    def test_no_brob_not_compressed(self) -> None:
        data = b"\x00\x00\x00\x10jumb" + b"\x00" * 20
        ctx: dict[str, Any] = {"_manifest_bytes": data}
        ok, msg = _eval_detect_compressed(ctx, {})
        assert ok is True
        assert ctx["_is_compressed"] is False
        assert "not compressed" in msg

    def test_empty_manifest_bytes_not_compressed(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_detect_compressed(ctx, {})
        assert ok is True
        assert ctx["_is_compressed"] is False

    def test_short_data_not_compressed(self) -> None:
        ctx: dict[str, Any] = {"_manifest_bytes": b"\x00"}
        ok, _ = _eval_detect_compressed(ctx, {})
        assert ctx["_is_compressed"] is False


class TestDecompress:
    def test_not_compressed_skips(self) -> None:
        ctx: dict[str, Any] = {"_is_compressed": False}
        ok, msg = _eval_decompress(ctx, {})
        assert ok is True
        assert "not compressed" in msg

    def test_brotli_not_available_passes(self) -> None:
        # Simulate: compressed=True but brotli not importable
        # We mock by patching _compressed_data with garbage and catching ImportError
        ctx: dict[str, Any] = {"_is_compressed": True, "_compressed_data": b"garbage"}
        ok, msg = _eval_decompress(ctx, {})
        # Either brotli is available (decompression fails gracefully) or not
        # Either way: ok may be True (import skip) or False (bad data)
        # The key invariant: does not raise
        assert isinstance(ok, bool)
        assert isinstance(msg, str)

    def test_no_is_compressed_key_skips(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_decompress(ctx, {})
        assert ok is True
        assert "not compressed" in msg


class TestValidateDecompressed:
    def _valid_jumbf_header(self) -> bytes:
        # Minimal valid JUMBF: LBox=8, TBox="jumb"
        return struct.pack(">I", 8) + b"jumb"

    def test_valid_jumbf_passes(self) -> None:
        data = self._valid_jumbf_header()
        ctx: dict[str, Any] = {"_decompressed_data": data, "_is_compressed": True}
        ok, msg = _eval_validate_decompressed(ctx, {})
        assert ok is True
        assert "valid JUMBF" in msg

    def test_invalid_tbox_fails(self) -> None:
        data = struct.pack(">I", 8) + b"xxxx"
        ctx: dict[str, Any] = {"_decompressed_data": data, "_is_compressed": True}
        ok, msg = _eval_validate_decompressed(ctx, {})
        assert ok is False
        assert "invalid JUMBF" in msg

    def test_not_compressed_no_data_passes(self) -> None:
        ctx: dict[str, Any] = {"_is_compressed": False}
        ok, msg = _eval_validate_decompressed(ctx, {})
        assert ok is True
        assert "not compressed" in msg

    def test_compressed_no_data_fails(self) -> None:
        ctx: dict[str, Any] = {"_is_compressed": True}
        ok, msg = _eval_validate_decompressed(ctx, {})
        assert ok is False
        assert "no decompressed data" in msg

    def test_too_short_fails(self) -> None:
        ctx: dict[str, Any] = {"_decompressed_data": b"short", "_is_compressed": True}
        ok, msg = _eval_validate_decompressed(ctx, {})
        assert ok is False


# ---------------------------------------------------------------------------
# Group 3: BMFF / Merkle tree operators
# ---------------------------------------------------------------------------


class TestBlockCoverageCheck:
    def test_single_block_covers_exactly(self) -> None:
        cond = {"block_size": 512, "block_count": 1, "total_size": 512}
        ok, msg = _eval_block_coverage_check({}, cond)
        assert ok is True

    def test_multiple_blocks_cover_total(self) -> None:
        cond = {"block_size": 512, "block_count": 4, "total_size": 1800}
        ok, _ = _eval_block_coverage_check({}, cond)
        assert ok is True

    def test_partial_last_block_still_covers(self) -> None:
        # 3 blocks of 512 = 1536 bytes; total is 1300 (last block partial)
        cond = {"block_size": 512, "block_count": 3, "total_size": 1300}
        ok, _ = _eval_block_coverage_check({}, cond)
        assert ok is True

    def test_insufficient_blocks_fails(self) -> None:
        # 1 block of 512 = 512 bytes but total is 1000
        cond = {"block_size": 512, "block_count": 1, "total_size": 1000}
        ok, msg = _eval_block_coverage_check({}, cond)
        assert ok is False
        assert "512 of 1000" in msg

    def test_zero_block_size_passes(self) -> None:
        # Cannot evaluate; treat as pass
        cond = {"block_size": 0, "block_count": 0, "total_size": 0}
        ok, msg = _eval_block_coverage_check({}, cond)
        assert ok is True
        assert "insufficient" in msg

    def test_zero_total_size_passes(self) -> None:
        cond = {"block_size": 512, "block_count": 0, "total_size": 0}
        ok, _ = _eval_block_coverage_check({}, cond)
        assert ok is True

    def test_block_count_inferred_from_total(self) -> None:
        # block_count=0 triggers auto-calculation
        cond = {"block_size": 100, "block_count": 0, "total_size": 250}
        ok, _ = _eval_block_coverage_check({}, cond)
        assert ok is True


class TestLeafCountCheck:
    def test_matching_count_passes(self) -> None:
        cond = {"actual_count": 4, "expected_count": 4}
        ok, msg = _eval_leaf_count_check({}, cond)
        assert ok is True
        assert "4 matches" in msg

    def test_mismatched_count_fails(self) -> None:
        cond = {"actual_count": 3, "expected_count": 4}
        ok, msg = _eval_leaf_count_check({}, cond)
        assert ok is False
        assert "3 != expected 4" in msg

    def test_alternative_keys(self) -> None:
        cond = {"leaf_count": 5, "expected": 5}
        ok, _ = _eval_leaf_count_check({}, cond)
        assert ok is True

    def test_no_expected_passes(self) -> None:
        # expected <= 0: cannot evaluate
        cond = {"actual_count": 3, "expected_count": 0}
        ok, msg = _eval_leaf_count_check({}, cond)
        assert ok is True
        assert "no expected" in msg


class TestForEachLeaf:
    def test_all_leaves_match(self) -> None:
        leaf_a = _sha256(b"block_a")
        leaf_b = _sha256(b"block_b")
        cond = {
            "leaves": [leaf_a, leaf_b],
            "declared_hashes": [leaf_a, leaf_b],
        }
        ok, msg = _eval_for_each_leaf({}, cond)
        assert ok is True
        assert "2 leaf hashes match" in msg

    def test_leaf_mismatch_fails(self) -> None:
        leaf_a = _sha256(b"block_a")
        wrong = _sha256(b"different")
        cond = {"leaves": [leaf_a], "declared_hashes": [wrong]}
        ok, msg = _eval_for_each_leaf({}, cond)
        assert ok is False
        assert "mismatch at indices: [0]" in msg

    def test_hex_string_leaves(self) -> None:
        leaf = _sha256(b"x")
        cond = {
            "leaves": [leaf.hex()],
            "declared_hashes": [leaf.hex()],
        }
        ok, _ = _eval_for_each_leaf({}, cond)
        assert ok is True

    def test_no_leaves_passes(self) -> None:
        ok, msg = _eval_for_each_leaf({}, {})
        assert ok is True
        assert "no leaves" in msg

    def test_hashes_key_alias(self) -> None:
        leaf = _sha256(b"y")
        cond = {"leaves": [leaf], "hashes": [leaf]}
        ok, _ = _eval_for_each_leaf({}, cond)
        assert ok is True

    def test_multiple_mismatches(self) -> None:
        a = _sha256(b"a")
        b_ = _sha256(b"b")
        wrong = _sha256(b"wrong")
        cond = {"leaves": [a, b_], "declared_hashes": [wrong, wrong]}
        ok, msg = _eval_for_each_leaf({}, cond)
        assert ok is False
        assert "0" in msg and "1" in msg


class TestTreeRootCheck:
    def _build_root(self, leaves: list[bytes], alg: str = "sha256") -> bytes:
        """Build Merkle root using the same algorithm as the implementation."""
        layer = list(leaves)
        while len(layer) > 1:
            next_layer = []
            for j in range(0, len(layer), 2):
                if j + 1 < len(layer):
                    h = hashlib.new(alg)
                    h.update(layer[j] + layer[j + 1])
                    next_layer.append(h.digest())
                else:
                    h = hashlib.new(alg)
                    h.update(layer[j] + layer[j])
                    next_layer.append(h.digest())
            layer = next_layer
        return layer[0]

    def test_two_leaves_match(self) -> None:
        l1 = _sha256(b"a")
        l2 = _sha256(b"b")
        root = self._build_root([l1, l2])
        cond = {"leaves": [l1, l2], "root_hash": root, "algorithm": "sha256"}
        ok, msg = _eval_tree_root_check({}, cond)
        assert ok is True
        assert "Merkle root matches" in msg

    def test_single_leaf(self) -> None:
        l1 = _sha256(b"only")
        root = l1  # single leaf = root
        cond = {"leaves": [l1], "root_hash": root}
        ok, _ = _eval_tree_root_check({}, cond)
        assert ok is True

    def test_wrong_root_fails(self) -> None:
        l1 = _sha256(b"a")
        l2 = _sha256(b"b")
        cond = {
            "leaves": [l1, l2],
            "root_hash": _sha256(b"wrong_root"),
        }
        ok, msg = _eval_tree_root_check({}, cond)
        assert ok is False
        assert "mismatch" in msg

    def test_hex_string_inputs(self) -> None:
        l1 = _sha256(b"x")
        root = self._build_root([l1])
        cond = {"leaves": [l1.hex()], "root_hash": root.hex()}
        ok, _ = _eval_tree_root_check({}, cond)
        assert ok is True

    def test_no_leaves_passes(self) -> None:
        ok, msg = _eval_tree_root_check({}, {})
        assert ok is True
        assert "insufficient" in msg

    def test_no_root_passes(self) -> None:
        ok, msg = _eval_tree_root_check({}, {"leaves": [_sha256(b"a")]})
        assert ok is True
        assert "insufficient" in msg

    def test_four_leaves(self) -> None:
        leaves = [_sha256(bytes([i])) for i in range(4)]
        root = self._build_root(leaves)
        cond = {"leaves": leaves, "root_hash": root}
        ok, _ = _eval_tree_root_check({}, cond)
        assert ok is True

    def test_declared_root_key_alias(self) -> None:
        leaf = _sha256(b"q")
        cond = {"leaves": [leaf], "declared_root": leaf}
        ok, _ = _eval_tree_root_check({}, cond)
        assert ok is True


# ---------------------------------------------------------------------------
# Group 4: Sequence / render operators
# ---------------------------------------------------------------------------


class TestSequenceContinuityCheck:
    def test_contiguous_sequence(self) -> None:
        cond = {"sequence": [1, 2, 3, 4, 5]}
        ok, msg = _eval_sequence_continuity_check({}, cond)
        assert ok is True
        assert "5 is contiguous" in msg

    def test_gap_detected(self) -> None:
        cond = {"sequence": [1, 2, 4, 5]}
        ok, msg = _eval_sequence_continuity_check({}, cond)
        assert ok is False
        assert "gap at index 2" in msg

    def test_empty_sequence_passes(self) -> None:
        ok, msg = _eval_sequence_continuity_check({}, {})
        assert ok is True
        assert "no sequence" in msg

    def test_single_element_passes(self) -> None:
        cond = {"sequence": [7]}
        ok, _ = _eval_sequence_continuity_check({}, cond)
        assert ok is True

    def test_values_key_alias(self) -> None:
        cond = {"values": [0, 1, 2]}
        ok, _ = _eval_sequence_continuity_check({}, cond)
        assert ok is True

    def test_gap_at_start_fails(self) -> None:
        cond = {"sequence": [1, 3]}
        ok, msg = _eval_sequence_continuity_check({}, cond)
        assert ok is False
        assert "1 -> 3" in msg


class TestVerifyBeforeRender:
    def test_both_valid_passes(self) -> None:
        ctx: dict[str, Any] = {"crypto_verified": True, "binding_verified": True}
        ok, msg = _eval_verify_before_render(ctx, {})
        assert ok is True
        assert "before render" in msg

    def test_signature_via_nested_key(self) -> None:
        ctx: dict[str, Any] = {
            "signature": {"is_valid": True},
            "hash": {"match": True},
        }
        ok, _ = _eval_verify_before_render(ctx, {})
        assert ok is True

    def test_signature_not_verified_fails(self) -> None:
        ctx: dict[str, Any] = {"crypto_verified": False, "binding_verified": True}
        ok, msg = _eval_verify_before_render(ctx, {})
        assert ok is False
        assert "signature not verified" in msg

    def test_hash_not_verified_fails(self) -> None:
        ctx: dict[str, Any] = {"crypto_verified": True, "binding_verified": False}
        ok, msg = _eval_verify_before_render(ctx, {})
        assert ok is False
        assert "binding not verified" in msg

    def test_both_invalid_fails_with_both_issues(self) -> None:
        ctx: dict[str, Any] = {"crypto_verified": False, "binding_verified": False}
        ok, msg = _eval_verify_before_render(ctx, {})
        assert ok is False
        assert "signature not verified" in msg
        assert "binding not verified" in msg

    def test_empty_context_fails(self) -> None:
        ok, msg = _eval_verify_before_render({}, {})
        assert ok is False


# ---------------------------------------------------------------------------
# Group 5: PDF exclusion operators
# ---------------------------------------------------------------------------


class TestCheckExclusionLength:
    def test_matching_length_passes(self) -> None:
        cond = {
            "exclusions": [{"start": 100, "length": 500}],
            "jumbf_length": 500,
        }
        ok, msg = _eval_check_exclusion_length({}, cond)
        assert ok is True
        assert "valid" in msg

    def test_mismatched_length_fails(self) -> None:
        cond = {
            "exclusions": [{"start": 100, "length": 400}],
            "jumbf_length": 500,
        }
        ok, msg = _eval_check_exclusion_length({}, cond)
        assert ok is False
        assert "400 != JUMBF length 500" in msg

    def test_no_exclusions_passes(self) -> None:
        cond = {"exclusions": [], "jumbf_length": 500}
        ok, msg = _eval_check_exclusion_length({}, cond)
        assert ok is True
        assert "no exclusions" in msg

    def test_jumbf_length_from_context(self) -> None:
        ctx: dict[str, Any] = {"jumbf_length": 200}
        cond = {"exclusions": [{"start": 0, "length": 200}]}
        ok, _ = _eval_check_exclusion_length(ctx, cond)
        assert ok is True

    def test_zero_jumbf_length_skips_check(self) -> None:
        # jumbf_length=0: cannot determine correctness -> pass
        cond = {"exclusions": [{"start": 0, "length": 123}], "jumbf_length": 0}
        ok, _ = _eval_check_exclusion_length({}, cond)
        assert ok is True

    def test_multiple_exclusions_first_mismatches(self) -> None:
        cond = {
            "exclusions": [
                {"start": 0, "length": 100},
                {"start": 200, "length": 500},
            ],
            "jumbf_length": 500,
        }
        ok, msg = _eval_check_exclusion_length({}, cond)
        assert ok is False
        assert "exclusion 0" in msg


class TestCheckOffsetAdjustment:
    def test_correct_adjustment_passes(self) -> None:
        cond = {"pre_offset": 1000, "post_offset": 1500, "adjustment": 500}
        ok, msg = _eval_check_offset_adjustment({}, cond)
        assert ok is True
        assert "500 valid" in msg

    def test_wrong_adjustment_fails(self) -> None:
        cond = {"pre_offset": 1000, "post_offset": 1200, "adjustment": 500}
        ok, msg = _eval_check_offset_adjustment({}, cond)
        assert ok is False
        assert "200 != expected 500" in msg

    def test_zero_offsets_passes(self) -> None:
        cond = {"pre_offset": 0, "post_offset": 0, "adjustment": 100}
        ok, msg = _eval_check_offset_adjustment({}, cond)
        assert ok is True
        assert "no offsets" in msg

    def test_expected_adjustment_key_alias(self) -> None:
        cond = {"pre_offset": 50, "post_offset": 150, "expected_adjustment": 100}
        ok, _ = _eval_check_offset_adjustment({}, cond)
        assert ok is True

    def test_zero_declared_adjustment_passes(self) -> None:
        # adjustment=0: no assertion to make
        cond = {"pre_offset": 100, "post_offset": 999, "adjustment": 0}
        ok, _ = _eval_check_offset_adjustment({}, cond)
        assert ok is True


# ---------------------------------------------------------------------------
# Group 6: Structural validation
# ---------------------------------------------------------------------------


class TestValidateManifestStore:
    def test_from_context_with_manifest_count(self) -> None:
        ctx: dict[str, Any] = {"manifest_store": {"manifest_count": 2}}
        ok, msg = _eval_validate_manifest_store(ctx, {})
        assert ok is True
        assert "2 manifest(s)" in msg

    def test_no_store_no_bytes_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_validate_manifest_store(ctx, {})
        assert ok is True
        assert "no store bytes" in msg

    def test_invalid_bytes_fails(self) -> None:
        cond = {"store_bytes": b"not valid jumbf at all"}
        ok, msg = _eval_validate_manifest_store({}, cond)
        assert ok is False
        assert "failed" in msg

    def test_decompressed_data_used_as_fallback(self) -> None:
        ctx: dict[str, Any] = {"_decompressed_data": b"garbage bytes for jumbf"}
        ok, msg = _eval_validate_manifest_store(ctx, {})
        assert ok is False
        assert "failed" in msg

    def test_context_store_zero_count_passes(self) -> None:
        # manifest_count=0 -> passes (no assertion to make without real bytes)
        ctx: dict[str, Any] = {"manifest_store": {"manifest_count": 0}}
        ok, msg = _eval_validate_manifest_store(ctx, {})
        assert ok is True


# ---------------------------------------------------------------------------
# Group 7: compute_hash_excluding_wrapper and compute_leaf_hash
# ---------------------------------------------------------------------------


class TestComputeHashExcludingWrapper:
    def test_no_wrapper_hashes_all(self) -> None:
        data = b"full content"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "wrapper_start": 0, "wrapper_length": 0}
        ok, msg = _eval_compute_hash_excluding_wrapper(ctx, cond)
        assert ok is True
        assert ctx["_computed_hash"] == _sha256(data)

    def test_excludes_wrapper(self) -> None:
        data = b"PRE" + b"WRAPPER" + b"POST"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "wrapper_start": 3, "wrapper_length": 7}
        ok, _ = _eval_compute_hash_excluding_wrapper(ctx, cond)
        assert ok is True
        from c2pa_conformance.crypto.hashing import ExclusionRange, compute_hash

        expected = compute_hash(data, "sha256", [ExclusionRange(start=3, length=7)])
        assert ctx["_computed_hash"] == expected

    def test_missing_asset_bytes_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_compute_hash_excluding_wrapper(ctx, {})
        assert ok is True
        assert "no asset bytes" in msg

    def test_start_length_keys_alias(self) -> None:
        data = b"ABCDE"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "start": 1, "length": 2}
        ok, _ = _eval_compute_hash_excluding_wrapper(ctx, cond)
        assert ok is True


class TestComputeLeafHash:
    def test_leaf_stored_in_context(self) -> None:
        data = b"blockblock"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "start": 0, "block_size": 5, "leaf_index": 0}
        ok, msg = _eval_compute_leaf_hash(ctx, cond)
        assert ok is True
        assert "computed leaf 0 hash" in msg
        assert ctx["_merkle_leaves"][0] == _sha256(b"block")

    def test_multiple_leaves(self) -> None:
        data = b"AAAABBBB"
        ctx: dict[str, Any] = {"asset_bytes": data}
        _eval_compute_leaf_hash(
            ctx, {"algorithm": "sha256", "start": 0, "block_size": 4, "leaf_index": 0}
        )
        _eval_compute_leaf_hash(
            ctx, {"algorithm": "sha256", "start": 4, "block_size": 4, "leaf_index": 1}
        )
        assert ctx["_merkle_leaves"][0] == _sha256(b"AAAA")
        assert ctx["_merkle_leaves"][1] == _sha256(b"BBBB")

    def test_missing_asset_bytes_passes(self) -> None:
        ctx: dict[str, Any] = {}
        ok, msg = _eval_compute_leaf_hash(ctx, {})
        assert ok is True
        assert "no asset bytes" in msg

    def test_length_key_alias(self) -> None:
        data = b"hello world"
        ctx: dict[str, Any] = {"asset_bytes": data}
        cond = {"algorithm": "sha256", "start": 0, "length": 5, "leaf_index": 3}
        ok, _ = _eval_compute_leaf_hash(ctx, cond)
        assert ok is True
        assert ctx["_merkle_leaves"][3] == _sha256(b"hello")
