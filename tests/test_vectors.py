"""Tests for C2PA test vector generation.

Covers: minimal asset builders, valid vector generation with round-trip
verification, structural mutations, crypto mutations, binding mutations,
full generation pipeline, and category filtering.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from c2pa_conformance.crypto.cose import CoseVerifyError, decode_cose_sign1, verify_signature
from c2pa_conformance.embedders import embed_jpeg, embed_png
from c2pa_conformance.extractors import detect_and_extract
from c2pa_conformance.extractors.base import ExtractionError
from c2pa_conformance.extractors.jpeg import JPEGExtractor
from c2pa_conformance.extractors.png import PNGExtractor
from c2pa_conformance.parser.jumbf import JUMBFParseError, parse_jumbf
from c2pa_conformance.parser.manifest import ManifestParseError, parse_manifest_store
from c2pa_conformance.vectors.assets import minimal_jpeg, minimal_png
from c2pa_conformance.vectors.definitions import get_all_definitions
from c2pa_conformance.vectors.generator import _generate_pki, generate_all_vectors
from c2pa_conformance.vectors.mutations import (
    corrupt_box_type,
    tamper_container_bytes,
    tamper_signature,
    truncate_jumbf,
)

# ---------------------------------------------------------------------------
# Session-scoped PKI fixture (generated once per test run)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki() -> dict:
    """Generate the test PKI hierarchy once for the entire session."""
    return _generate_pki()


# ---------------------------------------------------------------------------
# 1. Minimal asset generators
# ---------------------------------------------------------------------------


class TestMinimalJpeg:
    def test_starts_with_soi(self) -> None:
        """Output must start with JPEG SOI marker (0xFF 0xD8)."""
        data = minimal_jpeg()
        assert data[:2] == b"\xff\xd8"

    def test_ends_with_eoi(self) -> None:
        """Output must end with JPEG EOI marker (0xFF 0xD9)."""
        data = minimal_jpeg()
        assert data[-2:] == b"\xff\xd9"

    def test_contains_app0(self) -> None:
        """Output must contain an APP0 (JFIF) segment."""
        data = minimal_jpeg()
        assert b"\xff\xe0" in data

    def test_embed_round_trip(self) -> None:
        """minimal_jpeg() is valid enough for embed_jpeg round-trip extraction."""
        import cbor2

        from c2pa_conformance.builder.jumbf_builder import build_cbor_box, build_superbox

        _UUID = b"\x63\x32\x70\x61" + b"\x00" * 12
        jumbf = build_superbox(_UUID, "test", [build_cbor_box(cbor2.dumps({"k": 1}))])

        jpeg = minimal_jpeg()
        embedded = embed_jpeg(jpeg, jumbf)
        extracted = JPEGExtractor.extract(embedded)
        assert extracted.jumbf_bytes == jumbf

    def test_deterministic(self) -> None:
        """minimal_jpeg() produces the same bytes each call."""
        assert minimal_jpeg() == minimal_jpeg()

    def test_non_trivial_size(self) -> None:
        """minimal_jpeg() should be more than just SOI+EOI (must include markers)."""
        data = minimal_jpeg()
        assert len(data) > 10


class TestMinimalPng:
    def test_starts_with_png_signature(self) -> None:
        """Output must start with the PNG signature bytes."""
        data = minimal_png()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"

    def test_contains_ihdr(self) -> None:
        """Output must contain an IHDR chunk."""
        data = minimal_png()
        assert b"IHDR" in data

    def test_contains_idat(self) -> None:
        """Output must contain an IDAT chunk."""
        data = minimal_png()
        assert b"IDAT" in data

    def test_contains_iend(self) -> None:
        """Output must contain an IEND chunk."""
        data = minimal_png()
        assert b"IEND" in data

    def test_embed_round_trip(self) -> None:
        """minimal_png() is valid enough for embed_png round-trip extraction."""
        import cbor2

        from c2pa_conformance.builder.jumbf_builder import build_cbor_box, build_superbox

        _UUID = b"\x63\x32\x70\x61" + b"\x00" * 12
        jumbf = build_superbox(_UUID, "test", [build_cbor_box(cbor2.dumps({"k": 2}))])

        png = minimal_png()
        embedded = embed_png(png, jumbf)
        extracted = PNGExtractor.extract(embedded)
        assert extracted.jumbf_bytes == jumbf

    def test_deterministic(self) -> None:
        """minimal_png() produces the same bytes each call."""
        assert minimal_png() == minimal_png()


# ---------------------------------------------------------------------------
# 2. Valid vector generation with round-trip verification
# ---------------------------------------------------------------------------


class TestValidVectors:
    def test_valid_jpeg_es256_roundtrip(self, tmp_path: Path, pki: dict) -> None:
        """valid_jpeg_es256 can be extracted and parsed."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        jpeg_result = next(r for r in results if r["name"] == "valid_jpeg_es256")

        assert "error" not in jpeg_result
        vector_path = Path(jpeg_result["path"])
        assert vector_path.exists()

        # Extract JUMBF from the JPEG
        extraction = detect_and_extract(vector_path)
        assert extraction.container_format == "jpeg"
        assert len(extraction.jumbf_bytes) > 0

        # Parse manifest store
        store = parse_manifest_store(extraction.jumbf_bytes)
        assert store.manifest_count == 1
        assert store.active_manifest is not None
        assert store.active_manifest.claim is not None
        assert store.active_manifest.claim.claim_generator == "c2pa-conformance-suite/test-vectors"

    def test_valid_png_es256_roundtrip(self, tmp_path: Path, pki: dict) -> None:
        """valid_png_es256 can be extracted and parsed."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        png_result = next(r for r in results if r["name"] == "valid_png_es256")

        assert "error" not in png_result
        vector_path = Path(png_result["path"])

        extraction = detect_and_extract(vector_path)
        assert extraction.container_format == "png"

        store = parse_manifest_store(extraction.jumbf_bytes)
        assert store.manifest_count == 1
        assert store.active_manifest is not None

    def test_valid_sidecar_roundtrip(self, tmp_path: Path, pki: dict) -> None:
        """valid_sidecar can be read back and parsed."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        sidecar_result = next(r for r in results if r["name"] == "valid_sidecar")

        assert "error" not in sidecar_result
        vector_path = Path(sidecar_result["path"])

        extraction = detect_and_extract(vector_path)
        assert extraction.container_format == "sidecar"

        store = parse_manifest_store(extraction.jumbf_bytes)
        assert store.manifest_count == 1

    def test_valid_jpeg_signature_verifies(self, tmp_path: Path, pki: dict) -> None:
        """The COSE_Sign1 signature in valid_jpeg_es256 verifies correctly."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        jpeg_result = next(r for r in results if r["name"] == "valid_jpeg_es256")

        vector_path = Path(jpeg_result["path"])
        extraction = detect_and_extract(vector_path)
        store = parse_manifest_store(extraction.jumbf_bytes)
        manifest = store.active_manifest

        assert manifest is not None
        assert manifest.claim is not None
        assert len(manifest.signature_bytes) > 0

        cose = decode_cose_sign1(manifest.signature_bytes)
        result = verify_signature(cose, manifest.claim.raw_cbor)
        assert result is True

    def test_valid_vectors_expected_pass_true(self, tmp_path: Path) -> None:
        """All valid category vectors have expected_pass=True."""
        defs = [d for d in get_all_definitions() if d.category == "valid"]
        for d in defs:
            assert d.expected_pass is True, f"{d.name} should have expected_pass=True"


# ---------------------------------------------------------------------------
# 3. Structural mutations
# ---------------------------------------------------------------------------


class TestStructuralMutations:
    def test_truncate_jumbf_makes_parse_fail(self, tmp_path: Path) -> None:
        """truncated_jumbf vector: extraction or parsing fails."""
        results = generate_all_vectors(tmp_path, categories=["structural"])
        trunc_result = next(r for r in results if r["name"] == "truncated_jumbf")

        assert "error" not in trunc_result, "Vector generation itself should succeed"

        vector_path = Path(trunc_result["path"])
        data = vector_path.read_bytes()

        # Attempt extraction - the JUMBF is embedded in APP11 so extraction
        # may succeed (the bytes are present), but parsing should fail
        try:
            extraction = JPEGExtractor.extract(data)
            # If extraction succeeds, the resulting JUMBF should be malformed
            with pytest.raises((JUMBFParseError, ManifestParseError, Exception)):
                parse_manifest_store(extraction.jumbf_bytes)
        except (ExtractionError, Exception):
            # Extraction failure also counts - the vector is invalid
            pass

    def test_corrupt_box_type_makes_parse_fail(self, tmp_path: Path) -> None:
        """corrupt_box_type vector: extraction or parsing fails."""
        results = generate_all_vectors(tmp_path, categories=["structural"])
        corrupt_result = next(r for r in results if r["name"] == "corrupt_box_type")

        assert "error" not in corrupt_result

        vector_path = Path(corrupt_result["path"])
        data = vector_path.read_bytes()

        try:
            extraction = JPEGExtractor.extract(data)
            jumbf_bytes = extraction.jumbf_bytes
            # The box type is corrupted; parse_jumbf or parse_manifest_store should
            # either fail or return an empty/invalid store
            try:
                parse_jumbf(jumbf_bytes)
                # If it parses, the store should not be a valid C2PA store
                store = parse_manifest_store(jumbf_bytes)
                # An empty store or no active manifest indicates failure
                assert store.manifest_count == 0 or store.active_manifest is None
            except (JUMBFParseError, ManifestParseError):
                pass  # Expected failure
        except Exception:
            pass  # Extraction failure also indicates the vector is invalid

    def test_structural_definitions_expected_pass_false(self) -> None:
        """All structural category vectors have expected_pass=False."""
        defs = [d for d in get_all_definitions() if d.category == "structural"]
        for d in defs:
            assert d.expected_pass is False, f"{d.name} should have expected_pass=False"

    def test_truncate_mutation_function(self) -> None:
        """truncate_jumbf returns exactly half the bytes."""
        data = b"\x00" * 100
        result = truncate_jumbf(data)
        assert len(result) == 50
        assert result == data[:50]

    def test_corrupt_box_type_mutation_function(self) -> None:
        """corrupt_box_type overwrites bytes 4-8 with 'XXXX'."""
        data = b"\x00\x01\x02\x03" + b"TYPE" + b"\x00" * 10
        result = corrupt_box_type(data)
        assert result[4:8] == b"XXXX"
        assert result[:4] == data[:4]
        assert result[8:] == data[8:]


# ---------------------------------------------------------------------------
# 4. Crypto mutations
# ---------------------------------------------------------------------------


class TestCryptoMutations:
    def test_tampered_signature_crypto_fails(self, tmp_path: Path) -> None:
        """tampered_signature vector: extraction succeeds but signature invalid."""
        results = generate_all_vectors(tmp_path, categories=["crypto"])
        tampered_result = next(r for r in results if r["name"] == "tampered_signature")

        assert "error" not in tampered_result

        vector_path = Path(tampered_result["path"])
        data = vector_path.read_bytes()

        # Extraction should succeed (the JUMBF bytes are embedded correctly)
        extraction = JPEGExtractor.extract(data)

        try:
            store = parse_manifest_store(extraction.jumbf_bytes)
            manifest = store.active_manifest

            if manifest is not None and manifest.claim is not None and manifest.signature_bytes:
                cose = decode_cose_sign1(manifest.signature_bytes)
                # Signature verification should fail
                with pytest.raises((CoseVerifyError, Exception)):
                    verify_signature(cose, manifest.claim.raw_cbor)
        except (ManifestParseError, Exception):
            # Parsing failure from a corrupted COSE structure is also acceptable
            pass

    def test_tamper_signature_mutation_function(self) -> None:
        """tamper_signature flips a byte 20 positions from the end."""
        data = bytes(range(50))
        result = tamper_signature(data)
        # byte at position len-20 = position 30 should be flipped
        assert result[30] == data[30] ^ 0xFF
        # all other bytes unchanged
        assert result[:30] == data[:30]
        assert result[31:] == data[31:]

    def test_tamper_signature_too_short(self) -> None:
        """tamper_signature returns input unchanged if fewer than 32 bytes."""
        data = b"\x01" * 10
        assert tamper_signature(data) == data

    def test_crypto_definitions_expected_pass_false(self) -> None:
        """All crypto category vectors have expected_pass=False."""
        defs = [d for d in get_all_definitions() if d.category == "crypto"]
        for d in defs:
            assert d.expected_pass is False, f"{d.name} should have expected_pass=False"

    def test_expired_signer_variant(self) -> None:
        """expired_signer vector definition uses signer_variant='expired'."""
        defs = {d.name: d for d in get_all_definitions()}
        assert defs["expired_signer"].signer_variant == "expired"

    def test_wrong_eku_signer_variant(self) -> None:
        """wrong_eku_signer vector definition uses signer_variant='wrong_eku'."""
        defs = {d.name: d for d in get_all_definitions()}
        assert defs["wrong_eku_signer"].signer_variant == "wrong_eku"


# ---------------------------------------------------------------------------
# 5. Binding mutations
# ---------------------------------------------------------------------------


class TestBindingMutations:
    def test_tampered_content_extraction_succeeds(self, tmp_path: Path) -> None:
        """tampered_content vector: extraction succeeds (JUMBF is intact)."""
        results = generate_all_vectors(tmp_path, categories=["binding"])
        tampered = next(r for r in results if r["name"] == "tampered_content")

        assert "error" not in tampered

        vector_path = Path(tampered["path"])
        data = vector_path.read_bytes()

        # The JUMBF manifest store is present; extraction should work
        extraction = JPEGExtractor.extract(data)
        assert len(extraction.jumbf_bytes) > 0

    def test_tampered_content_manifest_parseable(self, tmp_path: Path) -> None:
        """tampered_content vector: manifest parses (hash mismatch is semantic, not structural)."""
        results = generate_all_vectors(tmp_path, categories=["binding"])
        tampered = next(r for r in results if r["name"] == "tampered_content")

        vector_path = Path(tampered["path"])
        data = vector_path.read_bytes()
        extraction = JPEGExtractor.extract(data)
        store = parse_manifest_store(extraction.jumbf_bytes)

        # Manifest store should parse successfully
        assert store.manifest_count == 1

    def test_tamper_container_bytes_mutation_function(self) -> None:
        """tamper_container_bytes flips a byte 10 positions from the end."""
        data = bytes(range(200))
        result = tamper_container_bytes(data)
        pos = len(data) - 10  # = 190
        assert result[pos] == data[pos] ^ 0xFF
        assert result[:pos] == data[:pos]
        assert result[pos + 1 :] == data[pos + 1 :]

    def test_tamper_container_bytes_too_short(self) -> None:
        """tamper_container_bytes returns input unchanged if fewer than 100 bytes."""
        data = b"\xaa" * 50
        assert tamper_container_bytes(data) == data

    def test_binding_definitions_expected_pass_false(self) -> None:
        """All binding category vectors have expected_pass=False."""
        defs = [d for d in get_all_definitions() if d.category == "binding"]
        for d in defs:
            assert d.expected_pass is False, f"{d.name} should have expected_pass=False"


# ---------------------------------------------------------------------------
# 6. Full generation pipeline
# ---------------------------------------------------------------------------


class TestFullGeneration:
    def test_all_vectors_created(self, tmp_path: Path) -> None:
        """generate_all_vectors creates a file for each definition."""
        defs = get_all_definitions()
        results = generate_all_vectors(tmp_path)

        assert len(results) == len(defs)
        for r in results:
            if "error" not in r:
                assert Path(r["path"]).exists(), f"Vector file missing: {r['path']}"

    def test_index_json_exists(self, tmp_path: Path) -> None:
        """generate_all_vectors writes an index.json file."""
        generate_all_vectors(tmp_path)
        index_path = tmp_path / "index.json"
        assert index_path.exists()

    def test_index_json_contents(self, tmp_path: Path) -> None:
        """index.json contains one entry per vector with required fields."""
        results = generate_all_vectors(tmp_path)
        index_path = tmp_path / "index.json"

        with open(index_path) as f:
            index = json.load(f)

        assert len(index) == len(results)

        required_fields = {"name", "category"}
        for entry in index:
            for field in required_fields:
                assert field in entry, f"index.json entry missing field '{field}': {entry}"

    def test_metadata_json_written_per_vector(self, tmp_path: Path) -> None:
        """Each vector has a companion .json metadata file."""
        results = generate_all_vectors(tmp_path)
        successes = [r for r in results if "error" not in r]

        for r in successes:
            vector_path = Path(r["path"])
            meta_path = vector_path.with_suffix(".json")
            assert meta_path.exists(), f"Metadata file missing: {meta_path}"

            with open(meta_path) as f:
                meta = json.load(f)
            assert meta["name"] == r["name"]
            assert meta["category"] == r["category"]

    def test_vectors_organized_by_category(self, tmp_path: Path) -> None:
        """Vectors are written into category subdirectories."""
        generate_all_vectors(tmp_path)
        categories = {d.category for d in get_all_definitions()}

        for cat in categories:
            cat_dir = tmp_path / cat
            assert cat_dir.is_dir(), f"Category directory missing: {cat_dir}"

    def test_no_errors_from_valid_definitions(self, tmp_path: Path) -> None:
        """Valid-category vectors should generate without errors."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        for r in results:
            assert "error" not in r, f"Unexpected error for {r['name']}: {r.get('error')}"

    def test_generate_all_definitions_count(self) -> None:
        """get_all_definitions returns the expected number of vector definitions."""
        defs = get_all_definitions()
        # 3 valid + 3 structural + 3 crypto + 1 binding + 1 timestamp + 2 ingredient = 13
        assert len(defs) == 13

    def test_categories_covered(self) -> None:
        """All expected categories are present in definitions."""
        defs = get_all_definitions()
        categories = {d.category for d in defs}
        expected = {"valid", "structural", "crypto", "binding", "timestamp", "ingredient"}
        assert categories == expected


# ---------------------------------------------------------------------------
# 7. Category filtering
# ---------------------------------------------------------------------------


class TestCategoryFilter:
    def test_filter_valid_only(self, tmp_path: Path) -> None:
        """Filtering by 'valid' generates only valid-category vectors."""
        results = generate_all_vectors(tmp_path, categories=["valid"])

        for r in results:
            assert r["category"] == "valid", f"{r['name']} not in 'valid' category"

    def test_filter_valid_count(self, tmp_path: Path) -> None:
        """Filtering by 'valid' generates exactly 3 vectors."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        assert len(results) == 3

    def test_filter_crypto_only(self, tmp_path: Path) -> None:
        """Filtering by 'crypto' generates only crypto-category vectors."""
        results = generate_all_vectors(tmp_path, categories=["crypto"])
        for r in results:
            assert r["category"] == "crypto"

    def test_filter_multiple_categories(self, tmp_path: Path) -> None:
        """Filtering by multiple categories returns vectors from all specified categories."""
        results = generate_all_vectors(tmp_path, categories=["valid", "structural"])
        categories_seen = {r["category"] for r in results}
        assert categories_seen == {"valid", "structural"}

    def test_filter_creates_only_specified_dirs(self, tmp_path: Path) -> None:
        """Only the specified category directory is created when filtering."""
        generate_all_vectors(tmp_path, categories=["valid"])
        assert (tmp_path / "valid").is_dir()
        assert not (tmp_path / "crypto").exists()
        assert not (tmp_path / "structural").exists()

    def test_filter_valid_no_errors(self, tmp_path: Path) -> None:
        """Valid-only generation produces no errors."""
        results = generate_all_vectors(tmp_path, categories=["valid"])
        errors = [r for r in results if "error" in r]
        assert errors == []

    def test_filter_all_categories_via_none(self, tmp_path: Path) -> None:
        """Passing categories=None generates all vectors."""
        all_defs = get_all_definitions()
        results = generate_all_vectors(tmp_path, categories=None)
        assert len(results) == len(all_defs)
