"""Tests for two-pass content-bound manifest signing.

Verifies the build_bound_manifest() function produces manifests whose
data hash assertion correctly binds the manifest to its container.
"""

from __future__ import annotations

import cbor2
import pytest

from c2pa_conformance.binding.data_hash import verify_data_hash
from c2pa_conformance.builder.two_pass import (
    _compute_embedded_size,
    _get_insert_position,
    _make_data_hash_assertion,
    build_bound_manifest,
)
from c2pa_conformance.crypto.cose import decode_cose_sign1, verify_signature
from c2pa_conformance.crypto.pki import generate_test_pki
from c2pa_conformance.parser.manifest import parse_manifest_store
from c2pa_conformance.vectors.assets import minimal_jpeg, minimal_png

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    output_dir = tmp_path_factory.mktemp("two_pass_pki")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="session")
def valid_key(pki: dict):
    return pki["valid_signer"].key


@pytest.fixture(scope="session")
def cert_chain(pki: dict) -> list:
    return [pki["valid_signer"].cert, pki["intermediate"].cert]


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestMakeDataHashAssertion:
    def test_basic_structure(self) -> None:
        a = _make_data_hash_assertion("sha256", b"\x00" * 32, 100, 500)
        assert a["label"] == "c2pa.hash.data"
        assert a["data"]["alg"] == "sha256"
        assert a["data"]["hash"] == b"\x00" * 32
        assert a["data"]["exclusions"] == [{"start": 100, "length": 500}]

    def test_no_exclusion_when_length_zero(self) -> None:
        a = _make_data_hash_assertion("sha256", b"\xab" * 32, 0, 0)
        assert "exclusions" not in a["data"]


class TestComputeEmbeddedSize:
    def test_jpeg_single_segment(self) -> None:
        # Small JUMBF fits in one APP11 segment
        size = _compute_embedded_size("jpeg", 1000)
        assert size == 1000 + 12  # 1 segment * 12 overhead

    def test_jpeg_multiple_segments(self) -> None:
        # JUMBF larger than MAX_SEGMENT_PAYLOAD
        size = _compute_embedded_size("jpeg", 70000)
        # ceil(70000 / 65525) = 2 segments
        assert size == 70000 + 2 * 12

    def test_png(self) -> None:
        size = _compute_embedded_size("png", 1000)
        assert size == 1012  # 1000 + 12

    def test_unknown_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown"):
            _compute_embedded_size("tiff", 100)


class TestGetInsertPosition:
    def test_jpeg_after_app0(self) -> None:
        jpeg = minimal_jpeg()
        pos = _get_insert_position("jpeg", jpeg)
        # After SOI (2) + APP0 segment
        assert pos > 2

    def test_png_before_idat(self) -> None:
        png = minimal_png()
        pos = _get_insert_position("png", png)
        # After PNG sig (8) + IHDR chunk
        assert pos > 8

    def test_unknown_type(self) -> None:
        with pytest.raises(ValueError, match="Unknown"):
            _get_insert_position("tiff", b"")


# ---------------------------------------------------------------------------
# JPEG two-pass signing
# ---------------------------------------------------------------------------


class TestBuildBoundManifestJpeg:
    def test_produces_valid_embedded_jpeg(
        self,
        valid_key,
        cert_chain,
    ) -> None:
        """Embedded JPEG starts with SOI marker."""
        jpeg = minimal_jpeg()
        embedded, _ = build_bound_manifest(
            claim_data={"claim_generator": "two-pass-test/1.0"},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )
        assert embedded[:2] == b"\xff\xd8"
        assert len(embedded) > len(jpeg)

    def test_data_hash_verifies(self, valid_key, cert_chain) -> None:
        """The embedded data hash matches the container content."""
        jpeg = minimal_jpeg()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        # Parse the manifest to get the data hash assertion
        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        assert manifest is not None

        data_hash_assertions = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assert len(data_hash_assertions) == 1

        assertion_data = cbor2.loads(data_hash_assertions[0].raw_cbor)
        result = verify_data_hash(embedded, assertion_data)
        assert result.is_valid, f"Data hash mismatch: {result.message}"
        assert result.status_code == "assertion.dataHash.match"

    def test_signature_valid(self, valid_key, cert_chain) -> None:
        """The COSE_Sign1 signature verifies against the claim."""
        jpeg = minimal_jpeg()
        _, jumbf = build_bound_manifest(
            claim_data={"claim_generator": "sig-test/1.0"},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        assert manifest is not None

        cose = decode_cose_sign1(manifest.signature_bytes)
        assert verify_signature(cose, manifest.claim.raw_cbor) is True

    def test_exclusion_range_correct(self, valid_key, cert_chain) -> None:
        """The exclusion range exactly covers the APP11 segments."""
        jpeg = minimal_jpeg()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)
        exclusions = assertion_data["exclusions"]
        assert len(exclusions) == 1

        excl = exclusions[0]
        start = excl["start"]
        length = excl["length"]

        # The exclusion range must fit within the embedded container
        assert start >= 0
        assert start + length <= len(embedded)

        # Verify the excluded region starts with APP11 marker
        assert embedded[start : start + 2] == b"\xff\xeb"

    def test_jumbf_size_stable(self, valid_key, cert_chain) -> None:
        """Building twice with the same label produces same-size JUMBF."""
        jpeg = minimal_jpeg()
        label = "urn:uuid:stable-size-test"
        _, jumbf1 = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
            manifest_label=label,
        )
        _, jumbf2 = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
            manifest_label=label,
        )
        assert len(jumbf1) == len(jumbf2)

    def test_with_extra_assertions(self, valid_key, cert_chain) -> None:
        """Data hash works alongside other assertions."""
        jpeg = minimal_jpeg()
        assertions = [
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {"@type": "CreativeWork"},
            },
            {
                "label": "c2pa.actions",
                "data": {"actions": [{"action": "c2pa.created"}]},
            },
        ]
        embedded, jumbf = build_bound_manifest(
            claim_data={"claim_generator": "multi-assert/1.0"},
            assertions=assertions,
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        labels = [a.label for a in manifest.assertions]
        assert "c2pa.hash.data" in labels
        assert "stds.schema-org.CreativeWork" in labels
        assert "c2pa.actions" in labels

        # Verify data hash
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)
        result = verify_data_hash(embedded, assertion_data)
        assert result.is_valid


# ---------------------------------------------------------------------------
# PNG two-pass signing
# ---------------------------------------------------------------------------


class TestBuildBoundManifestPng:
    def test_produces_valid_embedded_png(
        self,
        valid_key,
        cert_chain,
    ) -> None:
        png = minimal_png()
        embedded, _ = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="png",
            container_bytes=png,
        )
        assert embedded[:8] == b"\x89PNG\r\n\x1a\n"
        assert len(embedded) > len(png)

    def test_data_hash_verifies(self, valid_key, cert_chain) -> None:
        png = minimal_png()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="png",
            container_bytes=png,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)

        result = verify_data_hash(embedded, assertion_data)
        assert result.is_valid, f"PNG data hash mismatch: {result.message}"

    def test_exclusion_covers_cabx_chunk(self, valid_key, cert_chain) -> None:
        """The exclusion range covers the entire caBX chunk."""
        png = minimal_png()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="png",
            container_bytes=png,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)
        excl = assertion_data["exclusions"][0]

        # caBX chunk type is at offset start + 4
        assert embedded[excl["start"] + 4 : excl["start"] + 8] == b"caBX"


# ---------------------------------------------------------------------------
# Sidecar (no data hash)
# ---------------------------------------------------------------------------


class TestBuildBoundManifestSidecar:
    def test_sidecar_returns_jumbf(self, valid_key, cert_chain) -> None:
        embedded, jumbf = build_bound_manifest(
            claim_data={"claim_generator": "sidecar/1.0"},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="sidecar",
        )
        # For sidecar, embedded == jumbf
        assert embedded == jumbf
        store = parse_manifest_store(jumbf)
        assert store.manifest_count == 1

    def test_sidecar_no_data_hash(self, valid_key, cert_chain) -> None:
        _, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="sidecar",
        )
        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assert len(dh) == 0


# ---------------------------------------------------------------------------
# Hash algorithm variants
# ---------------------------------------------------------------------------


class TestHashAlgorithms:
    @pytest.mark.parametrize(
        ("alg_id", "hash_alg", "digest_size"),
        [
            (-7, "sha256", 32),
            (-35, "sha384", 48),
        ],
    )
    def test_hash_algorithm_override(
        self,
        valid_key,
        cert_chain,
        alg_id,
        hash_alg,
        digest_size,
    ) -> None:
        jpeg = minimal_jpeg()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            algorithm=alg_id,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)

        assert assertion_data["alg"] == hash_alg
        assert len(assertion_data["hash"]) == digest_size

        result = verify_data_hash(embedded, assertion_data)
        assert result.is_valid


# ---------------------------------------------------------------------------
# Round-trip: build -> parse -> verify full pipeline
# ---------------------------------------------------------------------------


class TestFullRoundTrip:
    def test_jpeg_full_pipeline(self, valid_key, cert_chain) -> None:
        """Build bound JPEG, parse manifest, verify signature AND data hash."""
        jpeg = minimal_jpeg()
        embedded, jumbf = build_bound_manifest(
            claim_data={"claim_generator": "round-trip/1.0"},
            assertions=[
                {
                    "label": "c2pa.actions",
                    "data": {"actions": [{"action": "c2pa.created"}]},
                },
            ],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
            manifest_label="urn:uuid:round-trip-test",
        )

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest

        # Verify signature
        cose = decode_cose_sign1(manifest.signature_bytes)
        assert verify_signature(cose, manifest.claim.raw_cbor) is True

        # Verify data hash
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)
        result = verify_data_hash(embedded, assertion_data)
        assert result.is_valid

        # Verify other assertions preserved
        labels = [a.label for a in manifest.assertions]
        assert "c2pa.actions" in labels
        assert manifest.claim.claim_generator == "round-trip/1.0"
        assert manifest.label == "urn:uuid:round-trip-test"

    def test_tampering_detected(self, valid_key, cert_chain) -> None:
        """Modifying the embedded container after signing breaks the hash."""
        jpeg = minimal_jpeg()
        embedded, jumbf = build_bound_manifest(
            claim_data={},
            assertions=[],
            private_key=valid_key,
            cert_chain=cert_chain,
            container_type="jpeg",
            container_bytes=jpeg,
        )

        # Tamper with a byte near the end
        tampered = bytearray(embedded)
        tampered[-5] ^= 0xFF
        tampered = bytes(tampered)

        store = parse_manifest_store(jumbf)
        manifest = store.active_manifest
        dh = [a for a in manifest.assertions if a.label == "c2pa.hash.data"]
        assertion_data = cbor2.loads(dh[0].raw_cbor)

        result = verify_data_hash(tampered, assertion_data)
        assert not result.is_valid
        assert result.status_code == "assertion.dataHash.mismatch"
