"""Tests for COSE signer, JUMBF builder, and manifest store builder.

All tests are round-trip: build with the builder modules, then parse or
decode with existing parser/crypto modules to verify correctness.
"""

from __future__ import annotations

import struct

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from c2pa_conformance.builder.cose_signer import (
    ES256,
    sign_cose,
)
from c2pa_conformance.builder.jumbf_builder import (
    CBOR_BOX,
    JUMD,
    build_box,
    build_cbor_box,
    build_jumd,
    build_superbox,
)
from c2pa_conformance.builder.manifest_builder import build_manifest_store
from c2pa_conformance.crypto.cose import (
    CoseVerifyError,
    decode_cose_sign1,
    verify_signature,
)
from c2pa_conformance.crypto.pki import generate_test_pki
from c2pa_conformance.crypto.verifier import verify_manifest_signature
from c2pa_conformance.parser.jumbf import (
    parse_boxes,
    parse_jumd,
)
from c2pa_conformance.parser.manifest import parse_manifest_store

# ---------------------------------------------------------------------------
# Shared PKI fixture (generated once per test session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Generate a complete test PKI hierarchy for the session."""
    output_dir = tmp_path_factory.mktemp("builder_pki")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="session")
def valid_key(pki: dict):
    """EC P-256 private key for the valid signer."""
    return pki["valid_signer"].key


@pytest.fixture(scope="session")
def cert_chain(pki: dict) -> list:
    """Full certificate chain: [signer, intermediate, root]."""
    return [
        pki["valid_signer"].cert,
        pki["intermediate"].cert,
        pki["root"].cert,
    ]


# ---------------------------------------------------------------------------
# 1. JUMBF builder: build_box
# ---------------------------------------------------------------------------


def test_build_box_standard() -> None:
    """A standard box has an 8-byte header with correct LBox and TBox."""
    payload = b"hello world"
    raw = build_box(b"test", payload)

    # Parse back with the existing parser
    boxes = parse_boxes(raw)
    assert len(boxes) == 1
    box = boxes[0]
    assert box.box_type == b"test"
    assert box.payload == payload
    assert box.size == 8 + len(payload)


def test_build_box_empty_payload() -> None:
    """A box with an empty payload has size == 8."""
    raw = build_box(b"free", b"")
    assert struct.unpack_from(">I", raw, 0)[0] == 8
    assert raw[4:8] == b"free"


def test_build_box_large() -> None:
    """A payload that keeps total <= 0xFFFFFFFF uses the standard 8-byte header."""
    # We test the standard header path with a smallish payload and verify the
    # extended-size path triggers at the boundary (>= 0xFFFFFFFF - 8 + 1 bytes).
    # Rather than allocating 4 GiB, we verify the header format for a normal box.
    payload = b"\xab" * 1024
    raw = build_box(b"data", payload)
    lbox = struct.unpack_from(">I", raw, 0)[0]
    assert lbox == 8 + 1024
    assert raw[4:8] == b"data"


def test_build_box_extended_header() -> None:
    """When LBox would overflow 32 bits, the builder uses XLBox (LBox=1)."""
    # Construct a mock payload large enough to need XLBox.
    # We cannot allocate 4 GiB, so we monkeypatch _MAX_LBOX to force the path.
    import c2pa_conformance.builder.jumbf_builder as jb

    original = jb._MAX_LBOX
    try:
        jb._MAX_LBOX = 20  # anything above 8 + len(payload) triggers extended
        payload = b"\xcc" * 20  # total would be 28 > 20, forces extended header
        raw = jb.build_box(b"data", payload)
    finally:
        jb._MAX_LBOX = original

    # Extended header: LBox=1, TBox=b"data", XLBox (8 bytes), then payload
    lbox = struct.unpack_from(">I", raw, 0)[0]
    assert lbox == 1
    assert raw[4:8] == b"data"
    xlbox = struct.unpack_from(">Q", raw, 8)[0]
    assert xlbox == 16 + len(payload)
    assert raw[16:] == payload


# ---------------------------------------------------------------------------
# 2. JUMBF builder: build_jumd
# ---------------------------------------------------------------------------


def test_build_jumd() -> None:
    """A JUMD box round-trips through parse_jumd correctly."""
    type_uuid = b"\x63\x32\x70\x61" + b"\x00" * 12
    raw = build_jumd(type_uuid, "test-label")

    # The JUMD box starts with LBox/TBox; strip the 8-byte header to get payload.
    boxes = parse_boxes(raw)
    assert len(boxes) == 1
    box = boxes[0]
    assert box.box_type == JUMD

    parsed_uuid, parsed_label = parse_jumd(box.payload)
    assert parsed_uuid == type_uuid
    assert parsed_label == "test-label"


def test_build_jumd_no_label() -> None:
    """A JUMD with toggles=0 produces an empty label on parse."""
    type_uuid = b"\x00" * 16
    raw = build_jumd(type_uuid, "ignored", toggles=0x00)

    boxes = parse_boxes(raw)
    parsed_uuid, parsed_label = parse_jumd(boxes[0].payload)
    assert parsed_uuid == type_uuid
    assert parsed_label == ""


def test_build_jumd_wrong_uuid_length() -> None:
    """build_jumd raises ValueError when type_uuid is not 16 bytes."""
    with pytest.raises(ValueError, match="16 bytes"):
        build_jumd(b"\x00" * 15, "label")


# ---------------------------------------------------------------------------
# 3. JUMBF builder: build_superbox
# ---------------------------------------------------------------------------


def test_build_superbox() -> None:
    """A superbox contains a JUMD and all provided children."""
    type_uuid = b"\x11" * 16
    child1 = build_cbor_box(cbor2.dumps({"a": 1}))
    child2 = build_cbor_box(cbor2.dumps({"b": 2}))

    raw = build_superbox(type_uuid, "my-superbox", [child1, child2])
    boxes = parse_boxes(raw)

    assert len(boxes) == 1
    superbox = boxes[0]
    assert superbox.is_superbox
    assert superbox.label == "my-superbox"
    assert superbox.uuid == type_uuid

    # Children: JUMD + child1 + child2 = 3
    assert len(superbox.children) == 3
    assert superbox.children[0].box_type == JUMD
    assert superbox.children[1].box_type == CBOR_BOX
    assert superbox.children[2].box_type == CBOR_BOX


def test_build_superbox_no_children() -> None:
    """A superbox with no data children still contains the JUMD."""
    type_uuid = b"\x22" * 16
    raw = build_superbox(type_uuid, "empty-box", [])
    boxes = parse_boxes(raw)

    assert len(boxes) == 1
    assert boxes[0].is_superbox
    assert boxes[0].label == "empty-box"
    # Only the JUMD child
    assert len(boxes[0].children) == 1
    assert boxes[0].children[0].box_type == JUMD


# ---------------------------------------------------------------------------
# 4. JUMBF builder: build_cbor_box
# ---------------------------------------------------------------------------


def test_build_cbor_box() -> None:
    """A CBOR box round-trips: the payload decodes to the original data."""
    data = {"key": "value", "num": 42}
    cbor_bytes = cbor2.dumps(data)
    raw = build_cbor_box(cbor_bytes)

    boxes = parse_boxes(raw)
    assert len(boxes) == 1
    box = boxes[0]
    assert box.box_type == CBOR_BOX
    decoded = cbor2.loads(box.payload)
    assert decoded == data


# ---------------------------------------------------------------------------
# 5. COSE signer: sign_cose ES256
# ---------------------------------------------------------------------------


def test_sign_cose_es256(valid_key, cert_chain) -> None:
    """A COSE_Sign1 built with ES256 decodes and verifies successfully."""
    claim_cbor = cbor2.dumps({"claim_generator": "test/1.0"})
    raw = sign_cose(claim_cbor, valid_key, cert_chain, ES256)

    cose = decode_cose_sign1(raw)
    assert cose.algorithm_id == ES256
    assert cose.algorithm_name == "ES256"
    assert len(cose.x5chain) == 3  # signer + intermediate + root
    assert verify_signature(cose, claim_cbor) is True


def test_sign_cose_roundtrip(valid_key, cert_chain) -> None:
    """sign_cose -> decode_cose_sign1 -> verify_signature is a complete round-trip."""
    claim_cbor = cbor2.dumps({"action": "round-trip"})
    raw = sign_cose(claim_cbor, valid_key, cert_chain, ES256)

    cose = decode_cose_sign1(raw)
    assert cose.protected_header[1] == ES256
    assert "x5chain" in cose.protected_header
    expected_der = cert_chain[0].public_bytes(serialization.Encoding.DER)
    assert cose.protected_header["x5chain"][0] == expected_der
    result = verify_signature(cose, claim_cbor)
    assert result is True


def test_sign_cose_wrong_key_fails(cert_chain) -> None:
    """Signing with one key and verifying with a different certificate fails."""
    signing_key = ec.generate_private_key(ec.SECP256R1())
    claim_cbor = cbor2.dumps({"test": "wrong-key"})

    # Use cert_chain[0] which corresponds to a different key than signing_key
    raw = sign_cose(claim_cbor, signing_key, cert_chain, ES256)
    cose = decode_cose_sign1(raw)

    with pytest.raises(CoseVerifyError):
        verify_signature(cose, claim_cbor)


def test_sign_cose_cbor_tag_18(valid_key, cert_chain) -> None:
    """sign_cose output is tagged with CBOR tag 18 (COSE_Sign1)."""
    raw = sign_cose(b"claim", valid_key, cert_chain, ES256)
    decoded = cbor2.loads(raw)
    assert isinstance(decoded, cbor2.CBORTag)
    assert decoded.tag == 18


def test_sign_cose_detached_payload(valid_key, cert_chain) -> None:
    """The COSE_Sign1 payload field is nil (C2PA detached payload requirement)."""
    raw = sign_cose(b"claim", valid_key, cert_chain, ES256)
    decoded = cbor2.loads(raw)
    _, _, payload, _ = decoded.value
    assert payload is None


# ---------------------------------------------------------------------------
# 6. Manifest store builder: round-trip
# ---------------------------------------------------------------------------


def test_build_manifest_store_roundtrip(valid_key, cert_chain) -> None:
    """Build a manifest store and parse it back; structure must be intact."""
    store_bytes = build_manifest_store(
        claim_data={"claim_generator": "test-suite/1.0"},
        assertions=[],
        private_key=valid_key,
        cert_chain=cert_chain,
    )

    store = parse_manifest_store(store_bytes)
    assert store.manifest_count == 1
    assert store.active_manifest is not None

    manifest = store.active_manifest
    assert manifest.label.startswith("urn:uuid:")
    assert manifest.claim is not None
    assert manifest.claim.claim_generator == "test-suite/1.0"
    assert isinstance(manifest.signature_bytes, bytes)
    assert len(manifest.signature_bytes) > 0


def test_build_manifest_store_with_assertions(valid_key, cert_chain) -> None:
    """Build with two assertions; both must appear in the parsed manifest."""
    assertions = [
        {"label": "c2pa.hash.data", "data": {"alg": "sha256", "hash": b"\xab" * 32}},
        {"label": "c2pa.training-mining", "data": {"entries": {}}},
    ]

    store_bytes = build_manifest_store(
        claim_data={},
        assertions=assertions,
        private_key=valid_key,
        cert_chain=cert_chain,
    )

    store = parse_manifest_store(store_bytes)
    manifest = store.active_manifest
    assert manifest is not None
    assert len(manifest.assertions) == 2

    labels = [a.label for a in manifest.assertions]
    assert "c2pa.hash.data" in labels
    assert "c2pa.training-mining" in labels


def test_build_manifest_store_signature_valid(valid_key, cert_chain) -> None:
    """The built manifest's COSE_Sign1 signature verifies against the claim bytes."""
    store_bytes = build_manifest_store(
        claim_data={"claim_generator": "test/1.0"},
        assertions=[{"label": "c2pa.actions", "data": {"actions": []}}],
        private_key=valid_key,
        cert_chain=cert_chain,
    )

    store = parse_manifest_store(store_bytes)
    manifest = store.active_manifest
    assert manifest is not None
    assert manifest.claim is not None

    cose = decode_cose_sign1(manifest.signature_bytes)
    result = verify_signature(cose, manifest.claim.raw_cbor)
    assert result is True


def test_build_manifest_store_custom_label(valid_key, cert_chain) -> None:
    """A custom manifest_label is preserved through the parse round-trip."""
    label = "urn:uuid:aaaabbbb-cccc-dddd-eeee-ffffaaaabbbb"

    store_bytes = build_manifest_store(
        claim_data={},
        assertions=[],
        private_key=valid_key,
        cert_chain=cert_chain,
        manifest_label=label,
    )

    store = parse_manifest_store(store_bytes)
    assert store.active_manifest is not None
    assert store.active_manifest.label == label


def test_build_manifest_store_default_claim_generator(valid_key, cert_chain) -> None:
    """When claim_generator is not supplied, the default value is used."""
    store_bytes = build_manifest_store(
        claim_data={},
        assertions=[],
        private_key=valid_key,
        cert_chain=cert_chain,
    )

    store = parse_manifest_store(store_bytes)
    manifest = store.active_manifest
    assert manifest is not None
    assert manifest.claim is not None
    assert "c2pa-conformance-suite" in manifest.claim.claim_generator


# ---------------------------------------------------------------------------
# 7. Full pipeline: build -> write sidecar -> parse -> verify
# ---------------------------------------------------------------------------


def test_full_roundtrip_build_parse_verify(tmp_path, valid_key, cert_chain) -> None:
    """Build a manifest store, write it as a .c2pa sidecar, read back, verify."""
    assertions = [
        {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created"}]}},
    ]

    store_bytes = build_manifest_store(
        claim_data={"claim_generator": "full-pipeline-test/1.0"},
        assertions=assertions,
        private_key=valid_key,
        cert_chain=cert_chain,
        manifest_label="urn:uuid:12345678-1234-5678-1234-567812345678",
    )

    # Write as a .c2pa sidecar file
    sidecar = tmp_path / "test.c2pa"
    sidecar.write_bytes(store_bytes)

    # Read back and parse
    raw = sidecar.read_bytes()
    store = parse_manifest_store(raw)

    assert store.manifest_count == 1
    manifest = store.active_manifest
    assert manifest is not None
    assert manifest.label == "urn:uuid:12345678-1234-5678-1234-567812345678"
    assert manifest.claim is not None
    assert manifest.claim.claim_generator == "full-pipeline-test/1.0"
    assert len(manifest.assertions) == 1
    assert manifest.assertions[0].label == "c2pa.actions"

    # Verify signature with the verifier module
    result = verify_manifest_signature(manifest)
    assert result.signature_valid is True
    assert result.signature_status == "claimSignature.validated"
