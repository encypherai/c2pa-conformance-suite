"""Integration tests for the full conformance pipeline.

Tests the end-to-end flow: build a container with embedded JUMBF,
extract it, parse the manifest store, build context, and verify
the context structure.
"""

from __future__ import annotations

import struct
import zlib

import cbor2

from c2pa_conformance.cli import _build_context
from c2pa_conformance.extractors.base import ExtractionResult, detect_and_extract
from c2pa_conformance.parser.jumbf import (
    CBOR_BOX,
    JUMB,
    JUMD,
    parse_jumbf,
)
from c2pa_conformance.parser.manifest import (
    parse_manifest_store,
)

# ---------------------------------------------------------------------------
# Helpers: build realistic JUMBF manifest store bytes
# ---------------------------------------------------------------------------


def _build_jumd_box(type_uuid: bytes, label: str) -> bytes:
    """Build a JUMD description box."""
    toggles = 0x01  # label present
    payload = type_uuid + bytes([toggles]) + label.encode("utf-8") + b"\x00"
    size = 8 + len(payload)
    return struct.pack(">I", size) + JUMD + payload


def _build_cbor_box(data: dict) -> bytes:
    """Build a CBOR content box."""
    payload = cbor2.dumps(data)
    size = 8 + len(payload)
    return struct.pack(">I", size) + CBOR_BOX + payload


def _build_superbox(label: str, type_uuid: bytes, children_bytes: bytes) -> bytes:
    """Build a JUMBF superbox with JUMD + children."""
    jumd = _build_jumd_box(type_uuid, label)
    inner = jumd + children_bytes
    size = 8 + len(inner)
    return struct.pack(">I", size) + JUMB + inner


def _build_manifest_jumbf(
    manifest_label: str = "urn:c2pa:test-manifest",
    claim_data: dict | None = None,
    assertions: list[tuple[str, dict]] | None = None,
) -> bytes:
    """Build a complete JUMBF manifest store with one manifest.

    Returns raw JUMBF bytes suitable for embedding in any container.
    """
    # Default claim
    if claim_data is None:
        claim_data = {
            "claim_generator": "c2pa-conformance-suite/0.1.0",
            "claim_generator_info": [{"name": "c2pa-conformance-suite", "version": "0.1.0"}],
            "assertions": [],
            "signature": f"self#jumbf={manifest_label}/c2pa.signature",
        }

    # Default assertions: one c2pa.hash.data assertion
    if assertions is None:
        assertions = [
            (
                "c2pa.hash.data",
                {
                    "name": "jumbf manifest",
                    "hash": "sha256",
                    "exclusions": [{"start": 0, "length": 100}],
                },
            ),
        ]

    # Build assertion store
    assertion_boxes = b""
    assertion_refs = []
    for label, data in assertions:
        cbor_box = _build_cbor_box(data)
        assertion_box = _build_superbox(label, b"\x00" * 16, cbor_box)
        assertion_boxes += assertion_box
        assertion_refs.append({"url": f"self#jumbf={manifest_label}/c2pa.assertions/{label}"})

    claim_data["assertions"] = assertion_refs
    assertion_store = _build_superbox("c2pa.assertions", b"\x00" * 16, assertion_boxes)

    # Build claim
    claim_cbor = _build_cbor_box(claim_data)
    claim_box = _build_superbox("c2pa.claim", b"\x00" * 16, claim_cbor)

    # Build signature (stub - just a CBOR box with empty bytes)
    sig_cbor = _build_cbor_box({"sig": b"\x00" * 32})
    sig_box = _build_superbox("c2pa.signature", b"\x00" * 16, sig_cbor)

    # Build manifest superbox
    manifest_box = _build_superbox(
        manifest_label,
        b"\x00" * 16,
        claim_box + assertion_store + sig_box,
    )

    # Build manifest store superbox
    store_uuid = bytes.fromhex("63327061001100108000" + "00aa00389b71")
    store_box = _build_superbox("c2pa", store_uuid, manifest_box)

    return store_box


# ---------------------------------------------------------------------------
# JUMBF round-trip tests
# ---------------------------------------------------------------------------


class TestJUMBFRoundTrip:
    def test_parse_built_manifest_store(self) -> None:
        jumbf = _build_manifest_jumbf()
        boxes = parse_jumbf(jumbf)
        assert len(boxes) == 1
        store_box = boxes[0]
        assert store_box.is_superbox
        assert store_box.label == "c2pa"

    def test_store_contains_manifest(self) -> None:
        jumbf = _build_manifest_jumbf()
        boxes = parse_jumbf(jumbf)
        store_box = boxes[0]
        manifests = [
            c
            for c in store_box.children
            if c.is_superbox and c.box_type == JUMB and c.label != "c2pa"
        ]
        assert len(manifests) >= 1


# ---------------------------------------------------------------------------
# Manifest parser integration
# ---------------------------------------------------------------------------


class TestManifestParserIntegration:
    def test_parse_manifest_store(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        assert store.manifest_count >= 1

    def test_active_manifest_is_set(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        assert store.active_manifest is not None

    def test_claim_parsed(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        assert store.active_manifest is not None
        claim = store.active_manifest.claim
        assert claim is not None
        assert claim.claim_generator == "c2pa-conformance-suite/0.1.0"

    def test_assertions_parsed(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        assert store.active_manifest is not None
        assertions = store.active_manifest.assertions
        assert len(assertions) >= 1
        assert assertions[0].label == "c2pa.hash.data"
        assert assertions[0].is_hard_binding

    def test_signature_bytes_present(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        assert store.active_manifest is not None
        assert len(store.active_manifest.signature_bytes) > 0

    def test_multiple_assertions(self) -> None:
        jumbf = _build_manifest_jumbf(
            assertions=[
                ("c2pa.hash.data", {"hash": "sha256"}),
                ("c2pa.actions", {"actions": [{"action": "c2pa.created"}]}),
                ("c2pa.thumbnail.claim.jpeg", {"data": "thumbnail"}),
            ]
        )
        store = parse_manifest_store(jumbf)
        assert store.active_manifest is not None
        labels = [a.label for a in store.active_manifest.assertions]
        assert "c2pa.hash.data" in labels
        assert "c2pa.actions" in labels
        assert "c2pa.thumbnail.claim.jpeg" in labels


# ---------------------------------------------------------------------------
# Context builder integration
# ---------------------------------------------------------------------------


class TestContextBuilder:
    def test_build_context_structure(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        extraction = ExtractionResult(
            jumbf_bytes=jumbf,
            container_format="test",
            jumbf_offset=0,
            jumbf_length=len(jumbf),
        )
        ctx = _build_context(store, extraction)

        assert "manifest_store" in ctx
        assert "active_manifest" in ctx
        assert "claim" in ctx
        assert ctx["claim_generator"] == "c2pa-conformance-suite/0.1.0"

    def test_context_has_assertion_labels(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        extraction = ExtractionResult(
            jumbf_bytes=jumbf,
            container_format="test",
            jumbf_offset=0,
            jumbf_length=len(jumbf),
        )
        ctx = _build_context(store, extraction)
        assert "c2pa.hash.data" in ctx["assertion_labels"]
        assert ctx["assertion_count"] >= 1

    def test_context_has_hard_binding(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        extraction = ExtractionResult(
            jumbf_bytes=jumbf,
            container_format="test",
            jumbf_offset=0,
            jumbf_length=len(jumbf),
        )
        ctx = _build_context(store, extraction)
        assert "hard_binding" in ctx
        assert ctx["hard_binding"]["label"] == "c2pa.hash.data"

    def test_context_claim_data(self) -> None:
        jumbf = _build_manifest_jumbf()
        store = parse_manifest_store(jumbf)
        extraction = ExtractionResult(
            jumbf_bytes=jumbf,
            container_format="test",
            jumbf_offset=0,
            jumbf_length=len(jumbf),
        )
        ctx = _build_context(store, extraction)
        assert ctx["claim"]["claim_generator"] == "c2pa-conformance-suite/0.1.0"
        assert len(ctx["claim"]["claim_generator_info"]) == 1


# ---------------------------------------------------------------------------
# Full pipeline: container -> extract -> parse -> context
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_jpeg_pipeline(self, tmp_path) -> None:
        """Full pipeline: JPEG -> extract -> parse -> context."""
        jumbf = _build_manifest_jumbf()
        jpeg_data = _build_jpeg_with_jumbf(jumbf)

        p = tmp_path / "test.jpg"
        p.write_bytes(jpeg_data)

        extraction = detect_and_extract(p)
        assert extraction.container_format == "jpeg"

        store = parse_manifest_store(extraction.jumbf_bytes)
        assert store.manifest_count >= 1
        assert store.active_manifest is not None
        assert store.active_manifest.claim is not None

        ctx = _build_context(store, extraction)
        assert ctx["claim_generator"] == "c2pa-conformance-suite/0.1.0"

    def test_png_pipeline(self, tmp_path) -> None:
        """Full pipeline: PNG -> extract -> parse -> context."""
        jumbf = _build_manifest_jumbf()
        png_data = _build_png_with_jumbf(jumbf)

        p = tmp_path / "test.png"
        p.write_bytes(png_data)

        extraction = detect_and_extract(p)
        store = parse_manifest_store(extraction.jumbf_bytes)
        ctx = _build_context(store, extraction)
        assert ctx["container_format"] == "png"
        assert ctx["claim_generator"] == "c2pa-conformance-suite/0.1.0"

    def test_riff_pipeline(self, tmp_path) -> None:
        """Full pipeline: RIFF/WAV -> extract -> parse -> context."""
        jumbf = _build_manifest_jumbf()
        wav_data = _build_riff_with_jumbf(jumbf)

        p = tmp_path / "test.wav"
        p.write_bytes(wav_data)

        extraction = detect_and_extract(p)
        store = parse_manifest_store(extraction.jumbf_bytes)
        ctx = _build_context(store, extraction)
        assert ctx["container_format"] == "riff"
        assert store.active_manifest is not None

    def test_sidecar_pipeline(self, tmp_path) -> None:
        """Full pipeline: .c2pa sidecar -> parse -> context."""
        jumbf = _build_manifest_jumbf()

        p = tmp_path / "test.c2pa"
        p.write_bytes(jumbf)

        extraction = detect_and_extract(p)
        store = parse_manifest_store(extraction.jumbf_bytes)
        ctx = _build_context(store, extraction)
        assert ctx["container_format"] == "sidecar"
        assert ctx["claim_generator"] == "c2pa-conformance-suite/0.1.0"

    def test_text_pipeline(self, tmp_path) -> None:
        """Full pipeline: text/C2PATextManifestWrapper -> extract -> parse."""
        import base64

        jumbf = _build_manifest_jumbf()
        b64 = base64.b64encode(jumbf).decode("ascii")
        text = (
            f"Document content here.\n\n"
            f"---BEGIN C2PA MANIFEST---\n{b64}\n---END C2PA MANIFEST---\n"
        )

        p = tmp_path / "test.txt"
        p.write_bytes(text.encode("utf-8"))

        extraction = detect_and_extract(p)
        store = parse_manifest_store(extraction.jumbf_bytes)
        ctx = _build_context(store, extraction)
        assert ctx["container_format"] == "text"
        assert store.active_manifest is not None


# ---------------------------------------------------------------------------
# Container builders (reused from test_extractors, kept here for isolation)
# ---------------------------------------------------------------------------


def _build_jpeg_with_jumbf(jumbf: bytes) -> bytes:
    soi = b"\xff\xd8"
    inner = b"\x4a\x50" + struct.pack(">H", 1) + struct.pack(">I", len(jumbf)) + jumbf
    lp = len(inner) + 2
    segment = b"\xff\xeb" + struct.pack(">H", lp) + inner
    return soi + segment + b"\xff\xda\x00\x02\xff\xd9"


def _build_png_with_jumbf(jumbf: bytes) -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return length + chunk_type + data + crc

    ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    cabx = _chunk(b"caBX", jumbf)
    idat = _chunk(b"IDAT", zlib.compress(b"\x00\x00"))
    iend = _chunk(b"IEND", b"")
    return sig + ihdr + cabx + idat + iend


def _build_riff_with_jumbf(jumbf: bytes) -> bytes:
    fmt_data = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
    fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_data)) + fmt_data
    c2pa_chunk = b"C2PA" + struct.pack("<I", len(jumbf)) + jumbf
    if len(jumbf) % 2 != 0:
        c2pa_chunk += b"\x00"
    body = b"WAVE" + fmt_chunk + c2pa_chunk
    return b"RIFF" + struct.pack("<I", len(body)) + body
