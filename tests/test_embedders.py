"""Tests for container format embedders.

Each test constructs minimal JUMBF bytes, embeds them into a container,
then extracts with the corresponding extractor to verify a round-trip.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from c2pa_conformance.builder.jumbf_builder import (
    build_cbor_box,
    build_superbox,
)
from c2pa_conformance.embedders import embed_jpeg, embed_png, embed_sidecar
from c2pa_conformance.extractors.jpeg import JPEGExtractor
from c2pa_conformance.extractors.png import PNGExtractor

# ---------------------------------------------------------------------------
# JUMBF test data helpers
# ---------------------------------------------------------------------------

# A minimal type UUID (16 bytes)
_TEST_UUID = b"\x63\x32\x70\x61" + b"\x00" * 12  # "c2pa" + padding


def _make_jumbf(payload: bytes = b"\x00\x01\x02\x03") -> bytes:
    """Build a small JUMBF superbox containing a CBOR box."""
    cbor_box = build_cbor_box(payload)
    return build_superbox(_TEST_UUID, "test", [cbor_box])


# ---------------------------------------------------------------------------
# Minimal container construction helpers
# ---------------------------------------------------------------------------


def _build_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build a PNG chunk: Length + Type + Data + CRC."""
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def _minimal_jpeg() -> bytes:
    """Build a minimal valid JPEG: SOI + APP0 + SOS + EOI."""
    soi = b"\xff\xd8"
    # APP0 (JFIF): marker + Lp(16) + "JFIF\0" + version + density fields
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_data)) + app0_data
    # Minimal SOS + EOI (no actual image data)
    sos = b"\xff\xda\x00\x02"
    eoi = b"\xff\xd9"
    return soi + app0 + sos + eoi


def _minimal_jpeg_with_app1() -> bytes:
    """Build a minimal JPEG: SOI + APP0 + APP1 + SOS + EOI."""
    soi = b"\xff\xd8"
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_data)) + app0_data
    app1_data = b"Exif\x00\x00" + b"\x00" * 10
    app1 = b"\xff\xe1" + struct.pack(">H", 2 + len(app1_data)) + app1_data
    sos = b"\xff\xda\x00\x02"
    eoi = b"\xff\xd9"
    return soi + app0 + app1 + sos + eoi


def _minimal_jpeg_no_app() -> bytes:
    """Build a minimal JPEG: SOI + SOS + EOI (no APP markers)."""
    soi = b"\xff\xd8"
    sos = b"\xff\xda\x00\x02"
    eoi = b"\xff\xd9"
    return soi + sos + eoi


def _minimal_png() -> bytes:
    """Build a minimal valid PNG: signature + IHDR + IDAT + IEND."""
    sig = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1, 8-bit RGB
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _build_png_chunk(b"IHDR", ihdr_data)
    # IDAT: compressed 1x1 RGB pixel (filter byte 0 + RGB)
    raw_data = b"\x00\xff\x00\x00"  # filter=None, R=255, G=0, B=0
    compressed = zlib.compress(raw_data)
    idat = _build_png_chunk(b"IDAT", compressed)
    # IEND
    iend = _build_png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


# ---------------------------------------------------------------------------
# JPEG embedder tests
# ---------------------------------------------------------------------------


class TestJPEGEmbedder:
    def test_round_trip(self) -> None:
        """Embed JUMBF into JPEG, extract it back, verify bytes match."""
        jumbf = _make_jumbf()
        container = _minimal_jpeg()
        result_bytes = embed_jpeg(container, jumbf)
        extracted = JPEGExtractor.extract(result_bytes)
        assert extracted.jumbf_bytes == jumbf

    def test_multi_segment(self) -> None:
        """JUMBF > 65525 bytes must split into multiple APP11 segments."""
        # Build a large payload that will require at least 2 segments.
        # MAX_SEGMENT_PAYLOAD = 65525, so > 65525 bytes triggers split.
        large_payload = bytes(range(256)) * 260  # 66560 bytes
        jumbf = _make_jumbf(large_payload)

        container = _minimal_jpeg()
        result_bytes = embed_jpeg(container, jumbf)

        # Count APP11 segments in result
        app11_count = 0
        pos = 2  # after SOI
        while pos < len(result_bytes) - 1:
            if result_bytes[pos : pos + 2] == b"\xff\xeb":
                app11_count += 1
                lp = struct.unpack_from(">H", result_bytes, pos + 2)[0]
                pos += 2 + lp
            elif result_bytes[pos : pos + 2] == b"\xff\xda":
                break
            elif result_bytes[pos] == 0xFF:
                lp = struct.unpack_from(">H", result_bytes, pos + 2)[0]
                pos += 2 + lp
            else:
                pos += 1

        assert app11_count >= 2, f"Expected multiple APP11 segments, got {app11_count}"

        # Also verify round-trip integrity
        extracted = JPEGExtractor.extract(result_bytes)
        assert extracted.jumbf_bytes == jumbf

    def test_insertion_position_after_app0(self) -> None:
        """APP11 segments must be inserted after APP0, before SOS."""
        jumbf = _make_jumbf()
        container = _minimal_jpeg()
        result_bytes = embed_jpeg(container, jumbf)

        # SOI is at 0; APP0 marker at 2
        assert result_bytes[0:2] == b"\xff\xd8"  # SOI
        assert result_bytes[2:4] == b"\xff\xe0"  # APP0 still in place

        # After APP0, the next marker should be APP11 (0xFF 0xEB)
        app0_lp = struct.unpack_from(">H", result_bytes, 4)[0]
        after_app0 = 2 + 2 + app0_lp
        assert result_bytes[after_app0 : after_app0 + 2] == b"\xff\xeb"

    def test_insertion_position_after_app0_and_app1(self) -> None:
        """APP11 segments must be inserted after both APP0 and APP1."""
        jumbf = _make_jumbf()
        container = _minimal_jpeg_with_app1()
        result_bytes = embed_jpeg(container, jumbf)

        # Walk past APP0
        app0_lp = struct.unpack_from(">H", result_bytes, 4)[0]
        pos_after_app0 = 2 + 2 + app0_lp

        # APP1 should still be present
        assert result_bytes[pos_after_app0 : pos_after_app0 + 2] == b"\xff\xe1"

        # Walk past APP1
        app1_lp = struct.unpack_from(">H", result_bytes, pos_after_app0 + 2)[0]
        pos_after_app1 = pos_after_app0 + 2 + app1_lp

        # APP11 should follow immediately
        assert result_bytes[pos_after_app1 : pos_after_app1 + 2] == b"\xff\xeb"

    def test_insertion_position_no_app_markers(self) -> None:
        """APP11 should be inserted right after SOI when no APP markers exist."""
        jumbf = _make_jumbf()
        container = _minimal_jpeg_no_app()
        result_bytes = embed_jpeg(container, jumbf)

        # SOI at 0, APP11 immediately after SOI
        assert result_bytes[0:2] == b"\xff\xd8"
        assert result_bytes[2:4] == b"\xff\xeb"

    def test_invalid_container_raises(self) -> None:
        """Non-JPEG bytes must raise ValueError."""
        with pytest.raises(ValueError, match="Not a valid JPEG"):
            embed_jpeg(b"\x89PNG\r\n\x1a\n", b"\x00\x01\x02")

    def test_invalid_container_too_short_raises(self) -> None:
        """Bytes shorter than 2 must raise ValueError."""
        with pytest.raises(ValueError, match="Not a valid JPEG"):
            embed_jpeg(b"\xff", b"\x00")

    def test_box_instance_propagated(self) -> None:
        """The box_instance (En field) must appear in each APP11 segment."""
        jumbf = _make_jumbf()
        container = _minimal_jpeg()
        result_bytes = embed_jpeg(container, jumbf, box_instance=7)

        # Find first APP11 segment and check En field
        pos = 2  # after SOI
        found = False
        while pos < len(result_bytes) - 1:
            if result_bytes[pos : pos + 2] == b"\xff\xeb":
                # Lp at pos+2, CI at pos+4, En at pos+6
                en = struct.unpack_from(">H", result_bytes, pos + 6)[0]
                assert en == 7
                found = True
                break
            pos += 1
        assert found, "No APP11 segment found in output"


# ---------------------------------------------------------------------------
# PNG embedder tests
# ---------------------------------------------------------------------------


class TestPNGEmbedder:
    def test_round_trip(self) -> None:
        """Embed JUMBF into PNG, extract it back, verify bytes match."""
        jumbf = _make_jumbf()
        container = _minimal_png()
        result_bytes = embed_png(container, jumbf)
        extracted = PNGExtractor.extract(result_bytes)
        assert extracted.jumbf_bytes == jumbf

    def test_crc_validity(self) -> None:
        """The caBX chunk CRC must be correct."""
        jumbf = _make_jumbf()
        container = _minimal_png()
        result_bytes = embed_png(container, jumbf)

        # Find caBX chunk and verify its CRC
        pos = 8  # skip PNG signature
        found = False
        while pos + 12 <= len(result_bytes):
            chunk_len = struct.unpack_from(">I", result_bytes, pos)[0]
            chunk_type = result_bytes[pos + 4 : pos + 8]
            chunk_data = result_bytes[pos + 8 : pos + 8 + chunk_len]
            chunk_crc_stored = struct.unpack_from(">I", result_bytes, pos + 8 + chunk_len)[0]

            if chunk_type == b"caBX":
                expected_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                assert chunk_crc_stored == expected_crc, (
                    f"caBX CRC mismatch: stored={chunk_crc_stored:#010x}, "
                    f"expected={expected_crc:#010x}"
                )
                assert chunk_data == jumbf
                found = True
                break

            pos += 12 + chunk_len

        assert found, "No caBX chunk found in output"

    def test_insertion_before_idat(self) -> None:
        """caBX chunk must appear before the first IDAT chunk."""
        jumbf = _make_jumbf()
        container = _minimal_png()
        result_bytes = embed_png(container, jumbf)

        # Collect chunk types in order
        chunk_types = []
        pos = 8  # skip signature
        while pos + 8 <= len(result_bytes):
            chunk_len = struct.unpack_from(">I", result_bytes, pos)[0]
            chunk_type = result_bytes[pos + 4 : pos + 8]
            chunk_types.append(chunk_type)
            if chunk_type == b"IEND":
                break
            pos += 12 + chunk_len

        cabx_idx = chunk_types.index(b"caBX")
        idat_idx = chunk_types.index(b"IDAT")
        assert cabx_idx < idat_idx, (
            f"caBX (index {cabx_idx}) must come before IDAT (index {idat_idx})"
        )

    def test_invalid_container_raises(self) -> None:
        """Non-PNG bytes must raise ValueError."""
        with pytest.raises(ValueError, match="Not a valid PNG"):
            embed_png(b"\xff\xd8\xff\xe0", b"\x00\x01\x02")

    def test_invalid_container_too_short_raises(self) -> None:
        """Bytes shorter than 8 must raise ValueError."""
        with pytest.raises(ValueError, match="Not a valid PNG"):
            embed_png(b"\x89PNG", b"\x00")

    def test_large_jumbf_round_trip(self) -> None:
        """Large JUMBF payload embeds and extracts correctly."""
        large_payload = bytes(range(256)) * 100  # 25600 bytes
        jumbf = _make_jumbf(large_payload)
        container = _minimal_png()
        result_bytes = embed_png(container, jumbf)
        extracted = PNGExtractor.extract(result_bytes)
        assert extracted.jumbf_bytes == jumbf


# ---------------------------------------------------------------------------
# Sidecar embedder tests
# ---------------------------------------------------------------------------


class TestSidecarEmbedder:
    def test_round_trip_identity(self) -> None:
        """embed_sidecar must return the input bytes unchanged."""
        jumbf = _make_jumbf()
        result = embed_sidecar(jumbf)
        assert result == jumbf

    def test_empty_bytes(self) -> None:
        """embed_sidecar must handle empty bytes."""
        assert embed_sidecar(b"") == b""

    def test_arbitrary_bytes(self) -> None:
        """embed_sidecar is a pass-through for any bytes."""
        data = bytes(range(256))
        assert embed_sidecar(data) is data
