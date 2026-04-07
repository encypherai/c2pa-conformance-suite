"""Tests for container format extractors.

Each test constructs a minimal but valid container format with embedded
JUMBF data, then verifies the extractor finds and returns the correct bytes.
"""

from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest

from c2pa_conformance.extractors.base import (
    ExtractionError,
    detect_and_extract,
)
from c2pa_conformance.extractors.bmff import C2PA_MANIFEST_UUID, BMFFExtractor
from c2pa_conformance.extractors.gif import GIFExtractor
from c2pa_conformance.extractors.jpeg import JPEGExtractor
from c2pa_conformance.extractors.jxl import JXLExtractor
from c2pa_conformance.extractors.pdf import PDFExtractor
from c2pa_conformance.extractors.png import PNGExtractor
from c2pa_conformance.extractors.riff import RIFFExtractor
from c2pa_conformance.extractors.svg import SVGExtractor
from c2pa_conformance.extractors.text import TextExtractor
from c2pa_conformance.extractors.tiff import TIFFExtractor

# A minimal JUMBF superbox: 16 bytes (size=16, type="jumb", jumd desc, payload)
# For testing we just need recognizable bytes the extractor should return.
SAMPLE_JUMBF = b"\x00\x00\x00\x10jumbTESTDATA"


# ---------------------------------------------------------------------------
# Helper: build minimal container formats with embedded JUMBF
# ---------------------------------------------------------------------------


def _build_jpeg_with_jumbf(jumbf: bytes, multi_segment: bool = False) -> bytes:
    """Build a minimal JPEG with APP11 JUMBF segment(s).

    Header per ISO 19566-5: CI(2) + En(2) + Z(4) = 8 bytes for all packets.
    """
    soi = b"\xff\xd8"
    en = 1  # box instance number

    if not multi_segment:
        # Single segment: CI(2) + En(2) + Z=1(4) + JUMBF data
        inner = (
            b"\x4a\x50"
            + struct.pack(">H", en)
            + struct.pack(">I", 1)  # Z = packet sequence 1
            + jumbf
        )
        lp = len(inner) + 2  # +2 for Lp field itself
        segment = b"\xff\xeb" + struct.pack(">H", lp) + inner
        # SOS + minimal scan data + EOI
        return soi + segment + b"\xff\xda\x00\x02\xff\xd9"
    else:
        # Split JUMBF across two segments
        mid = len(jumbf) // 2
        part1, part2 = jumbf[:mid], jumbf[mid:]

        # Segment 1: CI + En + Z=1 + first half of JUMBF
        inner1 = (
            b"\x4a\x50"
            + struct.pack(">H", en)
            + struct.pack(">I", 1)  # Z = 1
            + part1
        )
        lp1 = len(inner1) + 2
        seg1 = b"\xff\xeb" + struct.pack(">H", lp1) + inner1

        # Segment 2: CI + En + Z=2 + second half
        inner2 = (
            b"\x4a\x50"
            + struct.pack(">H", en)
            + struct.pack(">I", 2)  # Z = 2
            + part2
        )
        lp2 = len(inner2) + 2
        seg2 = b"\xff\xeb" + struct.pack(">H", lp2) + inner2

        return soi + seg1 + seg2 + b"\xff\xda\x00\x02\xff\xd9"


def _build_png_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal PNG with caBX chunk."""
    import zlib

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


def _build_bmff_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal BMFF with ftyp + C2PA uuid box (FullBox)."""
    # ftyp box
    ftyp_payload = b"isom\x00\x00\x02\x00isom"
    ftyp_size = 8 + len(ftyp_payload)
    ftyp = struct.pack(">I", ftyp_size) + b"ftyp" + ftyp_payload

    # C2PA uuid box: header(8) + uuid(16) + version/flags(4) + purpose + offset(8) + jumbf
    version_flags = b"\x00\x00\x00\x00"  # version=0, flags=0
    purpose = b"manifest\x00"
    merkle_offset = b"\x00" * 8
    uuid_payload = C2PA_MANIFEST_UUID + version_flags + purpose + merkle_offset + jumbf
    uuid_size = 8 + len(uuid_payload)
    uuid_box = struct.pack(">I", uuid_size) + b"uuid" + uuid_payload

    return ftyp + uuid_box


def _build_riff_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal RIFF/WAV with C2PA chunk."""
    fmt_data = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
    fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_data)) + fmt_data

    c2pa_chunk = b"C2PA" + struct.pack("<I", len(jumbf)) + jumbf
    # Pad to even if needed
    if len(jumbf) % 2 != 0:
        c2pa_chunk += b"\x00"

    body = b"WAVE" + fmt_chunk + c2pa_chunk
    riff_size = len(body)
    return b"RIFF" + struct.pack("<I", riff_size) + body


def _build_tiff_with_jumbf(jumbf: bytes, big_endian: bool = False) -> bytes:
    """Build a minimal TIFF with C2PA tag."""
    if big_endian:
        bom = b"MM"
        e = ">"
    else:
        bom = b"II"
        e = "<"

    # Header: BOM(2) + magic(2) + IFD offset(4)
    ifd_offset = 8
    header = bom + struct.pack(f"{e}H", 42) + struct.pack(f"{e}I", ifd_offset)

    # IFD: count(2) + entries(12 each) + next_ifd(4)
    # We'll put one entry: the C2PA tag
    entry_count = 1
    # Tag=0xCD41, Type=7 (UNDEFINED), Count=len(jumbf), Value=offset
    data_offset = ifd_offset + 2 + (12 * entry_count) + 4  # after IFD
    entry = (
        struct.pack(f"{e}H", 0xCD41)
        + struct.pack(f"{e}H", 7)  # UNDEFINED type
        + struct.pack(f"{e}I", len(jumbf))
        + struct.pack(f"{e}I", data_offset)
    )

    ifd = struct.pack(f"{e}H", entry_count) + entry + struct.pack(f"{e}I", 0)

    return header + ifd + jumbf


def _build_gif_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal GIF89a with C2PA Application Extension."""
    header = b"GIF89a"
    # Logical Screen Descriptor: width(2) + height(2) + packed(1) + bg(1) + aspect(1)
    lsd = struct.pack("<HH", 1, 1) + b"\x00\x00\x00"

    # Application Extension: 0x21 0xFF + block_size(11) + app_id(8) + auth(3) + sub-blocks
    app_ext = b"\x21\xff"
    app_ext += b"\x0b"  # block size = 11
    app_ext += b"C2PA\x00\x00\x00\x00"  # app identifier (8 bytes)
    app_ext += b"\x00\x00\x00"  # auth code (3 bytes)

    # Write JUMBF as sub-blocks (max 255 bytes each)
    pos = 0
    while pos < len(jumbf):
        chunk_size = min(255, len(jumbf) - pos)
        app_ext += bytes([chunk_size]) + jumbf[pos : pos + chunk_size]
        pos += chunk_size
    app_ext += b"\x00"  # sub-block terminator

    trailer = b"\x3b"  # GIF trailer

    return header + lsd + app_ext + trailer


def _build_svg_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal SVG with C2PA comment."""
    b64 = base64.b64encode(jumbf).decode("ascii")
    svg = (
        f'<?xml version="1.0"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">\n'
        f'  <rect width="1" height="1"/>\n'
        f"</svg>\n"
        f'<!-- c2pa manifest="{b64}" -->\n'
    )
    return svg.encode("utf-8")


def _build_text_with_jumbf(jumbf: bytes) -> bytes:
    """Build a text file with C2PATextManifestWrapper."""
    b64 = base64.b64encode(jumbf).decode("ascii")
    text = (
        f"This is the content of the document.\n"
        f"\n"
        f"---BEGIN C2PA MANIFEST---\n"
        f"{b64}\n"
        f"---END C2PA MANIFEST---\n"
    )
    return text.encode("utf-8")


def _build_jxl_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal JPEG XL container with JUMBF data.

    The JUMBF bytes are already a jumb superbox, so they appear directly
    as a top-level box in the JXL ISOBMFF container.
    """
    sig = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"
    return sig + jumbf


def _build_pdf_with_jumbf(jumbf: bytes) -> bytes:
    """Build a minimal PDF with JUMBF in a stream object."""
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Length " + str(len(jumbf)).encode() + b" /Subtype /C2PA >>\n"
        b"stream\n" + jumbf + b"\nendstream\n"
        b"endobj\n"
        b"%%EOF\n"
    )
    return pdf


# ---------------------------------------------------------------------------
# JPEG tests
# ---------------------------------------------------------------------------


class TestJPEGExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert JPEGExtractor.can_handle(b"\xff\xd8", ".jpg")
        assert JPEGExtractor.can_handle(b"\xff\xd8", ".jpeg")
        assert not JPEGExtractor.can_handle(b"\x89PNG\r\n\x1a\n", ".png")

    def test_can_handle_by_magic(self) -> None:
        assert JPEGExtractor.can_handle(b"\xff\xd8\xff", ".bin")
        assert not JPEGExtractor.can_handle(b"\x89PNG", ".bin")

    def test_extract_single_segment(self) -> None:
        data = _build_jpeg_with_jumbf(SAMPLE_JUMBF)
        result = JPEGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "jpeg"

    def test_extract_multi_segment(self) -> None:
        data = _build_jpeg_with_jumbf(SAMPLE_JUMBF, multi_segment=True)
        result = JPEGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "jpeg"

    def test_extract_large_payload(self) -> None:
        large_jumbf = b"\x00" * 65000 + SAMPLE_JUMBF
        data = _build_jpeg_with_jumbf(large_jumbf)
        result = JPEGExtractor.extract(data)
        assert result.jumbf_bytes == large_jumbf

    def test_no_jumbf_raises(self) -> None:
        # JPEG with no APP11 segments
        data = b"\xff\xd8\xff\xda\x00\x02\xff\xd9"
        with pytest.raises(ExtractionError, match="No C2PA APP11"):
            JPEGExtractor.extract(data)

    def test_not_jpeg_raises(self) -> None:
        with pytest.raises(ExtractionError, match="Not a valid JPEG"):
            JPEGExtractor.extract(b"\x89PNG")


# ---------------------------------------------------------------------------
# PNG tests
# ---------------------------------------------------------------------------


class TestPNGExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert PNGExtractor.can_handle(b"\x89PNG\r\n\x1a\n", ".png")

    def test_can_handle_by_magic(self) -> None:
        assert PNGExtractor.can_handle(b"\x89PNG\r\n\x1a\n\x00", ".bin")
        assert not PNGExtractor.can_handle(b"\xff\xd8", ".bin")

    def test_extract_cabx_chunk(self) -> None:
        data = _build_png_with_jumbf(SAMPLE_JUMBF)
        result = PNGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "png"

    def test_no_cabx_raises(self) -> None:
        import zlib

        sig = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
        iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
        iend = struct.pack(">I", 0) + b"IEND" + iend_crc
        data = sig + ihdr + iend

        with pytest.raises(ExtractionError, match="No C2PA caBX"):
            PNGExtractor.extract(data)


# ---------------------------------------------------------------------------
# BMFF tests
# ---------------------------------------------------------------------------


class TestBMFFExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert BMFFExtractor.can_handle(b"\x00\x00\x00\x00", ".mp4")
        assert BMFFExtractor.can_handle(b"\x00\x00\x00\x00", ".heif")
        assert BMFFExtractor.can_handle(b"\x00\x00\x00\x00", ".avif")

    def test_can_handle_by_ftyp(self) -> None:
        data = b"\x00\x00\x00\x14ftypisom\x00\x00\x02\x00"
        assert BMFFExtractor.can_handle(data, ".bin")

    def test_extract_uuid_box(self) -> None:
        data = _build_bmff_with_jumbf(SAMPLE_JUMBF)
        result = BMFFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "bmff"

    def test_no_c2pa_uuid_raises(self) -> None:
        # BMFF with ftyp but no C2PA uuid box
        ftyp = struct.pack(">I", 20) + b"ftypisom\x00\x00\x02\x00"
        with pytest.raises(ExtractionError, match="No C2PA uuid box"):
            BMFFExtractor.extract(ftyp)


# ---------------------------------------------------------------------------
# RIFF tests
# ---------------------------------------------------------------------------


class TestRIFFExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert RIFFExtractor.can_handle(b"RIFF", ".wav")
        assert RIFFExtractor.can_handle(b"RIFF", ".webp")

    def test_can_handle_by_magic(self) -> None:
        assert RIFFExtractor.can_handle(b"RIFF\x00\x00\x00\x00WAVE", ".bin")
        assert not RIFFExtractor.can_handle(b"\x89PNG", ".bin")

    def test_extract_c2pa_chunk(self) -> None:
        data = _build_riff_with_jumbf(SAMPLE_JUMBF)
        result = RIFFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "riff"

    def test_no_c2pa_chunk_raises(self) -> None:
        # RIFF with only fmt chunk, no C2PA
        fmt_data = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
        fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_data)) + fmt_data
        body = b"WAVE" + fmt_chunk
        data = b"RIFF" + struct.pack("<I", len(body)) + body

        with pytest.raises(ExtractionError, match="No C2PA chunk"):
            RIFFExtractor.extract(data)


# ---------------------------------------------------------------------------
# TIFF tests
# ---------------------------------------------------------------------------


class TestTIFFExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert TIFFExtractor.can_handle(b"II", ".tiff")
        assert TIFFExtractor.can_handle(b"MM", ".tif")

    def test_can_handle_by_magic_le(self) -> None:
        data = b"II\x2a\x00\x00\x00\x00\x00"
        assert TIFFExtractor.can_handle(data, ".bin")

    def test_can_handle_by_magic_be(self) -> None:
        data = b"MM\x00\x2a\x00\x00\x00\x00"
        assert TIFFExtractor.can_handle(data, ".bin")

    def test_extract_le(self) -> None:
        data = _build_tiff_with_jumbf(SAMPLE_JUMBF, big_endian=False)
        result = TIFFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "tiff"

    def test_extract_be(self) -> None:
        data = _build_tiff_with_jumbf(SAMPLE_JUMBF, big_endian=True)
        result = TIFFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "tiff"

    def test_no_c2pa_tag_raises(self) -> None:
        # TIFF with no IFD entries
        header = b"II\x2a\x00\x08\x00\x00\x00"
        ifd = struct.pack("<H", 0) + struct.pack("<I", 0)
        with pytest.raises(ExtractionError, match="No C2PA tag"):
            TIFFExtractor.extract(header + ifd)


# ---------------------------------------------------------------------------
# GIF tests
# ---------------------------------------------------------------------------


class TestGIFExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert GIFExtractor.can_handle(b"GIF89a", ".gif")

    def test_can_handle_by_magic(self) -> None:
        assert GIFExtractor.can_handle(b"GIF89a\x00\x00", ".bin")
        assert GIFExtractor.can_handle(b"GIF87a\x00\x00", ".bin")
        assert not GIFExtractor.can_handle(b"\xff\xd8", ".bin")

    def test_extract_app_extension(self) -> None:
        data = _build_gif_with_jumbf(SAMPLE_JUMBF)
        result = GIFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "gif"

    def test_large_payload_multi_subblock(self) -> None:
        large_jumbf = bytes(range(256)) * 4  # 1024 bytes, needs multiple sub-blocks
        data = _build_gif_with_jumbf(large_jumbf)
        result = GIFExtractor.extract(data)
        assert result.jumbf_bytes == large_jumbf

    def test_no_c2pa_extension_raises(self) -> None:
        # Minimal GIF with no extensions
        data = b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00" + b"\x3b"
        with pytest.raises(ExtractionError, match="No C2PA Application Extension"):
            GIFExtractor.extract(data)


# ---------------------------------------------------------------------------
# SVG tests
# ---------------------------------------------------------------------------


class TestSVGExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert SVGExtractor.can_handle(b"<svg>", ".svg")

    def test_can_handle_by_content(self) -> None:
        assert SVGExtractor.can_handle(b"<?xml version='1.0'?><svg c2pa='test'>", ".xml")

    def test_extract_comment(self) -> None:
        data = _build_svg_with_jumbf(SAMPLE_JUMBF)
        result = SVGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "svg"

    def test_extract_element(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        data = f"<svg><c2pa:manifest>{b64}</c2pa:manifest></svg>".encode()
        result = SVGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_no_manifest_raises(self) -> None:
        data = b'<?xml version="1.0"?><svg></svg>'
        with pytest.raises(ExtractionError, match="No C2PA manifest"):
            SVGExtractor.extract(data)


# ---------------------------------------------------------------------------
# Text tests
# ---------------------------------------------------------------------------


class TestTextExtractor:
    def test_can_handle(self) -> None:
        data = b"Hello\n---BEGIN C2PA MANIFEST---\nAAA\n---END C2PA MANIFEST---\n"
        assert TextExtractor.can_handle(data, ".txt")

    def test_extract_wrapper(self) -> None:
        data = _build_text_with_jumbf(SAMPLE_JUMBF)
        result = TextExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "text"

    def test_no_wrapper_raises(self) -> None:
        with pytest.raises(ExtractionError, match="No C2PATextManifestWrapper"):
            TextExtractor.extract(b"Just plain text with no manifest.")


# ---------------------------------------------------------------------------
# JPEG XL tests
# ---------------------------------------------------------------------------


class TestJXLExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert JXLExtractor.can_handle(b"\x00", ".jxl")

    def test_can_handle_by_magic(self) -> None:
        sig = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"
        assert JXLExtractor.can_handle(sig + b"\x00\x00", ".bin")

    def test_extract_jumb_box(self) -> None:
        data = _build_jxl_with_jumbf(SAMPLE_JUMBF)
        result = JXLExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "jxl"

    def test_codestream_only_raises(self) -> None:
        with pytest.raises(ExtractionError, match="codestream-only"):
            JXLExtractor.extract(b"\xff\x0a" + b"\x00" * 20)

    def test_no_jumb_raises(self) -> None:
        sig = b"\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a"
        # ftyp box but no jumb
        ftyp = struct.pack(">I", 20) + b"ftypjxl \x00\x00\x00\x00"
        with pytest.raises(ExtractionError, match="No JUMBF box"):
            JXLExtractor.extract(sig + ftyp)


# ---------------------------------------------------------------------------
# PDF tests
# ---------------------------------------------------------------------------


class TestPDFExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert PDFExtractor.can_handle(b"%PDF-1.7", ".pdf")

    def test_can_handle_by_magic(self) -> None:
        assert PDFExtractor.can_handle(b"%PDF-2.0\nrest", ".bin")
        assert not PDFExtractor.can_handle(b"\x89PNG", ".bin")

    def test_extract_from_stream(self) -> None:
        data = _build_pdf_with_jumbf(SAMPLE_JUMBF)
        result = PDFExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "pdf"

    def test_no_jumbf_raises(self) -> None:
        data = b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\n%%EOF\n"
        with pytest.raises(ExtractionError, match="No C2PA JUMBF"):
            PDFExtractor.extract(data)


# ---------------------------------------------------------------------------
# Sidecar (.c2pa) tests
# ---------------------------------------------------------------------------


class TestSidecarExtractor:
    def test_detect_sidecar(self, tmp_path: Path) -> None:
        sidecar = tmp_path / "test.c2pa"
        sidecar.write_bytes(SAMPLE_JUMBF)
        result = detect_and_extract(sidecar)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "sidecar"

    def test_sidecar_offset_and_length(self, tmp_path: Path) -> None:
        sidecar = tmp_path / "test.c2pa"
        sidecar.write_bytes(SAMPLE_JUMBF)
        result = detect_and_extract(sidecar)
        assert result.jumbf_offset == 0
        assert result.jumbf_length == len(SAMPLE_JUMBF)


# ---------------------------------------------------------------------------
# Auto-detection tests
# ---------------------------------------------------------------------------


class TestAutoDetect:
    def test_detect_jpeg(self, tmp_path: Path) -> None:
        p = tmp_path / "test.jpg"
        p.write_bytes(_build_jpeg_with_jumbf(SAMPLE_JUMBF))
        result = detect_and_extract(p)
        assert result.container_format == "jpeg"
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_detect_png(self, tmp_path: Path) -> None:
        p = tmp_path / "test.png"
        p.write_bytes(_build_png_with_jumbf(SAMPLE_JUMBF))
        result = detect_and_extract(p)
        assert result.container_format == "png"
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_detect_wav(self, tmp_path: Path) -> None:
        p = tmp_path / "test.wav"
        p.write_bytes(_build_riff_with_jumbf(SAMPLE_JUMBF))
        result = detect_and_extract(p)
        assert result.container_format == "riff"
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_unknown_format_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "test.xyz"
        p.write_bytes(b"\x00\x01\x02\x03")
        with pytest.raises(ExtractionError, match="No extractor found"):
            detect_and_extract(p)
