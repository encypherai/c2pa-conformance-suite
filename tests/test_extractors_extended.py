"""Tests for the new container format extractors (ID3, OGG, Font, HTML, ZIP)
and the updated Text (v2.4 VS encoding) and SVG (structured text) extractors.
"""

from __future__ import annotations

import base64
import struct
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from c2pa_conformance.extractors.base import ExtractionError, detect_and_extract
from c2pa_conformance.extractors.font import FontExtractor
from c2pa_conformance.extractors.html import HTMLExtractor
from c2pa_conformance.extractors.id3 import ID3Extractor
from c2pa_conformance.extractors.ogg import OGGExtractor
from c2pa_conformance.extractors.svg import SVGExtractor
from c2pa_conformance.extractors.text import TextExtractor
from c2pa_conformance.extractors.zip import ZIPExtractor

SAMPLE_JUMBF = b"\x00\x00\x00\x10jumbTESTDATA"


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------


def _build_id3_with_jumbf(jumbf: bytes, version: int = 4) -> bytes:
    """Build minimal MP3 with ID3v2 tag containing a C2PA GEOB frame."""
    # GEOB payload: encoding(1) + MIME(null-term) + filename(null-term) +
    #               description(null-term) + data
    geob_payload = (
        b"\x00"  # encoding: ISO-8859-1
        + b"application/c2pa\x00"  # MIME type
        + b"c2pa.jumbf\x00"  # filename
        + b"C2PA Manifest Store\x00"  # description
        + jumbf  # encapsulated object
    )

    if version >= 4:
        # Synchsafe size for v2.4
        size = len(geob_payload)
        frame_size = bytes(
            [
                (size >> 21) & 0x7F,
                (size >> 14) & 0x7F,
                (size >> 7) & 0x7F,
                size & 0x7F,
            ]
        )
    else:
        # Big-endian size for v2.3
        frame_size = struct.pack(">I", len(geob_payload))

    frame = b"GEOB" + frame_size + b"\x00\x00" + geob_payload

    # ID3v2 header
    tag_size = len(frame)
    synchsafe_tag = bytes(
        [
            (tag_size >> 21) & 0x7F,
            (tag_size >> 14) & 0x7F,
            (tag_size >> 7) & 0x7F,
            tag_size & 0x7F,
        ]
    )
    header = b"ID3" + bytes([version, 0]) + b"\x00" + synchsafe_tag

    # Append fake MP3 frame sync to make it look like an audio file
    return header + frame + b"\xff\xfb\x90\x00"


def _build_ogg_with_jumbf(jumbf: bytes) -> bytes:
    """Build minimal OGG with a C2PA logical bitstream."""
    # Build a single OGG page for the C2PA stream
    c2pa_data = b"\x00c2pa" + jumbf  # 5-byte magic + JUMBF

    # OGG page header
    capture = b"OggS"
    version = b"\x00"
    header_type = b"\x06"  # BOS + EOS (single page stream)
    granule = b"\x00" * 8
    serial = struct.pack("<I", 42)  # arbitrary serial number
    page_seq = struct.pack("<I", 0)
    checksum = b"\x00" * 4  # we skip CRC for test purposes

    # Segment table: one segment covering all data
    if len(c2pa_data) <= 255:
        num_segments = b"\x01"
        segment_table = bytes([len(c2pa_data)])
    else:
        # Split into 255-byte segments
        n_full = len(c2pa_data) // 255
        remainder = len(c2pa_data) % 255
        segments = [255] * n_full
        if remainder > 0:
            segments.append(remainder)
        num_segments = bytes([len(segments)])
        segment_table = bytes(segments)

    page = (
        capture
        + version
        + header_type
        + granule
        + serial
        + page_seq
        + checksum
        + num_segments
        + segment_table
        + c2pa_data
    )

    return page


def _build_flac_with_jumbf(jumbf: bytes) -> bytes:
    """Build minimal FLAC with a C2PA APPLICATION metadata block."""
    # STREAMINFO block (type=0, is_last=0)
    streaminfo = b"\x00" * 34
    si_header = bytes([0x00]) + len(streaminfo).to_bytes(3, "big")

    # APPLICATION block (type=2, is_last=1) with "c2pa" app ID
    app_data = b"c2pa" + jumbf
    app_header = bytes([(1 << 7) | 2]) + len(app_data).to_bytes(3, "big")

    return b"fLaC" + si_header + streaminfo + app_header + app_data


def _build_font_with_jumbf(jumbf: bytes) -> bytes:
    """Build minimal TTF with a C2PA table containing raw JUMBF."""
    # sfVersion + numTables + searchRange + entrySelector + rangeShift
    num_tables = 1
    header = b"\x00\x01\x00\x00" + struct.pack(">HHH H", num_tables, 16, 0, 0)

    # C2PA table data is raw JUMBF (no separate header)
    c2pa_table = jumbf

    # Table record: tag(4) + checksum(4) + offset(4) + length(4)
    table_offset = len(header) + 16  # after header + this table record
    table_record = (
        b"C2PA"
        + struct.pack(">I", 0)  # checksum (ignored)
        + struct.pack(">I", table_offset)
        + struct.pack(">I", len(c2pa_table))
    )

    return header + table_record + c2pa_table


def _build_html_with_jumbf(jumbf: bytes) -> bytes:
    """Build minimal HTML with inline C2PA script element."""
    b64 = base64.b64encode(jumbf).decode("ascii")
    html = (
        f"<!DOCTYPE html>\n<html><head>\n"
        f'<script type="application/c2pa">{b64}</script>\n'
        f"</head><body></body></html>\n"
    )
    return html.encode("utf-8")


def _build_html_with_link(href: str) -> bytes:
    """Build minimal HTML with external C2PA link element."""
    html = (
        f"<!DOCTYPE html>\n<html><head>\n"
        f'<link rel="c2pa-manifest" href="{href}" type="application/c2pa">\n'
        f"</head><body></body></html>\n"
    )
    return html.encode("utf-8")


def _build_zip_with_jumbf(jumbf: bytes) -> bytes:
    """Build minimal ZIP with META-INF/content_credential.c2pa."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("META-INF/content_credential.c2pa", jumbf)
        zf.writestr("content.txt", "Hello, world!")
    return buf.getvalue()


def _encode_byte_as_vs(b: int) -> bytes:
    """Encode a single byte as a UTF-8 variation selector."""
    if b <= 0x0F:
        # U+FE00-U+FE0F -> 3-byte UTF-8: EF B8 {80+b}
        return bytes([0xEF, 0xB8, 0x80 + b])
    else:
        # U+E0100-U+E01EF -> 4-byte UTF-8
        cp = 0xE0100 + (b - 0x10)
        return bytes(
            [
                0xF0 | (cp >> 18),
                0x80 | ((cp >> 12) & 0x3F),
                0x80 | ((cp >> 6) & 0x3F),
                0x80 | (cp & 0x3F),
            ]
        )


def _build_text_vs_wrapper(jumbf: bytes) -> bytes:
    """Build text file with v2.4 C2PATextManifestWrapper (VS encoding)."""
    # Binary structure: magic(8) + version(1) + length(4) + jumbf
    magic = b"C2PATXT\x00"
    version = b"\x01"
    length = struct.pack(">I", len(jumbf))
    binary = magic + version + length + jumbf

    # Encode each byte as a variation selector
    vs_encoded = b""
    for byte in binary:
        vs_encoded += _encode_byte_as_vs(byte)

    # U+FEFF marker in UTF-8
    bom = b"\xef\xbb\xbf"

    content = b"This is the document content.\n\n" + bom + vs_encoded + b"\n"
    return content


def _build_structured_text_with_jumbf(jumbf: bytes) -> bytes:
    """Build XML file with structured text C2PA delimiters."""
    b64 = base64.b64encode(jumbf).decode("ascii")
    xml = (
        f'<?xml version="1.0"?>\n'
        f"<document>\n"
        f"  <content>Test</content>\n"
        f"</document>\n"
        f"<!-- -----BEGIN C2PA MANIFEST----- "
        f"data:application/c2pa;base64,{b64} "
        f"-----END C2PA MANIFEST----- -->\n"
    )
    return xml.encode("utf-8")


# ---------------------------------------------------------------------------
# ID3v2 tests
# ---------------------------------------------------------------------------


class TestID3Extractor:
    def test_can_handle_by_suffix(self) -> None:
        assert ID3Extractor.can_handle(b"ID3", ".mp3")
        assert ID3Extractor.can_handle(b"ID3", ".flac")

    def test_can_handle_by_magic(self) -> None:
        assert ID3Extractor.can_handle(b"ID3\x04\x00", ".bin")
        assert not ID3Extractor.can_handle(b"\xff\xfb", ".bin")

    def test_extract_v24(self) -> None:
        data = _build_id3_with_jumbf(SAMPLE_JUMBF, version=4)
        result = ID3Extractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "id3"

    def test_extract_v23(self) -> None:
        data = _build_id3_with_jumbf(SAMPLE_JUMBF, version=3)
        result = ID3Extractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_no_geob_raises(self) -> None:
        # ID3 header with no frames (just padding)
        tag_size = bytes([0, 0, 0, 4])
        data = b"ID3\x04\x00\x00" + tag_size + b"\x00\x00\x00\x00"
        with pytest.raises(ExtractionError, match="No C2PA GEOB"):
            ID3Extractor.extract(data)


# ---------------------------------------------------------------------------
# OGG tests
# ---------------------------------------------------------------------------


class TestOGGExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert OGGExtractor.can_handle(b"OggS", ".ogg")
        assert OGGExtractor.can_handle(b"OggS", ".opus")

    def test_can_handle_by_magic(self) -> None:
        assert OGGExtractor.can_handle(b"OggS\x00", ".bin")
        assert not OGGExtractor.can_handle(b"\xff\xfb", ".bin")

    def test_extract_single_page(self) -> None:
        data = _build_ogg_with_jumbf(SAMPLE_JUMBF)
        result = OGGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "ogg"

    def test_no_c2pa_stream_raises(self) -> None:
        # OGG page with non-C2PA data
        capture = b"OggS"
        header = b"\x00\x06" + b"\x00" * 8  # version + header_type + granule
        serial = struct.pack("<I", 1)
        page_seq = struct.pack("<I", 0)
        checksum = b"\x00" * 4
        payload = b"vorbis_data_here"
        seg_table = b"\x01" + bytes([len(payload)])
        page = capture + header + serial + page_seq + checksum + seg_table + payload
        with pytest.raises(ExtractionError, match="No C2PA logical bitstream"):
            OGGExtractor.extract(page)


# ---------------------------------------------------------------------------
# FLAC tests
# ---------------------------------------------------------------------------


class TestFLACExtractor:
    def test_can_handle_by_suffix(self) -> None:
        from c2pa_conformance.extractors.flac import FLACExtractor

        assert FLACExtractor.can_handle(b"fLaC", ".flac")

    def test_can_handle_by_magic(self) -> None:
        from c2pa_conformance.extractors.flac import FLACExtractor

        assert FLACExtractor.can_handle(b"fLaC\x00\x00", ".bin")
        assert not FLACExtractor.can_handle(b"ID3\x04", ".bin")

    def test_extract_application_block(self) -> None:
        from c2pa_conformance.extractors.flac import FLACExtractor

        data = _build_flac_with_jumbf(SAMPLE_JUMBF)
        result = FLACExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "flac"

    def test_no_c2pa_block_raises(self) -> None:
        from c2pa_conformance.extractors.flac import FLACExtractor

        # FLAC with STREAMINFO only (type 0, is_last=1)
        block_data = b"\x00" * 34  # minimal STREAMINFO
        header_byte = (1 << 7) | 0  # is_last=1, type=STREAMINFO
        block = bytes([header_byte]) + len(block_data).to_bytes(3, "big") + block_data
        data = b"fLaC" + block
        with pytest.raises(ExtractionError, match="No C2PA APPLICATION"):
            FLACExtractor.extract(data)


# ---------------------------------------------------------------------------
# Font tests
# ---------------------------------------------------------------------------


class TestFontExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert FontExtractor.can_handle(b"\x00\x01\x00\x00", ".ttf")
        assert FontExtractor.can_handle(b"OTTO", ".otf")

    def test_can_handle_by_magic(self) -> None:
        assert FontExtractor.can_handle(b"\x00\x01\x00\x00\x00\x01", ".bin")
        assert FontExtractor.can_handle(b"OTTO\x00\x01", ".bin")
        assert not FontExtractor.can_handle(b"\xff\xd8", ".bin")

    def test_extract_ttf(self) -> None:
        data = _build_font_with_jumbf(SAMPLE_JUMBF)
        result = FontExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "font"

    def test_no_c2pa_table_raises(self) -> None:
        # TTF with no tables
        header = b"\x00\x01\x00\x00" + struct.pack(">HHHH", 0, 0, 0, 0)
        with pytest.raises(ExtractionError, match="No C2PA table"):
            FontExtractor.extract(header)


# ---------------------------------------------------------------------------
# HTML tests
# ---------------------------------------------------------------------------


class TestHTMLExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert HTMLExtractor.can_handle(b"<!DOCTYPE html>", ".html")
        assert HTMLExtractor.can_handle(b"<html>", ".htm")

    def test_can_handle_by_content(self) -> None:
        assert HTMLExtractor.can_handle(b"<!doctype html><html>", ".bin")

    def test_extract_inline_script(self) -> None:
        data = _build_html_with_jumbf(SAMPLE_JUMBF)
        result = HTMLExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "html"

    def test_extract_data_uri_link(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        href = f"data:application/c2pa;base64,{b64}"
        data = _build_html_with_link(href)
        result = HTMLExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_external_link_raises(self) -> None:
        data = _build_html_with_link("https://example.com/manifest.c2pa")
        with pytest.raises(ExtractionError, match="external reference"):
            HTMLExtractor.extract(data)

    def test_multiple_scripts_raises(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        html = (
            f"<html><head>"
            f'<script type="application/c2pa">{b64}</script>'
            f'<script type="application/c2pa">{b64}</script>'
            f"</head></html>"
        ).encode()
        with pytest.raises(ExtractionError, match="multipleManifests"):
            HTMLExtractor.extract(html)

    def test_no_manifest_raises(self) -> None:
        data = b"<!DOCTYPE html><html><head></head><body></body></html>"
        with pytest.raises(ExtractionError, match="No C2PA manifest"):
            HTMLExtractor.extract(data)


# ---------------------------------------------------------------------------
# ZIP tests
# ---------------------------------------------------------------------------


class TestZIPExtractor:
    def test_can_handle_by_suffix(self) -> None:
        assert ZIPExtractor.can_handle(b"PK\x03\x04", ".epub")
        assert ZIPExtractor.can_handle(b"PK\x03\x04", ".docx")
        assert ZIPExtractor.can_handle(b"PK\x03\x04", ".odt")

    def test_can_handle_by_magic(self) -> None:
        assert ZIPExtractor.can_handle(b"PK\x03\x04rest", ".bin")
        assert not ZIPExtractor.can_handle(b"\xff\xd8", ".bin")

    def test_extract_from_zip(self) -> None:
        data = _build_zip_with_jumbf(SAMPLE_JUMBF)
        result = ZIPExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "zip"

    def test_no_c2pa_entry_raises(self) -> None:
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("content.txt", "Hello")
        with pytest.raises(ExtractionError, match="No META-INF/content_credential.c2pa"):
            ZIPExtractor.extract(buf.getvalue())

    def test_compressed_entry_raises(self) -> None:
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("META-INF/content_credential.c2pa", SAMPLE_JUMBF)
        with pytest.raises(ExtractionError, match="compressed"):
            ZIPExtractor.extract(buf.getvalue())

    def test_auto_detect_epub(self, tmp_path: Path) -> None:
        p = tmp_path / "test.epub"
        p.write_bytes(_build_zip_with_jumbf(SAMPLE_JUMBF))
        result = detect_and_extract(p)
        assert result.container_format == "zip"
        assert result.jumbf_bytes == SAMPLE_JUMBF


# ---------------------------------------------------------------------------
# Text extractor v2.4 VS encoding tests
# ---------------------------------------------------------------------------


class TestTextExtractorV24:
    def test_vs_encoded_wrapper(self) -> None:
        data = _build_text_vs_wrapper(SAMPLE_JUMBF)
        result = TextExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "text"

    def test_legacy_delimiters_still_work(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        data = (
            f"Content here.\n\n---BEGIN C2PA MANIFEST---\n{b64}\n---END C2PA MANIFEST---\n"
        ).encode()
        result = TextExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_vs_preferred_over_legacy(self) -> None:
        """When both VS and legacy are present, VS is used (tried first)."""
        vs_data = _build_text_vs_wrapper(SAMPLE_JUMBF)
        # Append legacy block with different data
        other_jumbf = b"\x00\x00\x00\x10jumbOTHERDAT"
        b64 = base64.b64encode(other_jumbf).decode("ascii")
        legacy = f"\n---BEGIN C2PA MANIFEST---\n{b64}\n---END C2PA MANIFEST---\n"
        combined = vs_data + legacy.encode()
        result = TextExtractor.extract(combined)
        # Should extract the VS-encoded one (SAMPLE_JUMBF), not the legacy one
        assert result.jumbf_bytes == SAMPLE_JUMBF

    def test_no_wrapper_raises(self) -> None:
        with pytest.raises(ExtractionError, match="No C2PATextManifestWrapper"):
            TextExtractor.extract(b"Just plain text, no manifest.")


# ---------------------------------------------------------------------------
# SVG/structured text extended tests
# ---------------------------------------------------------------------------


class TestStructuredTextExtractor:
    def test_generic_xml_delimiters(self) -> None:
        data = _build_structured_text_with_jumbf(SAMPLE_JUMBF)
        result = SVGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "structured_text"

    def test_data_uri_in_delimiters(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        data = (
            f"-----BEGIN C2PA MANIFEST-----\n"
            f"data:application/c2pa;base64,{b64}\n"
            f"-----END C2PA MANIFEST-----\n"
        ).encode()
        result = SVGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "structured_text"

    def test_external_url_in_delimiters_raises(self) -> None:
        data = (
            b"-----BEGIN C2PA MANIFEST-----\n"
            b"https://example.com/manifest.c2pa\n"
            b"-----END C2PA MANIFEST-----\n"
        )
        with pytest.raises(ExtractionError, match="external reference"):
            SVGExtractor.extract(data)

    def test_svg_comment_still_works(self) -> None:
        b64 = base64.b64encode(SAMPLE_JUMBF).decode("ascii")
        data = f'<svg><!-- c2pa manifest="{b64}" --></svg>'.encode()
        result = SVGExtractor.extract(data)
        assert result.jumbf_bytes == SAMPLE_JUMBF
        assert result.container_format == "svg"

    def test_can_handle_structured_text(self) -> None:
        data = b"-----BEGIN C2PA MANIFEST-----\ndata\n-----END C2PA MANIFEST-----\n"
        assert SVGExtractor.can_handle(data, ".xml")
        assert SVGExtractor.can_handle(data, ".xhtml")
        assert SVGExtractor.can_handle(data, ".rst")  # generic detection by content
