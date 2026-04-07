"""JPEG container extractor.

Extracts C2PA JUMBF manifest store from JPEG APP11 marker segments
per ISO 19566-5 (JPEG XT Part 6).

JPEG APP11 JUMBF segment header:
    Marker: 0xFF 0xEB
    Lp:     2 bytes big-endian (segment length, includes itself)
    CI:     2 bytes (0x4A 0x50 = "JP" Common Identifier)
    En:     2 bytes big-endian (box instance number)
    Z:      4 bytes big-endian (packet sequence number, 1-based)
    Data:   remaining bytes = JUMBF payload fragment

All packets have CI(2) + En(2) + Z(4) = 8 bytes of header.
For the first packet (Z=1), the JUMBF data begins with the
superbox's own LBox field. Segments with same En belong to the
same JUMBF box, ordered by Z.
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

# JPEG markers
SOI = b"\xff\xd8"
APP11 = b"\xff\xeb"
JUMBF_CI = b"\x4a\x50"  # "JP" - Common Identifier for JUMBF


@register
class JPEGExtractor:
    """Extract C2PA JUMBF from JPEG APP11 segments."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in (".jpg", ".jpeg", ".jpe"):
            return True
        return len(data) >= 2 and data[:2] == SOI

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 2 or data[:2] != SOI:
            raise ExtractionError("Not a valid JPEG file (missing SOI marker)")

        segments = _find_app11_jumbf_segments(data)
        if not segments:
            raise ExtractionError("No C2PA APP11 JUMBF segments found in JPEG")

        # Sort by packet sequence and concatenate payloads
        segments.sort(key=lambda s: s[0])
        jumbf_bytes = b"".join(payload for _, _, payload in segments)

        # Truncate to declared jumb superbox size to avoid trailing bytes
        # from segment boundaries
        if len(jumbf_bytes) >= 8:
            lbox = struct.unpack_from(">I", jumbf_bytes, 0)[0]
            if 8 <= lbox <= len(jumbf_bytes):
                jumbf_bytes = jumbf_bytes[:lbox]

        # First segment offset is the JUMBF start position in the file
        first_offset = segments[0][1]

        return ExtractionResult(
            jumbf_bytes=jumbf_bytes,
            container_format="jpeg",
            jumbf_offset=first_offset,
            jumbf_length=len(jumbf_bytes),
        )


def _find_app11_jumbf_segments(
    data: bytes,
) -> list[tuple[int, int, bytes]]:
    """Find all APP11 JUMBF segments in JPEG data.

    Returns list of (sequence_number, file_offset, payload_bytes).
    """
    segments: list[tuple[int, int, bytes]] = []
    pos = 2  # Skip SOI

    while pos < len(data) - 1:
        # Find next marker
        if data[pos] != 0xFF:
            pos += 1
            continue

        # Skip padding 0xFF bytes
        while pos < len(data) - 1 and data[pos + 1] == 0xFF:
            pos += 1

        if pos >= len(data) - 1:
            break

        marker = data[pos : pos + 2]
        pos += 2

        # SOS marker: rest is entropy-coded data, stop scanning
        if marker == b"\xff\xda":
            break

        # Markers without length (standalone markers)
        if marker[1] in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9):
            continue

        # Read segment length
        if pos + 2 > len(data):
            break
        lp = struct.unpack_from(">H", data, pos)[0]
        segment_start = pos - 2  # marker position

        if lp < 2:
            break

        segment_data = data[pos + 2 : pos + lp]  # data after Lp field
        pos += lp

        # Check if this is an APP11 with JUMBF CI
        if marker != APP11 or len(segment_data) < 4:
            continue

        ci = segment_data[0:2]
        if ci != JUMBF_CI:
            continue

        if len(segment_data) < 8:
            continue

        z = struct.unpack_from(">I", segment_data, 4)[0]

        # All packets: CI(2) + En(2) + Z(4) = 8 bytes header.
        # JUMBF data starts at offset 8. For the first packet (Z=1),
        # the JUMBF box's own LBox is the first 4 bytes of payload.
        payload = segment_data[8:]

        segments.append((z, segment_start, payload))

    return segments
