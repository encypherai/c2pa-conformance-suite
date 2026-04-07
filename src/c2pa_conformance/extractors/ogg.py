"""OGG container extractor (Vorbis, Opus, FLAC in OGG).

Extracts C2PA JUMBF from a dedicated OGG logical bitstream whose first
packet starts with the 5-byte magic \\x00c2pa.

OGG page header (27+ bytes):
    "OggS" (4 bytes) + version (1) + header_type (1) + granule (8)
    + serial_number (4 LE) + page_sequence (4 LE) + checksum (4)
    + page_segments (1) + segment_table (page_segments bytes)

Packets are reassembled from segments across pages. A segment of 255
bytes means the packet continues in the next segment. A segment < 255
terminates the packet.
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

OGG_MAGIC = b"OggS"
C2PA_STREAM_MAGIC = b"\x00c2pa"


@register
class OGGExtractor:
    """Extract C2PA JUMBF from OGG logical bitstream."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in (".ogg", ".oga", ".ogv", ".opus"):
            return True
        return len(data) >= 4 and data[:4] == OGG_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 4 or data[:4] != OGG_MAGIC:
            raise ExtractionError("Not a valid OGG file")

        # First pass: find the C2PA bitstream serial number
        c2pa_serial = _find_c2pa_serial(data)
        if c2pa_serial is None:
            raise ExtractionError("No C2PA logical bitstream found in OGG")

        # Second pass: reassemble all packets for that serial
        packets = _reassemble_stream(data, c2pa_serial)
        if not packets:
            raise ExtractionError("C2PA bitstream has no packets")

        # Strip 5-byte magic from first packet, concatenate all
        first = packets[0]
        if len(first) < 5 or first[:5] != C2PA_STREAM_MAGIC:
            raise ExtractionError("C2PA bitstream first packet missing magic")

        chunks = [first[5:]] + packets[1:]
        jumbf_bytes = b"".join(chunks)

        return ExtractionResult(
            jumbf_bytes=jumbf_bytes,
            container_format="ogg",
            jumbf_offset=0,
            jumbf_length=len(jumbf_bytes),
        )


def _parse_page(data: bytes, pos: int) -> tuple[int, int, int, list[bytes]] | None:
    """Parse one OGG page. Returns (serial, header_type, next_pos, segments) or None."""
    if pos + 27 > len(data) or data[pos : pos + 4] != OGG_MAGIC:
        return None

    header_type = data[pos + 5]
    serial = struct.unpack_from("<I", data, pos + 14)[0]
    num_segments = data[pos + 26]

    if pos + 27 + num_segments > len(data):
        return None

    segment_table = data[pos + 27 : pos + 27 + num_segments]
    data_start = pos + 27 + num_segments

    segments: list[bytes] = []
    seg_pos = data_start
    for size in segment_table:
        if seg_pos + size > len(data):
            break
        segments.append(data[seg_pos : seg_pos + size])
        seg_pos += size

    return serial, header_type, seg_pos, segments


def _find_c2pa_serial(data: bytes) -> int | None:
    """Find the serial number of the C2PA logical bitstream."""
    pos = 0
    # Track first packets by serial (BOS pages, header_type & 0x02)
    seen_serials: set[int] = set()

    while pos < len(data):
        page = _parse_page(data, pos)
        if page is None:
            break

        serial, header_type, next_pos, segments = page

        # BOS (beginning of stream) flag
        if (header_type & 0x02) and serial not in seen_serials:
            seen_serials.add(serial)
            # Check if first packet starts with C2PA magic
            if segments:
                first_seg = segments[0]
                if len(first_seg) >= 5 and first_seg[:5] == C2PA_STREAM_MAGIC:
                    return serial

        pos = next_pos

    return None


def _reassemble_stream(data: bytes, target_serial: int) -> list[bytes]:
    """Reassemble all packets for a given serial number."""
    packets: list[bytes] = []
    current_packet = bytearray()
    pos = 0

    while pos < len(data):
        page = _parse_page(data, pos)
        if page is None:
            break

        serial, header_type, next_pos, segments = page
        pos = next_pos

        if serial != target_serial:
            continue

        for seg_data in segments:
            current_packet.extend(seg_data)
            if len(seg_data) < 255:
                # Packet complete
                packets.append(bytes(current_packet))
                current_packet = bytearray()

    # Flush any remaining data
    if current_packet:
        packets.append(bytes(current_packet))

    return packets
