"""JPEG APP11 embedder for C2PA JUMBF manifest stores."""

from __future__ import annotations

import struct

# JPEG markers
SOI = b"\xff\xd8"
APP11 = b"\xff\xeb"
JUMBF_CI = b"\x4a\x50"  # "JP" Common Identifier

# Max payload per APP11 segment: 0xFFFF (max Lp) - 2 (Lp itself) - 8 (CI+En+Z) = 65525
MAX_SEGMENT_PAYLOAD = 65525


def embed_jpeg(container: bytes, jumbf_bytes: bytes, box_instance: int = 1) -> bytes:
    """Embed JUMBF bytes into a JPEG container via APP11 segments.

    Inserts APP11 segments after SOI and any existing APP0/APP1 markers,
    before the first non-APP marker. Splits JUMBF across multiple segments
    if needed.

    Args:
        container: Raw JPEG bytes (must start with SOI).
        jumbf_bytes: Raw JUMBF manifest store bytes.
        box_instance: En field value (box instance number).

    Returns:
        New JPEG bytes with APP11 segments inserted.

    Raises:
        ValueError: If container is not a valid JPEG.
    """
    if len(container) < 2 or container[:2] != SOI:
        raise ValueError("Not a valid JPEG (missing SOI marker)")

    # Build APP11 segments
    segments = _build_app11_segments(jumbf_bytes, box_instance)

    # Find insertion point: after SOI and existing APP markers
    insert_pos = _find_insert_position(container)

    # Splice segments into container
    return container[:insert_pos] + b"".join(segments) + container[insert_pos:]


def _build_app11_segments(jumbf_bytes: bytes, box_instance: int) -> list[bytes]:
    """Split JUMBF bytes into APP11 segments."""
    segments = []
    offset = 0
    seq = 1  # Z is 1-based

    while offset < len(jumbf_bytes):
        chunk = jumbf_bytes[offset : offset + MAX_SEGMENT_PAYLOAD]

        # Segment: marker + Lp + CI + En + Z + payload
        # Lp = 2 (self) + 2 (CI) + 2 (En) + 4 (Z) + len(chunk)
        lp = 2 + 2 + 2 + 4 + len(chunk)

        segment = (
            APP11
            + struct.pack(">H", lp)
            + JUMBF_CI
            + struct.pack(">H", box_instance)
            + struct.pack(">I", seq)
            + chunk
        )
        segments.append(segment)

        offset += len(chunk)
        seq += 1

    return segments


def _find_insert_position(data: bytes) -> int:
    """Find position to insert APP11 segments.

    Skips past SOI and any APP0/APP1 markers, inserts before
    the first non-APP or non-existent marker.
    """
    pos = 2  # After SOI

    while pos < len(data) - 3:
        if data[pos] != 0xFF:
            break

        marker_byte = data[pos + 1]

        # APP0 (0xE0) and APP1 (0xE1) - skip past them
        if marker_byte in (0xE0, 0xE1):
            lp = struct.unpack_from(">H", data, pos + 2)[0]
            pos += 2 + lp
            continue

        # Any other marker - insert here
        break

    return pos
