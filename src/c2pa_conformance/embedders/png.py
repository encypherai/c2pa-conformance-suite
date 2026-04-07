"""PNG caBX chunk embedder for C2PA JUMBF manifest stores."""

from __future__ import annotations

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CABX_TYPE = b"caBX"


def embed_png(container: bytes, jumbf_bytes: bytes) -> bytes:
    """Embed JUMBF bytes into a PNG container via a caBX chunk.

    Inserts the caBX chunk before the first IDAT chunk.

    Args:
        container: Raw PNG bytes (must start with PNG signature).
        jumbf_bytes: Raw JUMBF manifest store bytes.

    Returns:
        New PNG bytes with caBX chunk inserted.

    Raises:
        ValueError: If container is not a valid PNG.
    """
    if len(container) < 8 or container[:8] != PNG_SIGNATURE:
        raise ValueError("Not a valid PNG (bad signature)")

    # Build the caBX chunk
    chunk = _build_chunk(CABX_TYPE, jumbf_bytes)

    # Find insertion point: before first IDAT
    insert_pos = _find_idat_position(container)

    return container[:insert_pos] + chunk + container[insert_pos:]


def _build_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build a PNG chunk: Length + Type + Data + CRC."""
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def _find_idat_position(data: bytes) -> int:
    """Find the byte offset of the first IDAT chunk."""
    pos = 8  # Skip PNG signature

    while pos + 8 <= len(data):
        chunk_length = struct.unpack_from(">I", data, pos)[0]
        chunk_type = data[pos + 4 : pos + 8]

        if chunk_type == b"IDAT":
            return pos

        # Skip: length(4) + type(4) + data(chunk_length) + crc(4)
        pos += 12 + chunk_length

    # If no IDAT found, insert before IEND or at end
    return len(data)
