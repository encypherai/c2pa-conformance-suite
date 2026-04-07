"""ID3v2 container extractor (MP3, FLAC with ID3v2 tags).

Extracts C2PA JUMBF from an ID3v2 GEOB (General Encapsulated Object) frame
whose MIME type field equals "application/c2pa".

ID3v2 header (10 bytes):
    "ID3" (3 bytes) + version (2 bytes) + flags (1 byte) + size (4 bytes synchsafe)

ID3v2 frame (v2.3/v2.4):
    Frame ID (4 bytes) + Size (4 bytes) + Flags (2 bytes)
    Size is synchsafe in v2.4, big-endian in v2.3.

GEOB frame payload:
    Text encoding (1 byte: 0=ISO-8859-1, 1=UTF-16, 2=UTF-16BE, 3=UTF-8)
    MIME type (null-terminated, always ISO-8859-1)
    Filename (null-terminated in declared encoding)
    Content description (null-terminated in declared encoding)
    Encapsulated object data (remaining bytes = raw JUMBF)
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

ID3_MAGIC = b"ID3"
C2PA_MIME = b"application/c2pa"


def _decode_synchsafe(data: bytes) -> int:
    """Decode a 4-byte synchsafe integer (bit 7 of each byte is zero)."""
    return (data[0] << 21) | (data[1] << 14) | (data[2] << 7) | data[3]


def _skip_null_terminated(data: bytes, pos: int, encoding: int) -> int:
    """Skip past a null-terminated string, return position after null."""
    if encoding in (1, 2):
        # UTF-16: null terminator is two zero bytes
        while pos + 1 < len(data):
            if data[pos] == 0 and data[pos + 1] == 0:
                return pos + 2
            pos += 2
        return len(data)
    else:
        # ISO-8859-1 or UTF-8: single zero byte terminator
        null = data.find(b"\x00", pos)
        if null == -1:
            return len(data)
        return null + 1


@register
class ID3Extractor:
    """Extract C2PA JUMBF from ID3v2 GEOB frame."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix == ".mp3":
            return True
        # Check for ID3v2 header
        return len(data) >= 3 and data[:3] == ID3_MAGIC

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 10 or data[:3] != ID3_MAGIC:
            raise ExtractionError("No ID3v2 header found")

        version_major = data[3]
        # version_minor = data[4]
        # flags = data[5]
        tag_size = _decode_synchsafe(data[6:10])
        use_synchsafe = version_major >= 4

        pos = 10
        tag_end = 10 + tag_size

        while pos + 10 <= tag_end:
            frame_id = data[pos : pos + 4]

            # Padding bytes (all zeros) signal end of frames
            if frame_id == b"\x00\x00\x00\x00":
                break

            if use_synchsafe:
                frame_size = _decode_synchsafe(data[pos + 4 : pos + 8])
            else:
                frame_size = struct.unpack_from(">I", data, pos + 4)[0]

            # frame_flags = data[pos + 8 : pos + 10]
            frame_data_start = pos + 10
            frame_data_end = frame_data_start + frame_size

            if frame_data_end > tag_end:
                break

            if frame_id == b"GEOB" and frame_size > 2:
                payload = data[frame_data_start:frame_data_end]
                jumbf = _parse_geob(payload)
                if jumbf is not None:
                    return ExtractionResult(
                        jumbf_bytes=jumbf,
                        container_format="id3",
                        jumbf_offset=frame_data_start,
                        jumbf_length=len(jumbf),
                    )

            pos = frame_data_end

        raise ExtractionError("No C2PA GEOB frame found in ID3v2 tag")


def _parse_geob(payload: bytes) -> bytes | None:
    """Parse a GEOB frame payload. Returns JUMBF bytes if C2PA, else None."""
    if len(payload) < 3:
        return None

    encoding = payload[0]
    pos = 1

    # MIME type is always ISO-8859-1 null-terminated
    null = payload.find(b"\x00", pos)
    if null == -1:
        return None
    mime_type = payload[pos:null]
    pos = null + 1

    if mime_type != C2PA_MIME:
        return None

    # Skip filename (in declared encoding)
    pos = _skip_null_terminated(payload, pos, encoding)
    # Skip content description (in declared encoding)
    pos = _skip_null_terminated(payload, pos, encoding)

    # Remaining bytes are the encapsulated object = raw JUMBF
    if pos >= len(payload):
        return None

    return payload[pos:]
