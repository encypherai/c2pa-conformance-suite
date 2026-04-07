"""Generate minimal valid container files for test vector embedding."""

from __future__ import annotations

import struct
import zlib


def minimal_jpeg() -> bytes:
    """Build a minimal valid JPEG: SOI + APP0 (JFIF) + DQT + SOF0 + DHT + SOS + EOI."""
    soi = b"\xff\xd8"
    # APP0 JFIF header
    app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", 2 + len(app0_data)) + app0_data
    # Minimal quantization table (DQT)
    dqt_data = bytes([0]) + bytes(64)  # table 0, all zeros
    dqt = b"\xff\xdb" + struct.pack(">H", 2 + len(dqt_data)) + dqt_data
    # SOF0: 1x1 pixel, 1 component, 8-bit
    sof_data = bytes([8, 0, 1, 0, 1, 1, 1, 0x11, 0])
    sof = b"\xff\xc0" + struct.pack(">H", 2 + len(sof_data)) + sof_data
    # Minimal Huffman table (DHT)
    dht_data = bytes([0]) + bytes(16) + bytes(0)  # DC table 0, no codes
    dht = b"\xff\xc4" + struct.pack(">H", 2 + len(dht_data)) + dht_data
    # SOS + minimal entropy data + EOI
    sos_data = bytes([1, 1, 0, 0, 63, 0])
    sos = b"\xff\xda" + struct.pack(">H", 2 + len(sos_data)) + sos_data
    return soi + app0 + dqt + sof + dht + sos + b"\x00" + b"\xff\xd9"


def minimal_png() -> bytes:
    """Build a minimal valid PNG: signature + IHDR + IDAT + IEND."""
    sig = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1, 8-bit RGB
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _png_chunk(b"IHDR", ihdr_data)
    # IDAT: compressed 1x1 RGB pixel
    raw = b"\x00\xff\x00\x00"  # filter=None, R=255, G=0, B=0
    idat = _png_chunk(b"IDAT", zlib.compress(raw))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc
