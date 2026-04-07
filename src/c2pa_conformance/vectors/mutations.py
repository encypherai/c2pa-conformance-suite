"""Mutation functions for generating invalid test vectors."""

from __future__ import annotations


def truncate_jumbf(jumbf_bytes: bytes) -> bytes:
    """Truncate JUMBF to half its length."""
    return jumbf_bytes[: len(jumbf_bytes) // 2]


def corrupt_box_type(jumbf_bytes: bytes) -> bytes:
    """Corrupt the first JUMBF box type (bytes 4-8)."""
    if len(jumbf_bytes) < 8:
        return jumbf_bytes
    return jumbf_bytes[:4] + b"XXXX" + jumbf_bytes[8:]


def strip_claim_generator(jumbf_bytes: bytes) -> bytes:
    """Return JUMBF as-is; claim_generator is already omitted from claim_data."""
    return jumbf_bytes


def tamper_signature(jumbf_bytes: bytes) -> bytes:
    """Flip bits in the signature region of the JUMBF.

    The signature is typically in the last portion of the JUMBF.
    Flips a byte near the end to corrupt it.
    """
    if len(jumbf_bytes) < 32:
        return jumbf_bytes
    data = bytearray(jumbf_bytes)
    # Flip a byte 20 bytes from the end (in the COSE signature area)
    pos = len(data) - 20
    data[pos] ^= 0xFF
    return bytes(data)


def tamper_container_bytes(container: bytes) -> bytes:
    """Modify container bytes after embedding (simulates content tampering).

    Flips a byte in the image data area (past headers/JUMBF).
    """
    if len(container) < 100:
        return container
    data = bytearray(container)
    # Modify a byte near the end of the file (in image data)
    pos = len(data) - 10
    data[pos] ^= 0xFF
    return bytes(data)
