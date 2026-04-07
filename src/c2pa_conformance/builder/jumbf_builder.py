"""JUMBF box builder for constructing C2PA manifest stores.

This is the inverse of parser/jumbf.py's parse_jumbf(). It builds
raw JUMBF bytes from a tree of box specifications.
"""

from __future__ import annotations

import struct

# Well-known box types (match parser/jumbf.py constants)
JUMB = b"jumb"
JUMD = b"jumd"
JP2C = b"jp2c"
JSON_BOX = b"json"
CBOR_BOX = b"cbor"
UUID_BOX = b"uuid"
C2SH = b"c2sh"  # C2PA salt hash box

# Size threshold: if total box size exceeds a 32-bit LBox, use XLBox (LBox=1).
_MAX_LBOX = 0xFFFFFFFF


def build_box(box_type: bytes, payload: bytes) -> bytes:
    """Build a single JUMBF box with a standard 8-byte or extended 16-byte header.

    Standard form: LBox (4 bytes) | TBox (4 bytes) | payload
    Extended form: LBox=1 (4 bytes) | TBox (4 bytes) | XLBox (8 bytes) | payload

    LBox is the total byte count including the header itself.
    """
    total = 8 + len(payload)
    if total > _MAX_LBOX:
        # Extended size: LBox=1 signals XLBox follows; XLBox includes all 16 header bytes.
        xlbox_total = 16 + len(payload)
        return struct.pack(">I", 1) + box_type + struct.pack(">Q", xlbox_total) + payload
    return struct.pack(">I", total) + box_type + payload


def build_jumd(
    type_uuid: bytes,
    label: str,
    toggles: int = 0x03,
    salt: bytes | None = None,
) -> bytes:
    """Build a JUMD (description) box.

    Args:
        type_uuid: 16-byte type UUID.
        label: UTF-8 label string (null-terminated in output).
        toggles: Toggle byte. C2PA uses 0x03 (requestable + label present).
        salt: Optional salt bytes (>=16 bytes). When provided, a c2sh salt
            box is appended and the toggles private bit (0x10) is set.

    Returns:
        Raw bytes for the complete JUMD box (including LBox/TBox header).
    """
    if len(type_uuid) != 16:
        raise ValueError(f"type_uuid must be exactly 16 bytes; got {len(type_uuid)}")

    if salt is not None:
        toggles |= 0x10  # Set private bit

    payload = type_uuid + bytes([toggles])
    if (toggles & 0x01) and label:
        payload += label.encode("utf-8") + b"\x00"

    if salt is not None:
        payload += build_box(C2SH, salt)

    return build_box(JUMD, payload)


def build_superbox(type_uuid: bytes, label: str, children: list[bytes]) -> bytes:
    """Build a JUMB superbox containing a JUMD description box and child boxes.

    The JUMB box payload is: JUMD box + concatenated children bytes.

    Args:
        type_uuid: 16-byte type UUID for the JUMD description.
        label: Box label string.
        children: List of pre-built child box byte strings.

    Returns:
        Raw bytes for the complete superbox.
    """
    jumd = build_jumd(type_uuid, label)
    inner = jumd + b"".join(children)
    return build_box(JUMB, inner)


def build_superbox_from_parts(jumd_bytes: bytes, content_boxes: list[bytes]) -> bytes:
    """Build a JUMB superbox from a pre-built JUMD and content box bytes.

    Unlike build_superbox(), this takes already-built JUMD bytes so the
    caller can use the same JUMD for both hash computation and box assembly.
    """
    inner = jumd_bytes + b"".join(content_boxes)
    return build_box(JUMB, inner)


def build_cbor_box(cbor_data: bytes) -> bytes:
    """Build a CBOR content box containing the given CBOR bytes."""
    return build_box(CBOR_BOX, cbor_data)


def build_json_box(json_data: bytes) -> bytes:
    """Build a JSON content box containing the given JSON bytes."""
    return build_box(JSON_BOX, json_data)
