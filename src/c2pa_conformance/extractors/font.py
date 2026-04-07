"""OpenType/OFF font extractor (TTF, OTF, WOFF2).

Extracts C2PA JUMBF from the C2PA table in OpenType/OFF fonts.

OpenType table directory (starts at offset 0):
    sfVersion (4 bytes) + numTables (2) + searchRange (2) +
    entrySelector (2) + rangeShift (2) = 12 bytes

Table record (16 bytes each):
    tag (4) + checksum (4) + offset (4) + length (4)

The C2PA table data is the raw JUMBF manifest store (starts with jumb box).
"""

from __future__ import annotations

import struct

from c2pa_conformance.extractors.base import (
    ExtractionError,
    ExtractionResult,
    register,
)

C2PA_TABLE_TAG = b"C2PA"

# OpenType magic values
TTF_MAGIC = b"\x00\x01\x00\x00"  # TrueType
OTF_MAGIC = b"OTTO"  # OpenType with CFF
WOFF_MAGIC = b"wOFF"  # WOFF1
WOFF2_MAGIC = b"wOF2"  # WOFF2

FONT_SUFFIXES = {".ttf", ".otf", ".woff", ".woff2", ".ttc", ".sfnt"}


@register
class FontExtractor:
    """Extract C2PA JUMBF from OpenType C2PA table."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        if suffix in FONT_SUFFIXES:
            return True
        if len(data) >= 4:
            magic = data[:4]
            return magic in (TTF_MAGIC, OTF_MAGIC, WOFF_MAGIC, WOFF2_MAGIC)
        return False

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        if len(data) < 12:
            raise ExtractionError("Font file too short")

        magic = data[:4]

        if magic == WOFF2_MAGIC:
            return _extract_woff2(data)
        elif magic == WOFF_MAGIC:
            return _extract_woff1(data)
        elif magic in (TTF_MAGIC, OTF_MAGIC):
            return _extract_sfnt(data)
        else:
            raise ExtractionError(f"Unrecognized font format (magic={magic.hex()})")


def _extract_sfnt(data: bytes) -> ExtractionResult:
    """Extract from standard TrueType/OpenType (sfnt) font."""
    if len(data) < 12:
        raise ExtractionError("sfnt font too short for table directory")

    num_tables = struct.unpack_from(">H", data, 4)[0]

    for i in range(num_tables):
        record_offset = 12 + (i * 16)
        if record_offset + 16 > len(data):
            break

        tag = data[record_offset : record_offset + 4]
        table_offset = struct.unpack_from(">I", data, record_offset + 8)[0]
        table_length = struct.unpack_from(">I", data, record_offset + 12)[0]

        if tag == C2PA_TABLE_TAG:
            return _parse_c2pa_table(data, table_offset, table_length)

    raise ExtractionError("No C2PA table found in font")


def _extract_woff1(data: bytes) -> ExtractionResult:
    """Extract from WOFF1 font container."""
    if len(data) < 44:
        raise ExtractionError("WOFF1 file too short")

    num_tables = struct.unpack_from(">H", data, 12)[0]

    # WOFF1 table directory starts at offset 44
    for i in range(num_tables):
        entry_offset = 44 + (i * 20)
        if entry_offset + 20 > len(data):
            break

        tag = data[entry_offset : entry_offset + 4]
        offset = struct.unpack_from(">I", data, entry_offset + 4)[0]
        comp_length = struct.unpack_from(">I", data, entry_offset + 8)[0]
        orig_length = struct.unpack_from(">I", data, entry_offset + 12)[0]

        if tag == C2PA_TABLE_TAG:
            if comp_length == orig_length:
                # Not compressed
                return _parse_c2pa_table(data, offset, orig_length)
            else:
                # Compressed with zlib
                import zlib

                compressed = data[offset : offset + comp_length]
                decompressed = zlib.decompress(compressed)
                return _parse_c2pa_table(decompressed, 0, len(decompressed))

    raise ExtractionError("No C2PA table found in WOFF1 font")


def _extract_woff2(data: bytes) -> ExtractionResult:
    """Extract from WOFF2 font container."""
    if len(data) < 48:
        raise ExtractionError("WOFF2 file too short")

    num_tables = struct.unpack_from(">H", data, 12)[0]

    # WOFF2 table directory uses variable-length encoding
    # Each entry: flags(1) + optional tag(4) + origLength(UIntBase128) +
    #             optional transformLength(UIntBase128)
    pos = 48  # WOFF2 header is 48 bytes

    tables: list[tuple[bytes, int]] = []

    for _ in range(num_tables):
        if pos >= len(data):
            break

        flags = data[pos]
        pos += 1

        # Tag: if flags & 0x3F < 63, it's a known tag index; else 4 bytes follow
        tag_index = flags & 0x3F
        if tag_index == 63:
            if pos + 4 > len(data):
                break
            tag = data[pos : pos + 4]
            pos += 4
        else:
            tag = _WOFF2_KNOWN_TAGS.get(tag_index, b"\x00\x00\x00\x00")

        # origLength (UIntBase128)
        orig_length, pos = _read_uint_base128(data, pos)

        # transformLength present if transform flag set
        transform_version = (flags >> 6) & 0x03
        if tag in (b"glyf", b"loca") and transform_version == 0:
            # These have default transforms
            _, pos = _read_uint_base128(data, pos)
        elif transform_version != 0:
            _, pos = _read_uint_base128(data, pos)

        tables.append((tag, orig_length))

    # C2PA is not a known tag, so it will not have a transform applied.
    # The compressed table data follows the directory. For simplicity,
    # try to find C2PA table by scanning the decompressed stream.
    # WOFF2 compresses all tables together with Brotli.

    has_c2pa = any(tag == C2PA_TABLE_TAG for tag, _ in tables)
    if not has_c2pa:
        raise ExtractionError("No C2PA table found in WOFF2 font")

    # Find compressed data offset: after header(48) + directory + collection header
    # The total compressed data is one Brotli stream
    try:
        import brotli  # type: ignore[import-untyped]
    except ImportError:
        raise ExtractionError("WOFF2 C2PA extraction requires the 'brotli' package")

    # Approximate: the directory ends at current pos
    compressed_data = data[pos:]
    try:
        decompressed = brotli.decompress(compressed_data)
    except Exception as exc:
        raise ExtractionError(f"WOFF2 Brotli decompression failed: {exc}") from exc

    # Walk through decompressed data, table by table
    table_pos = 0
    for tag, orig_length in tables:
        if tag == C2PA_TABLE_TAG:
            table_data = decompressed[table_pos : table_pos + orig_length]
            return _parse_c2pa_table(table_data, 0, orig_length)
        # Tables are 4-byte aligned in the decompressed stream
        table_pos += orig_length
        if table_pos % 4 != 0:
            table_pos += 4 - (table_pos % 4)

    raise ExtractionError("C2PA table not found in decompressed WOFF2 data")


def _parse_c2pa_table(data: bytes, offset: int, length: int) -> ExtractionResult:
    """Parse C2PA table to extract JUMBF bytes.

    The C2PA table contains raw JUMBF manifest store data (starting with
    the jumb superbox LBox). No separate header structure.
    """
    if length < 8:
        raise ExtractionError(f"C2PA table too short ({length} bytes)")

    jumbf_bytes = data[offset : offset + length]

    # Validate it looks like JUMBF (first box should be jumb superbox)
    if length >= 8:
        box_type = jumbf_bytes[4:8]
        if box_type != b"jumb":
            raise ExtractionError(f"C2PA table does not start with jumb box (got {box_type!r})")

    return ExtractionResult(
        jumbf_bytes=jumbf_bytes,
        container_format="font",
        jumbf_offset=offset,
        jumbf_length=length,
    )


def _read_uint_base128(data: bytes, pos: int) -> tuple[int, int]:
    """Read a UIntBase128 value used in WOFF2."""
    result = 0
    for _ in range(5):  # Max 5 bytes
        if pos >= len(data):
            break
        b = data[pos]
        pos += 1
        result = (result << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            break
    return result, pos


# WOFF2 known tag table (first 63 entries)
_WOFF2_KNOWN_TAGS: dict[int, bytes] = {
    0: b"cmap",
    1: b"head",
    2: b"hhea",
    3: b"hmtx",
    4: b"maxp",
    5: b"name",
    6: b"OS/2",
    7: b"post",
    8: b"cvt ",
    9: b"fpgm",
    10: b"glyf",
    11: b"loca",
    12: b"prep",
    13: b"CFF ",
    14: b"VORG",
    15: b"EBDT",
    16: b"EBLC",
    17: b"gasp",
    18: b"hdmx",
    19: b"kern",
    20: b"LTSH",
    21: b"PCLT",
    22: b"VDMX",
    23: b"vhea",
    24: b"vmtx",
    25: b"BASE",
    26: b"GDEF",
    27: b"GPOS",
    28: b"GSUB",
    29: b"EBSC",
    30: b"JSTF",
    31: b"MATH",
    32: b"CBDT",
    33: b"CBLC",
    34: b"COLR",
    35: b"CPAL",
    36: b"SVG ",
    37: b"sbix",
    38: b"acnt",
    39: b"avar",
    40: b"bdat",
    41: b"bloc",
    42: b"bsln",
    43: b"cvar",
    44: b"fdsc",
    45: b"feat",
    46: b"fmtx",
    47: b"fvar",
    48: b"gvar",
    49: b"hsty",
    50: b"just",
    51: b"lcar",
    52: b"mort",
    53: b"morx",
    54: b"opbd",
    55: b"prop",
    56: b"trak",
    57: b"Zapf",
    58: b"Silf",
    59: b"Glat",
    60: b"Gloc",
    61: b"Feat",
    62: b"Sill",
}
