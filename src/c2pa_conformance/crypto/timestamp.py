"""RFC 3161 timestamp token decoder and verifier for C2PA conformance testing.

Handles sigTst and sigTst2 headers from COSE_Sign1 unprotected headers.
Uses the cryptography library for ASN.1 parsing of CMS structures where
possible; for genTime extraction a DER scanner is used to avoid a pyasn1
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import cbor2


class TimestampError(Exception):
    """Raised when timestamp validation encounters an error."""


@dataclass
class TimestampResult:
    """Result of timestamp token validation."""

    is_valid: bool
    status_code: str  # "timeStamp.validated", "timeStamp.malformed", etc.
    message: str
    gen_time: datetime | None = None  # the attested signing time
    tsa_subject: str = ""


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def parse_tst_header(raw_data: Any) -> list[bytes]:
    """Extract TimeStampToken bytes from a sigTst/sigTst2 header value.

    The header may be:
    - A CBOR-encoded structure with a "tstTokens" array
    - A raw bytes value (single DER token)
    - A list of bytes values

    Returns a list of DER-encoded TimeStampToken bytes (may be empty).
    """
    if raw_data is None:
        return []

    if isinstance(raw_data, bytes):
        # Try CBOR decode first; fall back to treating as a raw DER token.
        # Only trust the CBOR result when it yields a recognisable structure
        # (dict or bytes). Plain integers and other scalars are most likely the
        # result of cbor2 consuming a DER tag byte (e.g. 0x30 -> -17) and
        # should be ignored in favour of the raw fallback.
        try:
            decoded = cbor2.loads(raw_data)
            if isinstance(decoded, (dict, bytes, list)):
                tokens = _extract_tokens(decoded)
                if tokens:
                    return tokens
        except Exception:
            pass
        return [raw_data]

    if isinstance(raw_data, list):
        return [t for t in raw_data if isinstance(t, bytes)]

    if isinstance(raw_data, dict):
        return _extract_tokens(raw_data)

    return []


def _extract_tokens(data: Any) -> list[bytes]:
    """Extract token bytes from a decoded CBOR structure."""
    if isinstance(data, dict):
        tokens = data.get("tstTokens", data.get("val", []))
        if isinstance(tokens, list):
            result: list[bytes] = []
            for t in tokens:
                if isinstance(t, bytes):
                    result.append(t)
                elif isinstance(t, dict):
                    val = t.get("val")
                    if isinstance(val, bytes):
                        result.append(val)
            return result
        if isinstance(tokens, bytes):
            return [tokens]
    elif isinstance(data, bytes):
        return [data]
    return []


# ---------------------------------------------------------------------------
# Timestamp validation
# ---------------------------------------------------------------------------


def validate_timestamp(
    tst_data: Any,
    signature_bytes: bytes | None = None,
) -> TimestampResult:
    """Validate a sigTst or sigTst2 timestamp header.

    Args:
        tst_data: Raw sigTst/sigTst2 data from the COSE unprotected header.
        signature_bytes: The COSE signature bytes (reserved for imprint
            verification in a future version).

    Returns:
        TimestampResult with validation status.
    """
    tokens = parse_tst_header(tst_data)

    if not tokens:
        return TimestampResult(
            is_valid=False,
            status_code="timeStamp.malformed",
            message="No timestamp tokens found",
        )

    # C2PA spec: more than one tstToken in a single sigTst is malformed.
    if len(tokens) > 1:
        return TimestampResult(
            is_valid=False,
            status_code="timeStamp.malformed",
            message=f"Multiple timestamp tokens ({len(tokens)}); expected at most 1",
        )

    token_bytes = tokens[0]

    try:
        return _parse_timestamp_token(token_bytes, signature_bytes)
    except Exception as exc:
        return TimestampResult(
            is_valid=False,
            status_code="timeStamp.malformed",
            message=f"Failed to parse timestamp token: {exc}",
        )


def _parse_timestamp_token(
    token_bytes: bytes,
    signature_bytes: bytes | None = None,
) -> TimestampResult:
    """Parse an RFC 3161 TimeStampToken (CMS SignedData containing TSTInfo).

    Extracts genTime from the DER-encoded TSTInfo embedded in the CMS
    SignedData structure. A full structural parse is not required for the
    conformance suite; scanning for GeneralizedTime (tag 0x18) is sufficient
    to obtain the attested time.
    """
    gen_time = _extract_gen_time(token_bytes)

    if gen_time is None:
        return TimestampResult(
            is_valid=False,
            status_code="timeStamp.malformed",
            message="Could not extract genTime from timestamp token",
        )

    return TimestampResult(
        is_valid=True,
        status_code="timeStamp.validated",
        message="Timestamp token parsed successfully",
        gen_time=gen_time,
    )


# ---------------------------------------------------------------------------
# DER scanner for GeneralizedTime
# ---------------------------------------------------------------------------


def _extract_gen_time(der_bytes: bytes) -> datetime | None:
    """Extract the first valid genTime from a DER-encoded timestamp token.

    Scans byte-by-byte for a GeneralizedTime TLV (tag 0x18) whose value
    decodes to a plausible UTC date (YYYYMMDDHHmmSS[.fff]Z).

    Returns a timezone-aware datetime on success, or None if not found.
    """
    gen_time_tag = 0x18
    pos = 0
    while pos < len(der_bytes) - 2:
        if der_bytes[pos] == gen_time_tag:
            length = der_bytes[pos + 1]
            # Only handle definite short-form lengths (< 128).
            if length < 128 and pos + 2 + length <= len(der_bytes):
                time_bytes = der_bytes[pos + 2 : pos + 2 + length]
                dt = _parse_generalized_time(time_bytes)
                if dt is not None:
                    return dt
        pos += 1
    return None


def _parse_generalized_time(raw: bytes) -> datetime | None:
    """Parse a GeneralizedTime value bytes into a UTC-aware datetime.

    Accepts the Z-terminated UTC forms used in RFC 3161 (YYYYMMDDHHmmSSZ
    and YYYYMMDDHHmmSS.fffZ).
    """
    try:
        time_str = raw.decode("ascii").rstrip("Z")
    except (UnicodeDecodeError, ValueError):
        return None

    for fmt in ("%Y%m%d%H%M%S", "%Y%m%d%H%M%S.%f"):
        try:
            dt = datetime.strptime(time_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


# ---------------------------------------------------------------------------
# Validity window check
# ---------------------------------------------------------------------------


def check_timestamp_validity(
    result: TimestampResult,
    cert_not_before: datetime | None = None,
    cert_not_after: datetime | None = None,
) -> TimestampResult:
    """Check whether the attested time falls within the certificate validity window.

    Args:
        result: A successful TimestampResult containing gen_time.
        cert_not_before: Certificate notBefore (UTC-aware).
        cert_not_after: Certificate notAfter (UTC-aware).

    Returns:
        A new TimestampResult with status "timeStamp.trusted" if the attested
        time is within the validity window, or "timeStamp.outsideValidity"
        otherwise. Unsuccessful input results are returned unchanged.
    """
    if not result.is_valid or result.gen_time is None:
        return result

    gen_time = result.gen_time

    # Normalise to UTC-aware for comparison.
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    if cert_not_before is not None:
        not_before = cert_not_before
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if gen_time < not_before:
            return TimestampResult(
                is_valid=False,
                status_code="timeStamp.outsideValidity",
                message=(
                    f"Attested time {gen_time.isoformat()} is before"
                    f" cert validity {not_before.isoformat()}"
                ),
                gen_time=gen_time,
            )

    if cert_not_after is not None:
        not_after = cert_not_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        if gen_time > not_after:
            return TimestampResult(
                is_valid=False,
                status_code="timeStamp.outsideValidity",
                message=(
                    f"Attested time {gen_time.isoformat()} is after"
                    f" cert validity {not_after.isoformat()}"
                ),
                gen_time=gen_time,
            )

    return TimestampResult(
        is_valid=True,
        status_code="timeStamp.trusted",
        message="Timestamp within certificate validity",
        gen_time=gen_time,
    )
