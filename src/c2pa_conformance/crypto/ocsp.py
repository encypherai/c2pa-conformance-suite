"""OCSP response parser and stapled validation for C2PA conformance testing.

Parses DER-encoded OCSP responses from the COSE rVals header and validates
certificate revocation status.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509 import ocsp


class OcspError(Exception):
    """Raised when OCSP validation encounters an error."""


@dataclass
class OcspResult:
    """Result of OCSP revocation check."""

    status: str  # "notRevoked", "revoked", "unknown", "malformed", "skipped"
    status_code: str  # C2PA status code
    message: str
    cert_status: str = ""  # "good", "revoked", "unknown"
    revocation_reason: str = ""
    this_update: datetime | None = None
    next_update: datetime | None = None


def parse_ocsp_response(der_bytes: bytes) -> OcspResult:
    """Parse and validate a DER-encoded OCSP response.

    Returns an OcspResult describing the certificate status.
    """
    try:
        resp = ocsp.load_der_ocsp_response(der_bytes)
    except Exception as exc:
        return OcspResult(
            status="malformed",
            status_code="signingCredential.ocsp.malformed",
            message=f"Failed to parse OCSP response: {exc}",
        )

    # Check response status.
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OcspResult(
            status="malformed",
            status_code="signingCredential.ocsp.malformed",
            message=f"OCSP response status: {resp.response_status.name}",
        )

    # Extract certificate status.
    cert_status = resp.certificate_status
    this_update = resp.this_update_utc
    next_update = resp.next_update_utc

    if cert_status == ocsp.OCSPCertStatus.GOOD:
        return OcspResult(
            status="notRevoked",
            status_code="signingCredential.ocsp.notRevoked",
            message="Certificate is not revoked",
            cert_status="good",
            this_update=this_update,
            next_update=next_update,
        )

    if cert_status == ocsp.OCSPCertStatus.REVOKED:
        reason = ""
        if resp.revocation_reason is not None:
            reason = resp.revocation_reason.name

        # removeFromCRL means the certificate is no longer revoked.
        if reason == "remove_from_crl":
            return OcspResult(
                status="notRevoked",
                status_code="signingCredential.ocsp.notRevoked",
                message="Certificate revocation removed (removeFromCRL)",
                cert_status="revoked",
                revocation_reason=reason,
                this_update=this_update,
                next_update=next_update,
            )

        return OcspResult(
            status="revoked",
            status_code="signingCredential.ocsp.revoked",
            message=f"Certificate is revoked (reason: {reason or 'unspecified'})",
            cert_status="revoked",
            revocation_reason=reason,
            this_update=this_update,
            next_update=next_update,
        )

    # OCSPCertStatus.UNKNOWN
    return OcspResult(
        status="unknown",
        status_code="signingCredential.ocsp.unknown",
        message="Certificate status is unknown",
        cert_status="unknown",
        this_update=this_update,
        next_update=next_update,
    )


def validate_ocsp_freshness(
    result: OcspResult,
    validation_time: datetime | None = None,
) -> bool:
    """Check if an OCSP response is still valid (not expired).

    Returns True if the response is fresh, i.e. validation_time falls
    between thisUpdate and nextUpdate (inclusive).
    """
    if validation_time is None:
        validation_time = datetime.now(timezone.utc)

    if result.this_update is not None:
        # Normalise to UTC-aware for comparison.
        this_update = result.this_update
        if this_update.tzinfo is None:
            this_update = this_update.replace(tzinfo=timezone.utc)
        if validation_time < this_update:
            return False

    if result.next_update is not None:
        next_update = result.next_update
        if next_update.tzinfo is None:
            next_update = next_update.replace(tzinfo=timezone.utc)
        if validation_time > next_update:
            return False

    return True


def check_revocation(
    rvals_data: Any,
    signer_cert: x509.Certificate | None = None,
) -> OcspResult:
    """Check revocation status from COSE rVals data.

    The rVals field in a COSE unprotected header may contain:
    - A single DER-encoded OCSP response (bytes)
    - A list of DER-encoded OCSP responses
    - A dict with an "ocspVals" key containing a list

    Tries each OCSP response in order and returns the first notRevoked result.
    Falls back to the last result if none pass.
    """
    if rvals_data is None:
        return OcspResult(
            status="skipped",
            status_code="signingCredential.ocsp.skipped",
            message="No revocation values present",
        )

    # Normalise to a flat list of bytes.
    ocsp_responses: list[bytes] = []

    if isinstance(rvals_data, bytes):
        ocsp_responses = [rvals_data]
    elif isinstance(rvals_data, list):
        ocsp_responses = [r for r in rvals_data if isinstance(r, bytes)]
    elif isinstance(rvals_data, dict):
        vals = rvals_data.get("ocspVals", rvals_data.get("ocsp", []))
        if isinstance(vals, list):
            ocsp_responses = [r for r in vals if isinstance(r, bytes)]
        elif isinstance(vals, bytes):
            ocsp_responses = [vals]

    if not ocsp_responses:
        return OcspResult(
            status="skipped",
            status_code="signingCredential.ocsp.skipped",
            message="No OCSP responses found in rVals",
        )

    last_result: OcspResult | None = None
    for resp_bytes in ocsp_responses:
        result = parse_ocsp_response(resp_bytes)
        last_result = result
        if result.status == "notRevoked":
            return result

    # last_result is always set here because ocsp_responses is non-empty.
    assert last_result is not None
    return last_result
