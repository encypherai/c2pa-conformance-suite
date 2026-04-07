"""X.509 certificate chain builder and validator for C2PA conformance testing.

Validates that a certificate chain is well-formed, each signature is correct,
validity periods are in bounds, BasicConstraints and KeyUsage are appropriate,
and the chain terminates at a trusted anchor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from c2pa_conformance.crypto.pki import C2PA_EKU_OID

# id-kp-documentSigning (1.3.6.1.5.5.7.3.3) is accepted as a fallback
_DOCUMENT_SIGNING_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3")


@dataclass
class ChainValidationResult:
    """Result of a certificate chain validation."""

    is_valid: bool
    status_code: str  # e.g. "signingCredential.trusted", "signingCredential.invalid"
    message: str
    chain: list[x509.Certificate] = field(default_factory=list)
    signer_cert: x509.Certificate | None = None


class ChainValidationError(Exception):
    """Raised when a certificate chain cannot be validated."""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_cert_chain(der_certs: list[bytes]) -> list[x509.Certificate]:
    """Parse a list of DER-encoded certificates.

    Args:
        der_certs: DER-encoded X.509 certificates, signer first.

    Returns:
        Parsed Certificate objects in the same order as the input.

    Raises:
        ChainValidationError: If any certificate cannot be parsed.
    """
    result: list[x509.Certificate] = []
    for i, der in enumerate(der_certs):
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:
            raise ChainValidationError(f"Certificate {i} is not valid DER: {exc}") from exc
        result.append(cert)
    return result


# ---------------------------------------------------------------------------
# Chain ordering
# ---------------------------------------------------------------------------


def order_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """Order certificates from leaf (signer) to root.

    Handles unordered input by matching each certificate's issuer to
    another certificate's subject.  The leaf is the certificate whose
    subject does not appear as another certificate's issuer.

    Args:
        certs: Unordered list of X.509 certificates.

    Returns:
        List ordered signer -> intermediate(s) -> root.

    Raises:
        ChainValidationError: If the chain cannot be ordered (e.g., cycle or gap).
    """
    if not certs:
        return []
    if len(certs) == 1:
        return list(certs)

    # Build a subject -> cert map
    by_subject: dict[bytes, x509.Certificate] = {}
    for cert in certs:
        key = cert.subject.public_bytes()
        by_subject[key] = cert

    # The leaf is a cert whose subject is not the issuer of any other cert
    issuer_keys = {cert.issuer.public_bytes() for cert in certs}
    leaves = [c for c in certs if c.subject.public_bytes() not in issuer_keys]

    if len(leaves) != 1:
        raise ChainValidationError(f"Expected exactly one leaf certificate, found {len(leaves)}")

    ordered: list[x509.Certificate] = []
    current = leaves[0]
    visited: set[bytes] = set()

    while True:
        subject_key = current.subject.public_bytes()
        if subject_key in visited:
            raise ChainValidationError("Certificate chain contains a cycle")
        visited.add(subject_key)
        ordered.append(current)

        issuer_key = current.issuer.public_bytes()
        if issuer_key == subject_key:
            # Self-signed: end of chain
            break
        parent = by_subject.get(issuer_key)
        if parent is None:
            # No more certs available - chain is complete up to this point
            break
        current = parent

    return ordered


# ---------------------------------------------------------------------------
# Signature verification helpers
# ---------------------------------------------------------------------------


def _verify_cert_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> None:
    """Verify that `cert` was signed by `issuer_cert`.

    Raises:
        ChainValidationError: If the signature is invalid or the key type is unsupported.
    """
    issuer_key = issuer_cert.public_key()
    hash_alg = cert.signature_hash_algorithm
    if hash_alg is None:
        raise ChainValidationError("Certificate has no signature hash algorithm")

    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg,
            )
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(hash_alg),
            )
        else:
            raise ChainValidationError(f"Unsupported issuer key type: {type(issuer_key).__name__}")
    except InvalidSignature as exc:
        raise ChainValidationError(
            f"Signature verification failed for '{cert.subject.rfc4514_string()}': {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Individual certificate checks
# ---------------------------------------------------------------------------


def validate_basic_constraints(cert: x509.Certificate, must_be_ca: bool) -> tuple[bool, str]:
    """Check BasicConstraints on a certificate.

    Args:
        cert: The certificate to check.
        must_be_ca: True if CA=True is required (intermediate/root), False for leaf.

    Returns:
        (True, "valid") on success, (False, "signingCredential.invalid") on failure.
    """
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        if must_be_ca:
            return False, "signingCredential.invalid"
        # Leaf without BasicConstraints is acceptable
        return True, "valid"

    bc: x509.BasicConstraints = ext.value
    if must_be_ca and not bc.ca:
        return False, "signingCredential.invalid"
    if not must_be_ca and bc.ca:
        return False, "signingCredential.invalid"
    return True, "valid"


def validate_signer_eku(cert: x509.Certificate) -> tuple[bool, str]:
    """Check that the signer certificate carries the C2PA EKU.

    Accepts:
    - C2PA EKU OID (1.3.6.1.5.5.7.3.36)
    - Document signing OID (1.3.6.1.5.5.7.3.3) as a fallback

    Args:
        cert: The leaf signing certificate.

    Returns:
        (True, "valid") on success, (False, "signingCredential.invalid") on failure.
    """
    try:
        ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False, "signingCredential.invalid"

    eku: x509.ExtendedKeyUsage = ext.value
    oids = list(eku)
    if C2PA_EKU_OID in oids or _DOCUMENT_SIGNING_OID in oids:
        return True, "valid"
    return False, "signingCredential.invalid"


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


def validate_chain(
    chain: list[x509.Certificate],
    validation_time: datetime | None = None,
) -> ChainValidationResult:
    """Validate a certificate chain (signatures, validity periods, constraints).

    Does NOT check trust anchors - use evaluate_trust() for a full check.

    Args:
        chain: Ordered list of certificates, signer first, root last.
        validation_time: UTC time to use for validity checks. Defaults to now.

    Returns:
        ChainValidationResult with is_valid=True when all checks pass.
    """
    if not chain:
        return ChainValidationResult(
            is_valid=False,
            status_code="signingCredential.invalid",
            message="Empty certificate chain",
        )

    if validation_time is None:
        validation_time = datetime.now(timezone.utc)

    signer = chain[0]

    # -----------------------------------------------------------------------
    # Validate each consecutive pair: (cert, its issuer)
    # -----------------------------------------------------------------------
    for i, cert in enumerate(chain):
        subject_dn = cert.subject.rfc4514_string()

        # Validity period
        if cert.not_valid_before_utc > validation_time:
            return ChainValidationResult(
                is_valid=False,
                status_code="signingCredential.invalid",
                message=f"Certificate '{subject_dn}' is not yet valid",
                chain=chain,
                signer_cert=signer,
            )
        if cert.not_valid_after_utc < validation_time:
            return ChainValidationResult(
                is_valid=False,
                status_code="signingCredential.invalid",
                message=f"Certificate '{subject_dn}' has expired",
                chain=chain,
                signer_cert=signer,
            )

        is_last = i == len(chain) - 1

        if not is_last:
            issuer_cert = chain[i + 1]
            issuer_dn = issuer_cert.subject.rfc4514_string()

            # Signature
            try:
                _verify_cert_signature(cert, issuer_cert)
            except ChainValidationError as exc:
                return ChainValidationResult(
                    is_valid=False,
                    status_code="signingCredential.invalid",
                    message=str(exc),
                    chain=chain,
                    signer_cert=signer,
                )

            # Issuer must be a CA with keyCertSign
            ok, _ = validate_basic_constraints(issuer_cert, must_be_ca=True)
            if not ok:
                return ChainValidationResult(
                    is_valid=False,
                    status_code="signingCredential.invalid",
                    message=(f"Issuer '{issuer_dn}' does not have BasicConstraints CA=True"),
                    chain=chain,
                    signer_cert=signer,
                )

            try:
                ku_ext = issuer_cert.extensions.get_extension_for_class(x509.KeyUsage)
                if not ku_ext.value.key_cert_sign:
                    return ChainValidationResult(
                        is_valid=False,
                        status_code="signingCredential.invalid",
                        message=f"Issuer '{issuer_dn}' does not have keyCertSign",
                        chain=chain,
                        signer_cert=signer,
                    )
            except x509.ExtensionNotFound:
                # KeyUsage extension not present; keyCertSign cannot be verified
                return ChainValidationResult(
                    is_valid=False,
                    status_code="signingCredential.invalid",
                    message=f"Issuer '{issuer_dn}' is missing KeyUsage extension",
                    chain=chain,
                    signer_cert=signer,
                )
        else:
            # Last cert: if self-signed, verify its own signature
            if cert.issuer == cert.subject:
                try:
                    _verify_cert_signature(cert, cert)
                except ChainValidationError as exc:
                    return ChainValidationResult(
                        is_valid=False,
                        status_code="signingCredential.invalid",
                        message=str(exc),
                        chain=chain,
                        signer_cert=signer,
                    )

    return ChainValidationResult(
        is_valid=True,
        status_code="signingCredential.valid",
        message="Chain validation passed",
        chain=chain,
        signer_cert=signer,
    )
