"""Trust anchor store and chain trust evaluation for C2PA conformance testing.

Provides TrustAnchorStore for loading and querying trusted root certificates,
and evaluate_trust() as the primary entry point for full chain validation plus
trust anchor verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from c2pa_conformance.crypto.x509_chain import (
    ChainValidationResult,
    validate_chain,
    validate_signer_eku,
)


@dataclass
class TrustAnchorStore:
    """An in-memory collection of trusted root (anchor) certificates."""

    anchors: list[x509.Certificate] = field(default_factory=list)

    @classmethod
    def from_pem_file(cls, path: Path) -> TrustAnchorStore:
        """Load trust anchors from a PEM file (may contain multiple certificates).

        Args:
            path: Filesystem path to a PEM file.

        Returns:
            A TrustAnchorStore populated with all certificates found in the file.
        """
        pem_data = path.read_bytes()
        return cls.from_pem_bytes(pem_data)

    @classmethod
    def from_pem_bytes(cls, pem_data: bytes) -> TrustAnchorStore:
        """Load trust anchors from PEM bytes (may contain multiple certificates).

        Args:
            pem_data: Raw PEM bytes, potentially containing multiple certificates.

        Returns:
            A TrustAnchorStore populated with all certificates found.
        """
        anchors: list[x509.Certificate] = []
        # Split on PEM boundaries to handle multi-cert PEM blobs
        pem_str = pem_data.decode("ascii", errors="replace")
        sections = pem_str.split("-----BEGIN CERTIFICATE-----")
        for section in sections[1:]:
            end = section.find("-----END CERTIFICATE-----")
            if end == -1:
                continue
            pem_block = (
                "-----BEGIN CERTIFICATE-----" + section[: end + len("-----END CERTIFICATE-----")]
            )
            cert = x509.load_pem_x509_certificate(pem_block.encode("ascii"))
            anchors.append(cert)
        return cls(anchors=anchors)

    def is_trusted(self, cert: x509.Certificate) -> bool:
        """Check whether a certificate is in the trust store.

        Matching is done by subject name and public key, not serial number,
        so a re-issued anchor with the same key still matches.

        Args:
            cert: The certificate to check.

        Returns:
            True if the certificate's subject and public key match any anchor.
        """
        cert_subject = cert.subject.public_bytes()
        cert_pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        for anchor in self.anchors:
            if anchor.subject.public_bytes() != cert_subject:
                continue
            anchor_pub = anchor.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            if cert_pub == anchor_pub:
                return True
        return False


def _bundled_trust_list_path() -> Path:
    """Return the path to the bundled C2PA trust list PEM."""
    return Path(__file__).parent.parent / "data" / "c2pa_trust_list.pem"


def default_trust_store() -> TrustAnchorStore | None:
    """Load the bundled C2PA trust list as a TrustAnchorStore.

    Returns None if the bundled file is missing (e.g., development builds).
    """
    path = _bundled_trust_list_path()
    if not path.exists():
        return None
    return TrustAnchorStore.from_pem_file(path)


def evaluate_trust(
    chain: list[x509.Certificate],
    trust_store: TrustAnchorStore,
    validation_time: datetime | None = None,
) -> ChainValidationResult:
    """Perform full chain validation and trust anchor evaluation.

    Steps:
    1. Validate chain signatures, validity periods, and constraints.
    2. Verify the chain terminates at a certificate in the trust store.
    3. Validate the signer certificate's Extended Key Usage.

    Args:
        chain: Ordered list of certificates, signer first, root last.
        trust_store: Trust anchor store to check against.
        validation_time: UTC datetime for validity checks. Defaults to now.

    Returns:
        ChainValidationResult with status_code one of:
        - "signingCredential.trusted"   -- all checks passed
        - "signingCredential.untrusted" -- chain valid but no matching trust anchor
        - "signingCredential.invalid"   -- chain validation or EKU failure
    """
    # Step 1: structural and cryptographic chain validation
    chain_result = validate_chain(chain, validation_time=validation_time)
    if not chain_result.is_valid:
        return ChainValidationResult(
            is_valid=False,
            status_code="signingCredential.invalid",
            message=chain_result.message,
            chain=chain,
            signer_cert=chain[0] if chain else None,
        )

    signer = chain[0]

    # Step 2: EKU check on the signer
    eku_ok, eku_status = validate_signer_eku(signer)
    if not eku_ok:
        return ChainValidationResult(
            is_valid=False,
            status_code="signingCredential.invalid",
            message=(
                f"Signer '{signer.subject.rfc4514_string()}' does not carry a valid C2PA EKU"
            ),
            chain=chain,
            signer_cert=signer,
        )

    # Step 3: trust anchor check (any cert in the chain may be a trust anchor,
    # but the root is the natural terminus)
    for cert in chain:
        if trust_store.is_trusted(cert):
            return ChainValidationResult(
                is_valid=True,
                status_code="signingCredential.trusted",
                message="Chain is valid and terminates at a trusted anchor",
                chain=chain,
                signer_cert=signer,
            )

    return ChainValidationResult(
        is_valid=False,
        status_code="signingCredential.untrusted",
        message="Chain is valid but does not terminate at a trusted anchor",
        chain=chain,
        signer_cert=signer,
    )
