"""Test PKI infrastructure for C2PA conformance testing.

Generates a complete certificate hierarchy for testing cryptographic
validation rules without relying on real CAs or network access.

Hierarchy:
    Test Root CA (self-signed, RSA-4096)
      +-- Test Intermediate CA (RSA-2048)
            +-- Valid Signer (EC P-256, C2PA EKU)
            +-- Expired Signer (EC P-256, expired yesterday)
            +-- Wrong-EKU Signer (EC P-256, serverAuth EKU only)
            +-- Revoked Signer (EC P-256, OCSP status: revoked)
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# C2PA uses id-kp-documentSigning (1.3.6.1.5.5.7.3.36) but falls back
# to emailProtection in practice.  We use documentSigning.
C2PA_EKU_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")

ONE_DAY = datetime.timedelta(days=1)
TEN_YEARS = datetime.timedelta(days=3650)
ONE_YEAR = datetime.timedelta(days=365)


@dataclass
class CertKeyPair:
    """A certificate and its private key."""

    cert: x509.Certificate
    key: CertificateIssuerPrivateKeyTypes
    cert_pem: bytes = b""
    key_pem: bytes = b""

    def save(self, cert_path: Path, key_path: Path) -> None:
        cert_path.write_bytes(self.cert_pem)
        key_path.write_bytes(self.key_pem)


def _serialize(
    cert: x509.Certificate, key: CertificateIssuerPrivateKeyTypes
) -> tuple[bytes, bytes]:
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def generate_root_ca() -> CertKeyPair:
    """Generate a self-signed test root CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2PA Conformance Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem, key_pem = _serialize(cert, key)
    return CertKeyPair(cert=cert, key=key, cert_pem=cert_pem, key_pem=key_pem)


def generate_intermediate_ca(root: CertKeyPair) -> CertKeyPair:
    """Generate a test intermediate CA signed by the root."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2PA Conformance Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + TEN_YEARS)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()),
            critical=False,
        )
        .sign(root.key, hashes.SHA256())
    )

    cert_pem, key_pem = _serialize(cert, key)
    return CertKeyPair(cert=cert, key=key, cert_pem=cert_pem, key_pem=key_pem)


def generate_signer(
    issuer: CertKeyPair,
    common_name: str = "Test Signer",
    eku_oids: list[x509.ObjectIdentifier] | None = None,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
) -> CertKeyPair:
    """Generate a test end-entity signing certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    if not_valid_before is None:
        not_valid_before = now
    if not_valid_after is None:
        not_valid_after = now + ONE_YEAR
    if eku_oids is None:
        eku_oids = [C2PA_EKU_OID]

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2PA Conformance Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(eku_oids),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()),
            critical=False,
        )
    )

    cert = builder.sign(issuer.key, hashes.SHA256())
    cert_pem, key_pem = _serialize(cert, key)
    return CertKeyPair(cert=cert, key=key, cert_pem=cert_pem, key_pem=key_pem)


def generate_test_pki(output_dir: Path) -> dict[str, CertKeyPair]:
    """Generate the complete test PKI hierarchy.

    Creates all certificates needed for conformance testing and saves
    them to the output directory.

    Returns:
        Dict mapping certificate role names to CertKeyPair objects.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    root = generate_root_ca()
    root.save(output_dir / "root_ca.pem", output_dir / "root_ca_key.pem")

    intermediate = generate_intermediate_ca(root)
    intermediate.save(
        output_dir / "intermediate_ca.pem",
        output_dir / "intermediate_ca_key.pem",
    )

    valid_signer = generate_signer(intermediate, common_name="Valid C2PA Signer")
    valid_signer.save(
        output_dir / "valid_signer.pem",
        output_dir / "valid_signer_key.pem",
    )

    expired_signer = generate_signer(
        intermediate,
        common_name="Expired C2PA Signer",
        not_valid_before=now - datetime.timedelta(days=365),
        not_valid_after=now - ONE_DAY,
    )
    expired_signer.save(
        output_dir / "expired_signer.pem",
        output_dir / "expired_signer_key.pem",
    )

    wrong_eku_signer = generate_signer(
        intermediate,
        common_name="Wrong EKU Signer",
        eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    wrong_eku_signer.save(
        output_dir / "wrong_eku_signer.pem",
        output_dir / "wrong_eku_signer_key.pem",
    )

    revoked_signer = generate_signer(intermediate, common_name="Revoked C2PA Signer")
    revoked_signer.save(
        output_dir / "revoked_signer.pem",
        output_dir / "revoked_signer_key.pem",
    )

    # Write trust list (root + intermediate chain)
    chain_pem = intermediate.cert_pem + root.cert_pem
    (output_dir / "trust_chain.pem").write_bytes(chain_pem)

    return {
        "root": root,
        "intermediate": intermediate,
        "valid_signer": valid_signer,
        "expired_signer": expired_signer,
        "wrong_eku_signer": wrong_eku_signer,
        "revoked_signer": revoked_signer,
    }
