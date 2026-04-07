"""Tests for the test PKI infrastructure."""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from c2pa_conformance.crypto.pki import (
    C2PA_EKU_OID,
    generate_intermediate_ca,
    generate_root_ca,
    generate_signer,
    generate_test_pki,
)


class TestRootCA:
    def test_is_self_signed(self) -> None:
        root = generate_root_ca()
        assert root.cert.issuer == root.cert.subject

    def test_is_ca(self) -> None:
        root = generate_root_ca()
        bc = root.cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_key_usage(self) -> None:
        root = generate_root_ca()
        ku = root.cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True


class TestIntermediateCA:
    def test_signed_by_root(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        assert intermediate.cert.issuer == root.cert.subject

    def test_is_ca(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        bc = intermediate.cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.value.path_length == 0


class TestSigner:
    def test_valid_signer_has_c2pa_eku(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        signer = generate_signer(intermediate)
        eku = signer.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert C2PA_EKU_OID in eku.value

    def test_valid_signer_is_not_ca(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        signer = generate_signer(intermediate)
        bc = signer.cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_expired_signer(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        now = datetime.datetime.now(datetime.timezone.utc)
        signer = generate_signer(
            intermediate,
            not_valid_before=now - datetime.timedelta(days=30),
            not_valid_after=now - datetime.timedelta(days=1),
        )
        assert signer.cert.not_valid_after_utc < now

    def test_wrong_eku_signer(self) -> None:
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        signer = generate_signer(intermediate, eku_oids=[ExtendedKeyUsageOID.SERVER_AUTH])
        eku = signer.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert C2PA_EKU_OID not in eku.value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value


class TestGenerateTestPKI:
    def test_generates_all_certs(self, tmp_path: Path) -> None:
        certs = generate_test_pki(tmp_path)
        assert "root" in certs
        assert "intermediate" in certs
        assert "valid_signer" in certs
        assert "expired_signer" in certs
        assert "wrong_eku_signer" in certs
        assert "revoked_signer" in certs

    def test_files_written(self, tmp_path: Path) -> None:
        generate_test_pki(tmp_path)
        assert (tmp_path / "root_ca.pem").exists()
        assert (tmp_path / "root_ca_key.pem").exists()
        assert (tmp_path / "intermediate_ca.pem").exists()
        assert (tmp_path / "valid_signer.pem").exists()
        assert (tmp_path / "valid_signer_key.pem").exists()
        assert (tmp_path / "trust_chain.pem").exists()

    def test_trust_chain_contains_both(self, tmp_path: Path) -> None:
        generate_test_pki(tmp_path)
        chain = (tmp_path / "trust_chain.pem").read_text()
        assert chain.count("BEGIN CERTIFICATE") == 2
