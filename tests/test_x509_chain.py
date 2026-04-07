"""Comprehensive tests for X.509 chain validation and trust anchor evaluation."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from c2pa_conformance.crypto.pki import (
    generate_intermediate_ca,
    generate_root_ca,
    generate_signer,
    generate_test_pki,
)
from c2pa_conformance.crypto.trust import TrustAnchorStore, evaluate_trust
from c2pa_conformance.crypto.x509_chain import (
    ChainValidationError,
    order_chain,
    parse_cert_chain,
    validate_basic_constraints,
    validate_chain,
    validate_signer_eku,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Generate the full test PKI hierarchy once per module."""
    return generate_test_pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="module")
def root(pki: dict):  # type: ignore[type-arg]
    return pki["root"]


@pytest.fixture(scope="module")
def intermediate(pki: dict):  # type: ignore[type-arg]
    return pki["intermediate"]


@pytest.fixture(scope="module")
def valid_signer(pki: dict):  # type: ignore[type-arg]
    return pki["valid_signer"]


@pytest.fixture(scope="module")
def expired_signer(pki: dict):  # type: ignore[type-arg]
    return pki["expired_signer"]


@pytest.fixture(scope="module")
def wrong_eku_signer(pki: dict):  # type: ignore[type-arg]
    return pki["wrong_eku_signer"]


# ---------------------------------------------------------------------------
# Helper: build a complete DER chain
# ---------------------------------------------------------------------------


def _chain_der(pki: dict, signer_key: str = "valid_signer") -> list[bytes]:
    """Return DER bytes for signer -> intermediate -> root."""
    return [
        pki[signer_key].cert.public_bytes(serialization.Encoding.DER),
        pki["intermediate"].cert.public_bytes(serialization.Encoding.DER),
        pki["root"].cert.public_bytes(serialization.Encoding.DER),
    ]


def _chain_certs(pki: dict, signer_key: str = "valid_signer") -> list[x509.Certificate]:
    return [pki[signer_key].cert, pki["intermediate"].cert, pki["root"].cert]


# ===========================================================================
# parse_cert_chain
# ===========================================================================


class TestParseCertChain:
    def test_parse_cert_chain_valid(self, pki: dict) -> None:
        der_list = _chain_der(pki)
        certs = parse_cert_chain(der_list)
        assert len(certs) == 3
        assert all(isinstance(c, x509.Certificate) for c in certs)

    def test_parse_cert_chain_invalid_der(self) -> None:
        with pytest.raises(ChainValidationError, match="not valid DER"):
            parse_cert_chain([b"this is not a certificate"])

    def test_parse_cert_chain_empty(self) -> None:
        result = parse_cert_chain([])
        assert result == []

    def test_parse_cert_chain_single(self, pki: dict) -> None:
        der = pki["root"].cert.public_bytes(serialization.Encoding.DER)
        certs = parse_cert_chain([der])
        assert len(certs) == 1


# ===========================================================================
# order_chain
# ===========================================================================


class TestOrderChain:
    def test_order_chain_already_ordered(self, pki: dict) -> None:
        chain = _chain_certs(pki)
        ordered = order_chain(chain)
        assert ordered[0].subject == pki["valid_signer"].cert.subject
        assert ordered[-1].subject == pki["root"].cert.subject

    def test_order_chain_reversed_input(self, pki: dict) -> None:
        # Provide chain in reverse order: root, intermediate, signer
        shuffled = [pki["root"].cert, pki["intermediate"].cert, pki["valid_signer"].cert]
        ordered = order_chain(shuffled)
        assert ordered[0].subject == pki["valid_signer"].cert.subject
        assert ordered[1].subject == pki["intermediate"].cert.subject
        assert ordered[2].subject == pki["root"].cert.subject

    def test_order_chain_middle_first(self, pki: dict) -> None:
        # intermediate, signer, root
        shuffled = [pki["intermediate"].cert, pki["valid_signer"].cert, pki["root"].cert]
        ordered = order_chain(shuffled)
        assert ordered[0].subject == pki["valid_signer"].cert.subject

    def test_order_chain_single_cert(self, pki: dict) -> None:
        ordered = order_chain([pki["root"].cert])
        assert len(ordered) == 1

    def test_order_chain_empty(self) -> None:
        assert order_chain([]) == []


# ===========================================================================
# validate_chain
# ===========================================================================


class TestValidateChain:
    def test_validate_chain_valid(self, pki: dict) -> None:
        chain = _chain_certs(pki)
        result = validate_chain(chain)
        assert result.is_valid is True
        assert result.signer_cert is not None
        assert result.signer_cert.subject == pki["valid_signer"].cert.subject

    def test_validate_chain_expired_signer(self, pki: dict) -> None:
        chain = [pki["expired_signer"].cert, pki["intermediate"].cert, pki["root"].cert]
        result = validate_chain(chain)
        assert result.is_valid is False
        assert "signingCredential.invalid" == result.status_code
        assert "expired" in result.message.lower()

    def test_validate_chain_expired_intermediate(self) -> None:
        """Expired intermediate must fail even if signer is valid."""
        root = generate_root_ca()
        now = datetime.datetime.now(datetime.timezone.utc)
        # Build an intermediate that expired yesterday
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Expired Intermediate"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=30))
            .not_valid_after(now - datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
            .sign(root.key, hashes.SHA256())
        )
        from c2pa_conformance.crypto.pki import CertKeyPair

        expired_int = CertKeyPair(cert=cert, key=key)
        signer = generate_signer(expired_int)
        chain = [signer.cert, cert, root.cert]
        result = validate_chain(chain)
        assert result.is_valid is False
        assert "expired" in result.message.lower()

    def test_validate_chain_broken_signature(self, pki: dict) -> None:
        """A cert not signed by the claimed issuer must fail."""
        # Use wrong_eku_signer but pair it with a different intermediate key
        # by making a fresh root and pairing old signer with new intermediate
        fresh_root = generate_root_ca()
        fresh_int = generate_intermediate_ca(fresh_root)
        # chain: valid_signer cert (signed by original intermediate) -> fresh_int -> fresh_root
        chain = [pki["valid_signer"].cert, fresh_int.cert, fresh_root.cert]
        result = validate_chain(chain)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"
        assert "signature" in result.message.lower()

    def test_validate_chain_single_cert_self_signed(self, pki: dict) -> None:
        """A self-signed root certificate is a valid chain of length 1."""
        chain = [pki["root"].cert]
        result = validate_chain(chain)
        assert result.is_valid is True

    def test_validate_chain_empty(self) -> None:
        result = validate_chain([])
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"


# ===========================================================================
# validate_signer_eku
# ===========================================================================


class TestValidateSignerEku:
    def test_validate_signer_eku_c2pa(self, pki: dict) -> None:
        ok, status = validate_signer_eku(pki["valid_signer"].cert)
        assert ok is True
        assert status == "valid"

    def test_validate_signer_eku_wrong(self, pki: dict) -> None:
        ok, status = validate_signer_eku(pki["wrong_eku_signer"].cert)
        assert ok is False
        assert status == "signingCredential.invalid"

    def test_validate_signer_eku_missing(self) -> None:
        """Certificate with no EKU extension must fail."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No EKU")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "No EKU")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        ok, status = validate_signer_eku(cert)
        assert ok is False
        assert status == "signingCredential.invalid"

    def test_validate_signer_eku_document_signing_fallback(self, pki: dict) -> None:
        """Document signing OID (1.3.6.1.5.5.7.3.3) is accepted as fallback."""
        doc_signing_oid = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.3")
        root = generate_root_ca()
        intermediate = generate_intermediate_ca(root)
        signer = generate_signer(intermediate, eku_oids=[doc_signing_oid])
        ok, status = validate_signer_eku(signer.cert)
        assert ok is True
        assert status == "valid"


# ===========================================================================
# validate_basic_constraints
# ===========================================================================


class TestValidateBasicConstraints:
    def test_ca_cert_must_be_ca_passes(self, pki: dict) -> None:
        ok, _ = validate_basic_constraints(pki["root"].cert, must_be_ca=True)
        assert ok is True

    def test_leaf_cert_must_not_be_ca_passes(self, pki: dict) -> None:
        ok, _ = validate_basic_constraints(pki["valid_signer"].cert, must_be_ca=False)
        assert ok is True

    def test_leaf_cert_when_ca_required_fails(self, pki: dict) -> None:
        ok, status = validate_basic_constraints(pki["valid_signer"].cert, must_be_ca=True)
        assert ok is False
        assert status == "signingCredential.invalid"

    def test_ca_cert_when_non_ca_required_fails(self, pki: dict) -> None:
        ok, status = validate_basic_constraints(pki["root"].cert, must_be_ca=False)
        assert ok is False
        assert status == "signingCredential.invalid"


# ===========================================================================
# TrustAnchorStore
# ===========================================================================


class TestTrustAnchorStore:
    def test_trust_store_from_pem_file(self, pki: dict, tmp_path: Path) -> None:
        pem_path = tmp_path / "roots.pem"
        pem_path.write_bytes(pki["root"].cert_pem)
        store = TrustAnchorStore.from_pem_file(pem_path)
        assert len(store.anchors) == 1

    def test_trust_store_from_pem_bytes_single(self, pki: dict) -> None:
        store = TrustAnchorStore.from_pem_bytes(pki["root"].cert_pem)
        assert len(store.anchors) == 1

    def test_trust_store_from_pem_bytes_multi(self, pki: dict) -> None:
        multi_pem = pki["root"].cert_pem + pki["intermediate"].cert_pem
        store = TrustAnchorStore.from_pem_bytes(multi_pem)
        assert len(store.anchors) == 2

    def test_trust_store_is_trusted_true(self, pki: dict) -> None:
        store = TrustAnchorStore.from_pem_bytes(pki["root"].cert_pem)
        assert store.is_trusted(pki["root"].cert) is True

    def test_trust_store_not_trusted(self, pki: dict) -> None:
        store = TrustAnchorStore.from_pem_bytes(pki["root"].cert_pem)
        # Intermediate is not in the trust store
        assert store.is_trusted(pki["intermediate"].cert) is False

    def test_trust_store_signer_not_trusted(self, pki: dict) -> None:
        store = TrustAnchorStore.from_pem_bytes(pki["root"].cert_pem)
        assert store.is_trusted(pki["valid_signer"].cert) is False


# ===========================================================================
# evaluate_trust
# ===========================================================================


class TestEvaluateTrust:
    def _root_store(self, pki: dict) -> TrustAnchorStore:
        return TrustAnchorStore.from_pem_bytes(pki["root"].cert_pem)

    def test_evaluate_trust_full_success(self, pki: dict) -> None:
        chain = _chain_certs(pki)
        store = self._root_store(pki)
        result = evaluate_trust(chain, store)
        assert result.is_valid is True
        assert result.status_code == "signingCredential.trusted"
        assert result.signer_cert is not None
        assert result.signer_cert.subject == pki["valid_signer"].cert.subject

    def test_evaluate_trust_untrusted(self, pki: dict) -> None:
        """Valid chain but trust store has a different root."""
        fresh_root = generate_root_ca()
        store = TrustAnchorStore.from_pem_bytes(fresh_root.cert_pem)
        chain = _chain_certs(pki)
        result = evaluate_trust(chain, store)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.untrusted"

    def test_evaluate_trust_invalid_chain(self, pki: dict) -> None:
        """Broken chain must return signingCredential.invalid."""
        fresh_root = generate_root_ca()
        fresh_int = generate_intermediate_ca(fresh_root)
        # valid_signer was signed by original intermediate, not fresh_int
        chain = [pki["valid_signer"].cert, fresh_int.cert, fresh_root.cert]
        store = TrustAnchorStore.from_pem_bytes(fresh_root.cert_pem)
        result = evaluate_trust(chain, store)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"

    def test_evaluate_trust_with_validation_time_future(self, pki: dict) -> None:
        """Validating at a time after signer has not yet started must fail."""
        # valid_signer starts at "now"; ask for validity one year before
        past_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=400)
        chain = _chain_certs(pki)
        store = self._root_store(pki)
        result = evaluate_trust(chain, store, validation_time=past_time)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"

    def test_evaluate_trust_with_validation_time_valid_window(self, pki: dict) -> None:
        """Validating inside the certificate window must succeed."""
        # Just a few seconds after now -- all certs were just generated
        valid_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)
        chain = _chain_certs(pki)
        store = self._root_store(pki)
        result = evaluate_trust(chain, store, validation_time=valid_time)
        assert result.is_valid is True
        assert result.status_code == "signingCredential.trusted"

    def test_evaluate_trust_wrong_eku(self, pki: dict) -> None:
        """Valid chain with wrong EKU must return signingCredential.invalid."""
        chain = [pki["wrong_eku_signer"].cert, pki["intermediate"].cert, pki["root"].cert]
        store = self._root_store(pki)
        result = evaluate_trust(chain, store)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"
        assert "EKU" in result.message

    def test_evaluate_trust_expired_signer(self, pki: dict) -> None:
        chain = [pki["expired_signer"].cert, pki["intermediate"].cert, pki["root"].cert]
        store = self._root_store(pki)
        result = evaluate_trust(chain, store)
        assert result.is_valid is False
        assert result.status_code == "signingCredential.invalid"
        assert "expired" in result.message.lower()

    def test_evaluate_trust_revoked_signer_passes_without_ocsp(self, pki: dict) -> None:
        """Revoked signer has no OCSP check yet; chain validation must pass."""
        chain = [pki["revoked_signer"].cert, pki["intermediate"].cert, pki["root"].cert]
        store = self._root_store(pki)
        result = evaluate_trust(chain, store)
        # Without OCSP, the revoked cert looks like a valid cert
        assert result.is_valid is True
        assert result.status_code == "signingCredential.trusted"
