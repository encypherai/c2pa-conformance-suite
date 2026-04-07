"""Integration tests for the crypto verification pipeline.

Exercises the full verify_manifest_signature / verify_manifest_binding /
build_crypto_context pipeline using the test PKI infrastructure.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from c2pa_conformance.crypto.pki import generate_test_pki
from c2pa_conformance.crypto.trust import TrustAnchorStore
from c2pa_conformance.crypto.verifier import (
    VerificationResult,
    build_crypto_context,
    verify_manifest_binding,
    verify_manifest_signature,
)
from c2pa_conformance.parser.manifest import Assertion, Claim, Manifest

# ---------------------------------------------------------------------------
# Session-scoped PKI fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Generate a complete test PKI hierarchy for the session."""
    output_dir = tmp_path_factory.mktemp("pki_integration")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="session")
def root_trust_store(pki: dict) -> TrustAnchorStore:
    """TrustAnchorStore backed by the test root CA."""
    root_pem = pki["root"].cert_pem
    return TrustAnchorStore.from_pem_bytes(root_pem)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raw_ec_signature(private_key, data: bytes) -> bytes:
    """Sign data with EC P-256 and return raw r||s (COSE ES256 format)."""
    der_sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    key_size = (private_key.key_size + 7) // 8
    return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")


def _sign_claim(claim_bytes: bytes, private_key, cert_der: bytes, alg_id: int = -7) -> bytes:
    """Build COSE_Sign1 bytes for testing (ES256 only via alg_id=-7)."""
    protected = cbor2.dumps({1: alg_id, "x5chain": [cert_der]})
    # Build Sig_structure using re-encoded protected header (mirrors verifier behaviour)
    protected_decoded = cbor2.loads(protected)
    protected_reencoded = cbor2.dumps(protected_decoded)
    # C2PA: empty external_aad, claim bytes as payload
    sig_structure = cbor2.dumps(["Signature1", protected_reencoded, b"", claim_bytes])
    signature = _raw_ec_signature(private_key, sig_structure)
    unprotected: dict = {}
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, None, signature]))


def _make_manifest(
    signature_bytes: bytes,
    claim_data: dict | None = None,
    assertions: list[Assertion] | None = None,
) -> Manifest:
    """Build a minimal Manifest for testing."""
    claim_data = claim_data or {"claim_generator": "test"}
    claim = Claim(data=claim_data, raw_cbor=cbor2.dumps(claim_data))
    return Manifest(
        label="test:manifest",
        claim=claim,
        assertions=assertions or [],
        signature_bytes=signature_bytes,
    )


def _make_hash_data_assertion(asset_bytes: bytes, alg: str = "sha256") -> Assertion:
    """Build a c2pa.hash.data assertion with the correct hash of asset_bytes."""
    import hashlib

    digest = hashlib.new(alg, asset_bytes).digest()
    data: dict = {"alg": alg, "hash": digest, "exclusions": []}
    return Assertion(
        label="c2pa.hash.data",
        data=data,
        raw_cbor=cbor2.dumps(data),
    )


# ---------------------------------------------------------------------------
# 1. verify_manifest_signature -- valid signature
# ---------------------------------------------------------------------------


class TestVerifyManifestSignatureValid:
    def test_signature_valid(self, pki: dict) -> None:
        signer = pki["valid_signer"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        claim_data: dict = {"claim_generator": "test/1.0"}
        claim_cbor = cbor2.dumps(claim_data)
        sig_bytes = _sign_claim(claim_cbor, signer.key, cert_der)

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest)

        assert result.signature_valid is True
        assert result.signature_status == "claimSignature.validated"
        assert result.algorithm_name == "ES256"
        assert result.algorithm_allowed is True
        assert result.cose_signature is not None

    def test_signature_valid_with_chain_status(self, pki: dict) -> None:
        signer = pki["valid_signer"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        claim_data: dict = {"claim_generator": "test/1.0"}
        claim_cbor = cbor2.dumps(claim_data)
        sig_bytes = _sign_claim(claim_cbor, signer.key, cert_der)

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest)

        # Without trust store, chain is validated but untrusted
        assert result.signature_valid is True
        assert result.trust_status == "signingCredential.untrusted"


# ---------------------------------------------------------------------------
# 2. verify_manifest_signature -- missing signature
# ---------------------------------------------------------------------------


class TestVerifyManifestSignatureNoSignature:
    def test_empty_signature_bytes(self) -> None:
        manifest = _make_manifest(b"")
        result = verify_manifest_signature(manifest)

        assert result.signature_valid is False
        assert result.signature_status == "claimSignature.missing"
        assert "No signature bytes" in result.signature_message

    def test_zero_length_signature_bytes(self) -> None:
        manifest = Manifest(
            label="test:manifest",
            claim=Claim(data={}, raw_cbor=b""),
            assertions=[],
            signature_bytes=b"",
        )
        result = verify_manifest_signature(manifest)

        assert result.signature_status == "claimSignature.missing"


# ---------------------------------------------------------------------------
# 3. verify_manifest_signature -- expired cert
# ---------------------------------------------------------------------------


class TestVerifyManifestSignatureExpiredCert:
    def test_expired_signer_fails_chain_validation(self, pki: dict) -> None:
        signer = pki["expired_signer"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        claim_data: dict = {"claim_generator": "expired/1.0"}
        claim_cbor = cbor2.dumps(claim_data)
        sig_bytes = _sign_claim(claim_cbor, signer.key, cert_der)

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest)

        # Signature itself may verify, but chain validation should fail (expired)
        assert result.chain_status == "signingCredential.invalid"
        assert result.chain_valid is False


# ---------------------------------------------------------------------------
# 4. verify_manifest_signature -- wrong EKU
# ---------------------------------------------------------------------------


class TestVerifyManifestSignatureWrongEku:
    def test_wrong_eku_fails(self, pki: dict, root_trust_store: TrustAnchorStore) -> None:
        signer = pki["wrong_eku_signer"]
        intermediate = pki["intermediate"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        intermediate_der = intermediate.cert.public_bytes(serialization.Encoding.DER)

        claim_data: dict = {"claim_generator": "wrong_eku/1.0"}
        claim_cbor = cbor2.dumps(claim_data)

        # Build COSE with both signer and intermediate in x5chain
        protected = cbor2.dumps({1: -7, "x5chain": [cert_der, intermediate_der]})
        protected_decoded = cbor2.loads(protected)
        protected_reencoded = cbor2.dumps(protected_decoded)
        sig_structure = cbor2.dumps(["Signature1", protected_reencoded, b"", claim_cbor])
        signature = _raw_ec_signature(signer.key, sig_structure)
        unprotected: dict = {}
        sig_bytes = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, None, signature]))

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest, trust_store=root_trust_store)

        assert result.chain_valid is False
        assert result.chain_status == "signingCredential.invalid"


# ---------------------------------------------------------------------------
# 5. verify_manifest_signature -- with trust store (trusted)
# ---------------------------------------------------------------------------


class TestVerifyManifestWithTrustStore:
    def test_trusted_chain(self, pki: dict, root_trust_store: TrustAnchorStore) -> None:
        signer = pki["valid_signer"]
        intermediate = pki["intermediate"]
        root = pki["root"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        intermediate_der = intermediate.cert.public_bytes(serialization.Encoding.DER)
        root_der = root.cert.public_bytes(serialization.Encoding.DER)

        claim_data: dict = {"claim_generator": "trusted/1.0"}
        claim_cbor = cbor2.dumps(claim_data)

        # Include full chain: signer + intermediate + root in x5chain
        protected = cbor2.dumps({1: -7, "x5chain": [cert_der, intermediate_der, root_der]})
        protected_decoded = cbor2.loads(protected)
        protected_reencoded = cbor2.dumps(protected_decoded)
        sig_structure = cbor2.dumps(["Signature1", protected_reencoded, b"", claim_cbor])
        signature = _raw_ec_signature(signer.key, sig_structure)
        unprotected: dict = {}
        sig_bytes = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, None, signature]))

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest, trust_store=root_trust_store)

        assert result.signature_valid is True
        assert result.chain_valid is True
        assert result.trust_status == "signingCredential.trusted"


# ---------------------------------------------------------------------------
# 6. verify_manifest_signature -- without trust store (untrusted)
# ---------------------------------------------------------------------------


class TestVerifyManifestWithoutTrustStore:
    def test_no_trust_store_gives_untrusted(self, pki: dict) -> None:
        signer = pki["valid_signer"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        claim_data: dict = {"claim_generator": "untrusted/1.0"}
        claim_cbor = cbor2.dumps(claim_data)
        sig_bytes = _sign_claim(claim_cbor, signer.key, cert_der)

        manifest = _make_manifest(sig_bytes, claim_data)
        result = verify_manifest_signature(manifest, trust_store=None)

        assert result.signature_valid is True
        assert result.trust_status == "signingCredential.untrusted"
        assert result.chain_valid is True  # structural chain validation still passes


# ---------------------------------------------------------------------------
# 7. verify_manifest_binding -- data hash match
# ---------------------------------------------------------------------------


class TestVerifyBindingDataHashMatch:
    def test_hash_match(self) -> None:
        asset_bytes = b"Hello, C2PA conformance testing!"
        hash_assertion = _make_hash_data_assertion(asset_bytes)
        manifest = _make_manifest(b"", assertions=[hash_assertion])

        result = verify_manifest_binding(manifest, asset_bytes)

        assert result.hash_valid is True
        assert result.hash_status == "assertion.dataHash.match"

    def test_hash_match_with_real_asset(self) -> None:
        asset_bytes = b"\x00" * 1024  # Simulated binary asset
        hash_assertion = _make_hash_data_assertion(asset_bytes)
        manifest = _make_manifest(b"", assertions=[hash_assertion])

        result = verify_manifest_binding(manifest, asset_bytes)

        assert result.hash_valid is True
        assert result.hash_status == "assertion.dataHash.match"


# ---------------------------------------------------------------------------
# 8. verify_manifest_binding -- data hash mismatch (tampered asset)
# ---------------------------------------------------------------------------


class TestVerifyBindingDataHashMismatch:
    def test_tampered_asset_fails(self) -> None:
        original_bytes = b"Original asset content"
        tampered_bytes = b"Tampered asset content!"
        hash_assertion = _make_hash_data_assertion(original_bytes)
        manifest = _make_manifest(b"", assertions=[hash_assertion])

        result = verify_manifest_binding(manifest, tampered_bytes)

        assert result.hash_valid is False
        assert result.hash_status == "assertion.dataHash.mismatch"

    def test_single_byte_change_fails(self) -> None:
        original_bytes = b"abcdef"
        tampered_bytes = b"abcdeX"
        hash_assertion = _make_hash_data_assertion(original_bytes)
        manifest = _make_manifest(b"", assertions=[hash_assertion])

        result = verify_manifest_binding(manifest, tampered_bytes)

        assert result.hash_valid is False
        assert result.hash_status == "assertion.dataHash.mismatch"


# ---------------------------------------------------------------------------
# 9. verify_manifest_binding -- no hard binding assertion
# ---------------------------------------------------------------------------


class TestVerifyBindingNoHardBinding:
    def test_no_hard_binding_assertion(self) -> None:
        manifest = _make_manifest(b"", assertions=[])
        result = verify_manifest_binding(manifest, b"some bytes")

        assert result.hash_valid is None
        assert result.hash_status == "claim.hardBindings.missing"

    def test_non_binding_assertion_ignored(self) -> None:
        # A custom assertion that is not a hard binding
        custom = Assertion(label="com.example.custom", data={"foo": "bar"})
        manifest = _make_manifest(b"", assertions=[custom])
        result = verify_manifest_binding(manifest, b"some bytes")

        assert result.hash_valid is None
        assert result.hash_status == "claim.hardBindings.missing"


# ---------------------------------------------------------------------------
# 10. build_crypto_context -- structure check
# ---------------------------------------------------------------------------


class TestBuildCryptoContext:
    def test_context_keys_present(self) -> None:
        sig_result = VerificationResult(
            signature_valid=True,
            signature_status="claimSignature.validated",
            signature_message="Signature verified",
            algorithm_name="ES256",
            algorithm_allowed=True,
            chain_valid=True,
            chain_status="signingCredential.trusted",
            chain_message="ok",
            trust_status="signingCredential.trusted",
        )
        ctx = build_crypto_context(sig_result)

        assert "signature" in ctx
        assert "certificate" in ctx
        assert "trust" in ctx
        assert "hash" not in ctx  # no hash result provided

    def test_signature_fields(self) -> None:
        sig_result = VerificationResult(
            signature_valid=True,
            signature_status="claimSignature.validated",
            signature_message="ok",
            algorithm_name="ES256",
            algorithm_allowed=True,
        )
        ctx = build_crypto_context(sig_result)

        assert ctx["signature"]["is_valid"] is True
        assert ctx["signature"]["status_code"] == "claimSignature.validated"
        assert ctx["signature"]["algorithm"] == "ES256"
        assert ctx["signature"]["algorithm_allowed"] is True

    def test_trust_fields(self) -> None:
        sig_result = VerificationResult(
            trust_status="signingCredential.trusted",
        )
        ctx = build_crypto_context(sig_result)

        assert ctx["trust"]["is_trusted"] is True
        assert ctx["trust"]["status_code"] == "signingCredential.trusted"

    def test_untrusted_trust_fields(self) -> None:
        sig_result = VerificationResult(
            trust_status="signingCredential.untrusted",
        )
        ctx = build_crypto_context(sig_result)

        assert ctx["trust"]["is_trusted"] is False

    def test_hash_context_included_when_provided(self) -> None:
        sig_result = VerificationResult()
        hash_result = VerificationResult(
            hash_valid=True,
            hash_status="assertion.dataHash.match",
            hash_message="Data hash matches",
        )
        ctx = build_crypto_context(sig_result, hash_result)

        assert "hash" in ctx
        assert ctx["hash"]["is_valid"] is True
        assert ctx["hash"]["status_code"] == "assertion.dataHash.match"

    def test_hash_context_excluded_when_none(self) -> None:
        sig_result = VerificationResult()
        hash_result = VerificationResult(hash_valid=None)
        ctx = build_crypto_context(sig_result, hash_result)

        assert "hash" not in ctx

    def test_certificate_fields(self) -> None:
        sig_result = VerificationResult(
            chain_valid=True,
            chain_status="signingCredential.valid",
            chain_message="Chain validation passed",
        )
        ctx = build_crypto_context(sig_result)

        assert ctx["certificate"]["chain_valid"] is True
        assert ctx["certificate"]["status_code"] == "signingCredential.valid"


# ---------------------------------------------------------------------------
# 11. Full pipeline CLI context integration
# ---------------------------------------------------------------------------


class TestFullPipelineCliContext:
    def test_crypto_context_merged_into_manifest_context(self, pki: dict) -> None:
        """Simulate the CLI pipeline: manifest context + crypto context merged."""
        signer = pki["valid_signer"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        claim_data: dict = {"claim_generator": "pipeline/1.0"}
        claim_cbor = cbor2.dumps(claim_data)

        asset_bytes = b"pipeline test asset"
        sig_bytes = _sign_claim(claim_cbor, signer.key, cert_der)
        hash_assertion = _make_hash_data_assertion(asset_bytes)
        manifest = _make_manifest(sig_bytes, claim_data, assertions=[hash_assertion])

        # Simulate CLI pipeline
        sig_result = verify_manifest_signature(manifest)
        hash_result = verify_manifest_binding(manifest, asset_bytes)
        ctx = build_crypto_context(sig_result, hash_result)

        # Merge into a simulated base context (as CLI does)
        base_context: dict = {
            "manifest_store": {"manifest_count": 1},
            "container_format": "jpeg",
        }
        base_context.update(ctx)

        assert "signature" in base_context
        assert "certificate" in base_context
        assert "trust" in base_context
        assert "hash" in base_context
        assert base_context["signature"]["is_valid"] is True
        assert base_context["hash"]["is_valid"] is True

    def test_crypto_context_with_invalid_sig_propagates(self) -> None:
        """Invalid signature propagates correctly through context."""
        manifest = _make_manifest(b"not-valid-cose")
        sig_result = verify_manifest_signature(manifest)
        ctx = build_crypto_context(sig_result)

        assert ctx["signature"]["is_valid"] is False
        assert ctx["signature"]["status_code"] == "claimSignature.missing"

    def test_full_trusted_pipeline(self, pki: dict, root_trust_store: TrustAnchorStore) -> None:
        """Full trusted pipeline: valid signature, trusted chain, matching hash."""
        signer = pki["valid_signer"]
        intermediate = pki["intermediate"]
        root = pki["root"]
        cert_der = signer.cert.public_bytes(serialization.Encoding.DER)
        intermediate_der = intermediate.cert.public_bytes(serialization.Encoding.DER)
        root_der = root.cert.public_bytes(serialization.Encoding.DER)

        asset_bytes = b"full pipeline trusted asset content"
        claim_data: dict = {"claim_generator": "full_trusted/1.0"}
        claim_cbor = cbor2.dumps(claim_data)

        # Build COSE with full chain: signer + intermediate + root
        protected = cbor2.dumps({1: -7, "x5chain": [cert_der, intermediate_der, root_der]})
        protected_reencoded = cbor2.dumps(cbor2.loads(protected))
        sig_structure = cbor2.dumps(["Signature1", protected_reencoded, b"", claim_cbor])
        signature = _raw_ec_signature(signer.key, sig_structure)
        unprotected: dict = {}
        sig_bytes = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, None, signature]))

        hash_assertion = _make_hash_data_assertion(asset_bytes)
        manifest = _make_manifest(sig_bytes, claim_data, assertions=[hash_assertion])

        sig_result = verify_manifest_signature(manifest, trust_store=root_trust_store)
        hash_result = verify_manifest_binding(manifest, asset_bytes)
        ctx = build_crypto_context(sig_result, hash_result)

        assert ctx["signature"]["is_valid"] is True
        assert ctx["trust"]["is_trusted"] is True
        assert ctx["trust"]["status_code"] == "signingCredential.trusted"
        assert ctx["hash"]["is_valid"] is True
        assert ctx["certificate"]["chain_valid"] is True
