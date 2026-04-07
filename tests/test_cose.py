"""Tests for the COSE_Sign1 decoder and signature verifier.

Uses the existing test PKI infrastructure to generate certificates and keys.
All COSE_Sign1 structures are built manually with cbor2 so tests remain
independent of any high-level COSE library.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from c2pa_conformance.crypto.cose import (
    CoseDecodeError,
    CoseSignature,
    CoseVerifyError,
    decode_cose_sign1,
    get_algorithm,
    is_algorithm_allowed,
    is_algorithm_deprecated,
    verify_signature,
)
from c2pa_conformance.crypto.pki import generate_test_pki

# ---------------------------------------------------------------------------
# Shared PKI fixture (generated once per session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Generate a complete test PKI hierarchy for the session."""
    output_dir = tmp_path_factory.mktemp("pki")
    return generate_test_pki(output_dir)


@pytest.fixture(scope="session")
def valid_signer_der(pki: dict) -> bytes:
    """DER-encoded valid signer certificate."""
    return pki["valid_signer"].cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def valid_ec_key(pki: dict):
    """EC P-256 private key for the valid signer."""
    return pki["valid_signer"].key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raw_ec_signature(private_key, data: bytes, hash_alg) -> bytes:
    """Sign data with an EC key and return raw r||s (COSE format)."""
    der_sig = private_key.sign(data, ec.ECDSA(hash_alg))
    r, s = _decode_dss_signature_integers(der_sig)
    # Determine coordinate size from curve.
    key_size = (private_key.key_size + 7) // 8
    return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")


def _decode_dss_signature_integers(der_sig: bytes):
    """Return (r, s) integers from a DER-encoded DSS signature."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    return decode_dss_signature(der_sig)


def _build_cose_sign1(
    claim_bytes: bytes,
    private_key,
    cert_der: bytes,
    alg_id: int = -7,
    tagged: bool = True,
    extra_unprotected: dict | None = None,
) -> bytes:
    """Build a minimal valid COSE_Sign1 for testing.

    Supports ES256 (-7), ES384 (-35), ES512 (-36), PS256 (-37),
    PS384 (-38), PS512 (-39), Ed25519 (-8).
    """
    protected = cbor2.dumps({1: alg_id, "x5chain": [cert_der]})
    unprotected: dict = {}
    if extra_unprotected:
        unprotected.update(extra_unprotected)

    # Build Sig_structure: ["Signature1", protected, external_aad, payload]
    # C2PA uses empty external_aad and claim bytes as payload.
    sig_structure = cbor2.dumps(["Signature1", protected, b"", claim_bytes])

    # Sign according to algorithm.
    if alg_id in (-7, -35, -36):
        # ECDSA -- raw r||s
        hash_map = {-7: hashes.SHA256(), -35: hashes.SHA384(), -36: hashes.SHA512()}
        signature = _raw_ec_signature(private_key, sig_structure, hash_map[alg_id])
    elif alg_id in (-37, -38, -39):
        # RSA-PSS
        hash_map = {-37: hashes.SHA256(), -38: hashes.SHA384(), -39: hashes.SHA512()}
        h = hash_map[alg_id]
        signature = private_key.sign(
            sig_structure,
            padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.MAX_LENGTH),
            h,
        )
    elif alg_id == -8:
        # Ed25519
        signature = private_key.sign(sig_structure)
    else:
        raise ValueError(f"Unknown alg_id {alg_id} in test helper")

    array = [protected, unprotected, None, signature]
    if tagged:
        return cbor2.dumps(cbor2.CBORTag(18, array))
    return cbor2.dumps(array)


# ---------------------------------------------------------------------------
# 1. Decode tests
# ---------------------------------------------------------------------------


def test_decode_cose_sign1_valid(pki, valid_signer_der, valid_ec_key):
    """Decode a well-formed COSE_Sign1 and check all fields."""
    claim_bytes = b"fake-claim-cbor"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, alg_id=-7)

    cose = decode_cose_sign1(raw)

    assert isinstance(cose, CoseSignature)
    assert cose.algorithm_id == -7
    assert cose.algorithm_name == "ES256"
    assert isinstance(cose.signature_bytes, bytes)
    assert len(cose.x5chain) == 1
    assert cose.x5chain[0] == valid_signer_der
    assert cose.sig_tst is None
    assert cose.sig_tst2 is None
    assert cose.r_vals is None
    assert cose.protected_header[1] == -7
    assert "x5chain" in cose.protected_header


def test_decode_cose_sign1_tagged(pki, valid_signer_der, valid_ec_key):
    """CBOR tag 18 is stripped and the structure decoded correctly."""
    claim_bytes = b"tagged-claim"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, tagged=True)
    cose = decode_cose_sign1(raw)
    assert cose.algorithm_id == -7


def test_decode_cose_sign1_untagged(pki, valid_signer_der, valid_ec_key):
    """Untagged COSE_Sign1 (no CBOR tag 18) also decodes correctly."""
    claim_bytes = b"untagged-claim"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, tagged=False)
    cose = decode_cose_sign1(raw)
    assert cose.algorithm_id == -7


def test_decode_cose_sign1_malformed():
    """Truncated or garbage bytes raise CoseDecodeError."""
    # Truncated CBOR: start of a 4-element array (0x84) but no data.
    with pytest.raises(CoseDecodeError, match="CBOR decode failed"):
        decode_cose_sign1(b"\x84")

    # Valid CBOR but wrong structure (not a 4-element array).
    with pytest.raises(CoseDecodeError):
        decode_cose_sign1(cbor2.dumps([1, 2, 3]))  # only 3 elements

    # A plain integer.
    with pytest.raises(CoseDecodeError):
        decode_cose_sign1(cbor2.dumps(42))


def test_decode_cose_sign1_missing_algorithm(pki, valid_signer_der):
    """Protected header without alg (key 1) raises CoseDecodeError."""
    # Build a structure with alg omitted from protected header.
    protected = cbor2.dumps({99: "not-alg"})
    unprotected = {33: [valid_signer_der]}
    array = [protected, unprotected, None, b"\x00" * 64]
    raw = cbor2.dumps(cbor2.CBORTag(18, array))

    with pytest.raises(CoseDecodeError, match="alg"):
        decode_cose_sign1(raw)


def test_decode_cose_sign1_unknown_algorithm(pki, valid_signer_der):
    """A protected header with an unrecognised alg ID raises CoseDecodeError."""
    protected = cbor2.dumps({1: 9999})
    unprotected = {33: [valid_signer_der]}
    array = [protected, unprotected, None, b"\x00" * 64]
    raw = cbor2.dumps(cbor2.CBORTag(18, array))

    with pytest.raises(CoseDecodeError, match="Unsupported"):
        decode_cose_sign1(raw)


def test_decode_cose_sign1_non_nil_payload(pki, valid_signer_der):
    """A non-nil payload raises CoseDecodeError (C2PA requires detached)."""
    protected = cbor2.dumps({1: -7})
    unprotected = {33: [valid_signer_der]}
    array = [protected, unprotected, b"some-payload", b"\x00" * 64]
    raw = cbor2.dumps(cbor2.CBORTag(18, array))

    with pytest.raises(CoseDecodeError, match="detached"):
        decode_cose_sign1(raw)


def test_decode_cose_sign1_x5chain_single_cert(pki, valid_signer_der):
    """x5chain as a single bstr (not an array) is normalised to a list."""
    protected = cbor2.dumps({1: -7})
    # key 33 as a single bytes value, not an array.
    unprotected = {33: valid_signer_der}
    array = [protected, unprotected, None, b"\x00" * 64]
    raw = cbor2.dumps(array)

    cose = decode_cose_sign1(raw)
    assert cose.x5chain == [valid_signer_der]


def test_decode_cose_sign1_extra_unprotected_fields(pki, valid_signer_der, valid_ec_key):
    """sigTst, sigTst2, and rVals are stored if present."""
    claim_bytes = b"claim"
    extra = {
        "sigTst": b"\xde\xad\xbe\xef",
        "sigTst2": b"\xca\xfe",
        "rVals": {"ocspVals": [b"\xaa"]},
    }
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, extra_unprotected=extra)
    cose = decode_cose_sign1(raw)
    assert cose.sig_tst == b"\xde\xad\xbe\xef"
    assert cose.sig_tst2 == b"\xca\xfe"
    assert cose.r_vals is not None


# ---------------------------------------------------------------------------
# 2. Algorithm registry tests
# ---------------------------------------------------------------------------


def test_algorithm_registry_all_allowed():
    """All seven C2PA-allowed algorithm IDs are recognised."""
    expected = {
        -7: "ES256",
        -35: "ES384",
        -36: "ES512",
        -37: "PS256",
        -38: "PS384",
        -39: "PS512",
        -8: "Ed25519",
    }
    for cose_id, name in expected.items():
        alg = get_algorithm(cose_id)
        assert alg.cose_id == cose_id
        assert alg.name == name
        assert is_algorithm_allowed(cose_id)
        assert not is_algorithm_deprecated(cose_id)


def test_algorithm_registry_unsupported():
    """An unrecognised algorithm ID raises CoseDecodeError."""
    with pytest.raises(CoseDecodeError, match="Unsupported"):
        get_algorithm(0)

    with pytest.raises(CoseDecodeError, match="Unsupported"):
        get_algorithm(9999)


def test_algorithm_registry_allowed_vs_unsupported():
    """is_algorithm_allowed returns False for unknown IDs without raising."""
    assert not is_algorithm_allowed(0)
    assert not is_algorithm_allowed(-1)
    assert not is_algorithm_allowed(9999)


def test_algorithm_registry_deprecated_flag():
    """is_algorithm_deprecated returns False for all current v2.4 algorithms."""
    for cose_id in (-7, -35, -36, -37, -38, -39, -8):
        assert not is_algorithm_deprecated(cose_id)
    # Unknown IDs also return False (not deprecated, just unknown).
    assert not is_algorithm_deprecated(9999)


def test_algorithm_hash_alg_ed25519():
    """Ed25519 has hash_alg=None (hash is implicit in the algorithm)."""
    alg = get_algorithm(-8)
    assert alg.hash_alg is None


def test_algorithm_hash_alg_ecdsa():
    """ECDSA algorithms have concrete hash_alg instances."""
    assert isinstance(get_algorithm(-7).hash_alg, hashes.SHA256)
    assert isinstance(get_algorithm(-35).hash_alg, hashes.SHA384)
    assert isinstance(get_algorithm(-36).hash_alg, hashes.SHA512)


# ---------------------------------------------------------------------------
# 3. Signature verification tests
# ---------------------------------------------------------------------------


def test_verify_signature_es256(pki, valid_signer_der, valid_ec_key):
    """A valid ES256 COSE_Sign1 verifies successfully."""
    claim_bytes = b"claim-cbor-bytes"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, alg_id=-7)
    cose = decode_cose_sign1(raw)
    assert verify_signature(cose, claim_bytes) is True


def test_verify_signature_es384(pki):
    """A valid ES384 COSE_Sign1 verifies successfully."""
    ec_key = ec.generate_private_key(ec.SECP384R1())
    # Self-signed cert for the test key.
    cert_der = _self_signed_cert_der(ec_key)
    claim_bytes = b"claim-for-es384"
    raw = _build_cose_sign1(claim_bytes, ec_key, cert_der, alg_id=-35)
    cose = decode_cose_sign1(raw)
    assert verify_signature(cose, claim_bytes) is True


def test_verify_signature_es512(pki):
    """A valid ES512 COSE_Sign1 verifies successfully."""
    ec_key = ec.generate_private_key(ec.SECP521R1())
    cert_der = _self_signed_cert_der(ec_key)
    claim_bytes = b"claim-for-es512"
    raw = _build_cose_sign1(claim_bytes, ec_key, cert_der, alg_id=-36)
    cose = decode_cose_sign1(raw)
    assert verify_signature(cose, claim_bytes) is True


def test_verify_signature_ps256(pki):
    """A valid PS256 (RSA-PSS SHA-256) COSE_Sign1 verifies successfully."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert_der = _self_signed_cert_der(rsa_key)
    claim_bytes = b"claim-cbor-for-ps256"
    raw = _build_cose_sign1(claim_bytes, rsa_key, cert_der, alg_id=-37)
    cose = decode_cose_sign1(raw)
    assert verify_signature(cose, claim_bytes) is True


def test_verify_signature_tampered_aad(pki, valid_signer_der, valid_ec_key):
    """Modifying external_aad after signing causes verification to fail."""
    claim_bytes = b"original-claim"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, alg_id=-7)
    cose = decode_cose_sign1(raw)

    with pytest.raises(CoseVerifyError):
        verify_signature(cose, b"tampered-claim")


def test_verify_signature_wrong_key(pki, valid_signer_der):
    """Verifying with the wrong public key fails."""
    # Build COSE_Sign1 with one key but put a different cert in x5chain.
    signing_key = ec.generate_private_key(ec.SECP256R1())
    different_key = ec.generate_private_key(ec.SECP256R1())
    wrong_cert_der = _self_signed_cert_der(different_key)

    claim_bytes = b"claim"
    raw = _build_cose_sign1(claim_bytes, signing_key, wrong_cert_der, alg_id=-7)
    cose = decode_cose_sign1(raw)

    with pytest.raises(CoseVerifyError):
        verify_signature(cose, claim_bytes)


def test_verify_signature_tampered_signature(pki, valid_signer_der, valid_ec_key):
    """Flipping a bit in the signature causes verification to fail."""
    claim_bytes = b"claim"
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, alg_id=-7)
    cose = decode_cose_sign1(raw)

    # Flip the first byte of the signature.
    tampered_sig = bytes([cose.signature_bytes[0] ^ 0xFF]) + cose.signature_bytes[1:]
    tampered_cose = CoseSignature(
        protected_header=cose.protected_header,
        unprotected_header=cose.unprotected_header,
        algorithm_id=cose.algorithm_id,
        algorithm_name=cose.algorithm_name,
        signature_bytes=tampered_sig,
        x5chain=cose.x5chain,
    )

    with pytest.raises(CoseVerifyError):
        verify_signature(tampered_cose, claim_bytes)


def test_verify_signature_no_x5chain(pki, valid_ec_key):
    """Missing x5chain raises CoseVerifyError."""
    protected = cbor2.dumps({1: -7})
    unprotected: dict = {}  # no x5chain
    sig_structure = cbor2.dumps(["Signature1", protected, b"aad", b""])
    signature = _raw_ec_signature(valid_ec_key, sig_structure, hashes.SHA256())
    array = [protected, unprotected, None, signature]
    raw = cbor2.dumps(cbor2.CBORTag(18, array))
    cose = decode_cose_sign1(raw)

    with pytest.raises(CoseVerifyError, match="x5chain"):
        verify_signature(cose, b"aad")


# ---------------------------------------------------------------------------
# 4. Round-trip test
# ---------------------------------------------------------------------------


def test_round_trip_es256(pki, valid_signer_der, valid_ec_key):
    """Full encode->decode->verify round-trip with ES256."""
    claim_bytes = cbor2.dumps({"c2pa:claim": "round-trip-test"})
    raw = _build_cose_sign1(claim_bytes, valid_ec_key, valid_signer_der, alg_id=-7)
    cose = decode_cose_sign1(raw)

    assert cose.algorithm_name == "ES256"
    assert cose.x5chain[0] == valid_signer_der
    assert verify_signature(cose, claim_bytes) is True


# ---------------------------------------------------------------------------
# Utility: minimal self-signed certificate for ad-hoc test keys
# ---------------------------------------------------------------------------


def _self_signed_cert_der(private_key) -> bytes:
    """Generate a minimal self-signed DER certificate for a given key."""
    import datetime

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)
