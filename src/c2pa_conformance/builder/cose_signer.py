"""COSE_Sign1 builder for test vector generation.

Creates signed COSE_Sign1 structures using the test PKI infrastructure.
This is the inverse of crypto/cose.py's decode_cose_sign1().
"""

from __future__ import annotations

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# COSE algorithm IDs (RFC 9052 / IANA COSE Algorithms registry)
ES256 = -7
ES384 = -35
ES512 = -36
PS256 = -37
PS384 = -38
PS512 = -39
ED25519 = -8

# Algorithm to hash mapping
_ALG_HASH: dict[int, hashes.HashAlgorithm] = {
    ES256: hashes.SHA256(),
    ES384: hashes.SHA384(),
    ES512: hashes.SHA512(),
    PS256: hashes.SHA256(),
    PS384: hashes.SHA384(),
    PS512: hashes.SHA512(),
}

# Algorithm to coordinate byte size for raw r||s ECDSA encoding
_EC_KEY_SIZES: dict[int, int] = {
    ES256: 32,
    ES384: 48,
    ES512: 66,
}


def sign_cose(
    claim_cbor: bytes,
    private_key: EllipticCurvePrivateKey | RSAPrivateKey | Ed25519PrivateKey,
    cert_chain: list[x509.Certificate],
    algorithm: int = ES256,
) -> bytes:
    """Build and sign a COSE_Sign1 structure.

    Args:
        claim_cbor: The CBOR-encoded claim (used as external AAD).
        private_key: The signing key.
        cert_chain: X.509 certificates [signer, intermediate, ...] (DER encoded in output).
        algorithm: COSE algorithm ID (default ES256).

    Returns:
        CBOR-encoded COSE_Sign1 (tagged with CBOR tag 18).
    """
    # Build protected header: {alg: algorithm_id, x5chain: cert_chain_der}
    # C2PA v2 requires x5chain in the protected header.
    x5chain = [cert.public_bytes(serialization.Encoding.DER) for cert in cert_chain]
    protected_map: dict[int | str, object] = {1: algorithm, "x5chain": x5chain}
    protected_bytes = cbor2.dumps(protected_map)

    # Unprotected header is empty for C2PA v2
    unprotected: dict[int | str, object] = {}

    # Build Sig_structure per RFC 9052 section 4.4:
    # ["Signature1", protected, external_aad, payload]
    # C2PA uses detached payload: the COSE payload field is nil, but the
    # claim bytes are passed as the payload in the Sig_structure.
    sig_structure = cbor2.dumps(["Signature1", protected_bytes, b"", claim_cbor])

    signature = _sign(private_key, sig_structure, algorithm)

    # COSE_Sign1: tag 18, [protected_bstr, unprotected_map, nil, signature]
    return cbor2.dumps(cbor2.CBORTag(18, [protected_bytes, unprotected, None, signature]))


def _sign(
    key: EllipticCurvePrivateKey | RSAPrivateKey | Ed25519PrivateKey,
    data: bytes,
    algorithm: int,
) -> bytes:
    """Sign data with the given key and algorithm, returning the raw COSE signature."""
    if algorithm in (ES256, ES384, ES512):
        hash_alg = _ALG_HASH[algorithm]
        der_sig = key.sign(data, ec.ECDSA(hash_alg))  # type: ignore[arg-type]
        # Convert DER-encoded DSS signature to COSE raw r||s format
        r, s = decode_dss_signature(der_sig)
        key_size = _EC_KEY_SIZES[algorithm]
        return r.to_bytes(key_size, "big") + s.to_bytes(key_size, "big")

    if algorithm in (PS256, PS384, PS512):
        hash_alg = _ALG_HASH[algorithm]
        return key.sign(  # type: ignore[return-value]
            data,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg,
        )

    if algorithm == ED25519:
        return key.sign(data)  # type: ignore[return-value]

    raise ValueError(f"Unsupported COSE algorithm ID: {algorithm}")
