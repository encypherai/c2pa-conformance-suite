"""Tests for OCSP response parser and RFC 3161 timestamp token verifier.

Covers:
- src/c2pa_conformance/crypto/ocsp.py
- src/c2pa_conformance/crypto/timestamp.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp as ocsp_mod

from c2pa_conformance.crypto.ocsp import (
    OcspResult,
    check_revocation,
    parse_ocsp_response,
    validate_ocsp_freshness,
)
from c2pa_conformance.crypto.pki import generate_intermediate_ca, generate_root_ca, generate_signer
from c2pa_conformance.crypto.timestamp import (
    TimestampResult,
    _extract_gen_time,
    check_timestamp_validity,
    parse_tst_header,
    validate_timestamp,
)

# ---------------------------------------------------------------------------
# Shared PKI fixture (session-scoped for speed)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def pki():
    """Generate a minimal test PKI: root -> intermediate -> leaf signer."""
    root = generate_root_ca()
    intermediate = generate_intermediate_ca(root)
    signer = generate_signer(intermediate, common_name="OCSP Test Signer")
    return {"root": root, "intermediate": intermediate, "signer": signer}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_ocsp_response(cert, issuer_cert, issuer_key, status: str = "good") -> bytes:
    """Build a signed DER-encoded OCSP response for testing."""
    now = datetime.now(timezone.utc)
    builder = ocsp_mod.OCSPResponseBuilder()

    if status == "good":
        builder = builder.add_response(
            cert=cert,
            issuer=issuer_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp_mod.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=now + timedelta(days=7),
            revocation_time=None,
            revocation_reason=None,
        )
    elif status == "revoked":
        builder = builder.add_response(
            cert=cert,
            issuer=issuer_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp_mod.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=now + timedelta(days=7),
            revocation_time=now - timedelta(days=1),
            revocation_reason=x509.ReasonFlags.key_compromise,
        )
    elif status == "unknown":
        builder = builder.add_response(
            cert=cert,
            issuer=issuer_cert,
            algorithm=hashes.SHA256(),
            cert_status=ocsp_mod.OCSPCertStatus.UNKNOWN,
            this_update=now,
            next_update=now + timedelta(days=7),
            revocation_time=None,
            revocation_reason=None,
        )
    else:
        raise ValueError(f"Unknown status: {status}")

    builder = builder.responder_id(ocsp_mod.OCSPResponderEncoding.HASH, issuer_cert)
    response = builder.sign(issuer_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


def _build_fake_timestamp(gen_time: datetime) -> bytes:
    """Build a minimal DER structure containing a GeneralizedTime for testing.

    This is NOT a valid RFC 3161 token; it contains just enough structure for
    the genTime extractor to find the time value.
    """
    time_str = gen_time.strftime("%Y%m%d%H%M%S") + "Z"
    time_bytes = time_str.encode("ascii")
    # GeneralizedTime TLV: tag 0x18, length, value
    gen_time_tlv = bytes([0x18, len(time_bytes)]) + time_bytes
    # Wrap in a SEQUENCE (tag 0x30)
    sequence = bytes([0x30, len(gen_time_tlv)]) + gen_time_tlv
    return sequence


# ===========================================================================
# OCSP tests
# ===========================================================================


class TestParseOcspResponse:
    def test_parse_ocsp_good(self, pki):
        """Good OCSP response -> notRevoked."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = parse_ocsp_response(der)
        assert result.status == "notRevoked"
        assert result.status_code == "signingCredential.ocsp.notRevoked"
        assert result.cert_status == "good"
        assert result.this_update is not None
        assert result.next_update is not None

    def test_parse_ocsp_revoked(self, pki):
        """Revoked OCSP response -> revoked."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="revoked",
        )
        result = parse_ocsp_response(der)
        assert result.status == "revoked"
        assert result.status_code == "signingCredential.ocsp.revoked"
        assert result.cert_status == "revoked"
        assert "key_compromise" in result.revocation_reason

    def test_parse_ocsp_malformed(self):
        """Garbage bytes -> malformed."""
        result = parse_ocsp_response(b"\x00\x01\x02garbage")
        assert result.status == "malformed"
        assert result.status_code == "signingCredential.ocsp.malformed"

    def test_parse_ocsp_empty_bytes(self):
        """Empty bytes -> malformed."""
        result = parse_ocsp_response(b"")
        assert result.status == "malformed"


class TestCheckRevocation:
    def test_check_revocation_single_response(self, pki):
        """Single good OCSP response bytes in rVals -> notRevoked."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = check_revocation(der)
        assert result.status == "notRevoked"

    def test_check_revocation_no_rvals(self):
        """None rVals -> skipped."""
        result = check_revocation(None)
        assert result.status == "skipped"
        assert result.status_code == "signingCredential.ocsp.skipped"

    def test_check_revocation_list(self, pki):
        """List of OCSP responses: first good -> notRevoked."""
        good_der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = check_revocation([good_der, b"garbage"])
        assert result.status == "notRevoked"

    def test_check_revocation_list_all_bad(self):
        """List with only garbage entries -> malformed (last result)."""
        result = check_revocation([b"bad1", b"bad2"])
        assert result.status == "malformed"

    def test_check_revocation_dict_ocspVals(self, pki):
        """rVals as dict with ocspVals key -> extracts and validates."""
        good_der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        rvals = {"ocspVals": [good_der]}
        result = check_revocation(rvals)
        assert result.status == "notRevoked"

    def test_check_revocation_dict_empty_ocspVals(self):
        """rVals dict with empty ocspVals -> skipped."""
        result = check_revocation({"ocspVals": []})
        assert result.status == "skipped"

    def test_check_revocation_dict_no_known_key(self):
        """rVals dict with no recognised key -> skipped."""
        result = check_revocation({"someOtherKey": "value"})
        assert result.status == "skipped"


class TestValidateOcspFreshness:
    def test_validate_ocsp_freshness_valid(self, pki):
        """Validation time within thisUpdate..nextUpdate -> fresh."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = parse_ocsp_response(der)
        assert result.this_update is not None

        # Validate at a time 1 hour after thisUpdate.
        check_at = result.this_update.replace(tzinfo=timezone.utc) + timedelta(hours=1)
        assert validate_ocsp_freshness(result, validation_time=check_at) is True

    def test_validate_ocsp_freshness_expired(self, pki):
        """Validation time past nextUpdate -> stale."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = parse_ocsp_response(der)
        assert result.next_update is not None

        # Validate far in the future.
        check_at = result.next_update.replace(tzinfo=timezone.utc) + timedelta(days=30)
        assert validate_ocsp_freshness(result, validation_time=check_at) is False

    def test_validate_ocsp_freshness_before_this_update(self, pki):
        """Validation time before thisUpdate -> stale."""
        der = _build_ocsp_response(
            pki["signer"].cert,
            pki["intermediate"].cert,
            pki["intermediate"].key,
            status="good",
        )
        result = parse_ocsp_response(der)
        assert result.this_update is not None

        check_at = result.this_update.replace(tzinfo=timezone.utc) - timedelta(hours=1)
        assert validate_ocsp_freshness(result, validation_time=check_at) is False

    def test_validate_ocsp_freshness_no_times(self):
        """Result with no thisUpdate/nextUpdate -> always fresh."""
        result = OcspResult(
            status="notRevoked",
            status_code="signingCredential.ocsp.notRevoked",
            message="ok",
        )
        assert validate_ocsp_freshness(result) is True


# ===========================================================================
# Timestamp tests
# ===========================================================================


class TestParseTstHeader:
    def test_parse_tst_header_raw_bytes(self):
        """Raw DER bytes that fail CBOR decode -> treated as single token."""
        token = _build_fake_timestamp(datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc))
        tokens = parse_tst_header(token)
        assert tokens == [token]

    def test_parse_tst_header_cbor_tstTokens(self):
        """CBOR-encoded bytes with tstTokens key -> extracts token list."""
        token = _build_fake_timestamp(datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc))
        cbor_data = cbor2.dumps({"tstTokens": [token]})
        tokens = parse_tst_header(cbor_data)
        assert tokens == [token]

    def test_parse_tst_header_cbor_val(self):
        """CBOR-encoded bytes with val key -> extracts token."""
        token = _build_fake_timestamp(datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc))
        cbor_data = cbor2.dumps({"val": token})
        tokens = parse_tst_header(cbor_data)
        assert tokens == [token]

    def test_parse_tst_header_dict(self):
        """Pre-decoded dict with tstTokens -> extracts tokens."""
        token = _build_fake_timestamp(datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc))
        tokens = parse_tst_header({"tstTokens": [token]})
        assert tokens == [token]

    def test_parse_tst_header_list(self):
        """List of bytes -> returned as-is."""
        token = b"\x30\x06\x18\x04test"
        tokens = parse_tst_header([token])
        assert tokens == [token]

    def test_parse_tst_header_none(self):
        """None -> empty list."""
        assert parse_tst_header(None) == []

    def test_parse_tst_header_empty_list(self):
        """Empty list -> empty list."""
        assert parse_tst_header([]) == []


class TestValidateTimestamp:
    def test_validate_timestamp_valid(self):
        """Valid token with extractable genTime -> timeStamp.validated."""
        now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = _build_fake_timestamp(now)
        result = validate_timestamp(token)
        assert result.is_valid is True
        assert result.status_code == "timeStamp.validated"
        assert result.gen_time is not None
        assert result.gen_time.year == 2024

    def test_validate_timestamp_no_tokens(self):
        """None input -> malformed (no tokens)."""
        result = validate_timestamp(None)
        assert result.is_valid is False
        assert result.status_code == "timeStamp.malformed"
        assert "No timestamp tokens found" in result.message

    def test_validate_timestamp_multiple(self):
        """Two tokens in a single sigTst -> malformed per C2PA spec."""
        now = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        token = _build_fake_timestamp(now)
        # Pass as dict with two-element tstTokens list.
        result = validate_timestamp({"tstTokens": [token, token]})
        assert result.is_valid is False
        assert result.status_code == "timeStamp.malformed"
        assert "Multiple" in result.message

    def test_validate_timestamp_malformed(self):
        """Garbage bytes that contain no GeneralizedTime -> malformed."""
        result = validate_timestamp(b"\xff\xfe\xfd\xfc\xfb\xfa")
        assert result.is_valid is False
        assert result.status_code == "timeStamp.malformed"

    def test_validate_timestamp_cbor_encoded(self):
        """CBOR-encoded sigTst with tstTokens -> extracts and validates."""
        now = datetime(2025, 1, 15, 8, 30, 0, tzinfo=timezone.utc)
        token = _build_fake_timestamp(now)
        cbor_data = cbor2.dumps({"tstTokens": [token]})
        result = validate_timestamp(cbor_data)
        assert result.is_valid is True
        assert result.gen_time is not None
        assert result.gen_time.month == 1
        assert result.gen_time.day == 15


class TestExtractGenTime:
    def test_extract_gen_time_basic(self):
        """Correctly parses a GeneralizedTime from a minimal DER structure."""
        target = datetime(2024, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
        der = _build_fake_timestamp(target)
        result = _extract_gen_time(der)
        assert result is not None
        assert result.year == 2024
        assert result.month == 3
        assert result.day == 15
        assert result.hour == 10
        assert result.minute == 30
        assert result.second == 45
        assert result.tzinfo == timezone.utc

    def test_extract_gen_time_not_present(self):
        """Returns None when no GeneralizedTime is present."""
        result = _extract_gen_time(b"\x30\x04\x02\x02\x00\x01")
        assert result is None

    def test_extract_gen_time_garbage(self):
        """Returns None on arbitrary garbage bytes."""
        result = _extract_gen_time(b"\xff" * 32)
        assert result is None


class TestCheckTimestampValidity:
    def test_check_timestamp_validity_inside(self):
        """genTime inside cert validity window -> timeStamp.trusted."""
        gen_time = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        result_in = TimestampResult(
            is_valid=True,
            status_code="timeStamp.validated",
            message="ok",
            gen_time=gen_time,
        )
        not_before = datetime(2024, 1, 1, tzinfo=timezone.utc)
        not_after = datetime(2025, 1, 1, tzinfo=timezone.utc)
        result_out = check_timestamp_validity(result_in, not_before, not_after)
        assert result_out.is_valid is True
        assert result_out.status_code == "timeStamp.trusted"

    def test_check_timestamp_validity_before(self):
        """genTime before cert notBefore -> timeStamp.outsideValidity."""
        gen_time = datetime(2023, 1, 1, tzinfo=timezone.utc)
        result_in = TimestampResult(
            is_valid=True,
            status_code="timeStamp.validated",
            message="ok",
            gen_time=gen_time,
        )
        not_before = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result_out = check_timestamp_validity(result_in, not_before, None)
        assert result_out.is_valid is False
        assert result_out.status_code == "timeStamp.outsideValidity"
        assert "before" in result_out.message

    def test_check_timestamp_validity_after(self):
        """genTime after cert notAfter -> timeStamp.outsideValidity."""
        gen_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result_in = TimestampResult(
            is_valid=True,
            status_code="timeStamp.validated",
            message="ok",
            gen_time=gen_time,
        )
        not_after = datetime(2025, 1, 1, tzinfo=timezone.utc)
        result_out = check_timestamp_validity(result_in, None, not_after)
        assert result_out.is_valid is False
        assert result_out.status_code == "timeStamp.outsideValidity"
        assert "after" in result_out.message

    def test_check_timestamp_validity_no_bounds(self):
        """No bounds supplied -> always trusted."""
        gen_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
        result_in = TimestampResult(
            is_valid=True,
            status_code="timeStamp.validated",
            message="ok",
            gen_time=gen_time,
        )
        result_out = check_timestamp_validity(result_in, None, None)
        assert result_out.is_valid is True
        assert result_out.status_code == "timeStamp.trusted"

    def test_check_timestamp_validity_invalid_input_passthrough(self):
        """Invalid input result is returned unchanged."""
        result_in = TimestampResult(
            is_valid=False,
            status_code="timeStamp.malformed",
            message="bad",
        )
        result_out = check_timestamp_validity(
            result_in,
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        assert result_out.status_code == "timeStamp.malformed"
        assert result_out.is_valid is False
