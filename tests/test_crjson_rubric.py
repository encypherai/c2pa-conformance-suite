"""Comprehensive tests for crJSON serializer and rubric evaluator modules."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from c2pa_conformance.evaluator.engine import ConformanceReport, EvalResult, ResultType
from c2pa_conformance.rubric.evaluator import (
    RubricReport,
    RubricResult,
    evaluate_rubric,
    parse_rubric,
)
from c2pa_conformance.serializer.crjson import (
    _build_assertions_map,
    _encode_assertion_data,
    _parse_rdn_string,
    classify_status_code,
    serialize_to_crjson,
)

# ---------------------------------------------------------------------------
# Mock objects for serializer tests
# ---------------------------------------------------------------------------


class MockAssertion:
    def __init__(
        self,
        label: str,
        data: dict[str, Any] | None = None,
        is_hard_binding: bool = False,
        raw_cbor: bytes = b"",
        box: Any = None,
    ) -> None:
        self.label = label
        self.data = data or {}
        self.is_hard_binding = is_hard_binding
        self.raw_cbor = raw_cbor
        self.box = box


class MockClaim:
    def __init__(
        self,
        data: dict[str, Any] | None = None,
        claim_generator: str = "test",
        claim_generator_info: Any = None,
        signature_ref: str = "self#jumbf=c2pa.signature",
        assertion_refs: list[Any] | None = None,
        raw_cbor: bytes = b"",
    ) -> None:
        self.data = data or {}
        self.claim_generator = claim_generator
        self.claim_generator_info = claim_generator_info or {"name": "test", "version": "0.1"}
        self.signature_ref = signature_ref
        self.assertion_refs = assertion_refs or []
        self.raw_cbor = raw_cbor
        self.is_update_manifest = False


class MockManifest:
    def __init__(
        self,
        label: str = "urn:c2pa:test-manifest",
        assertions: list[MockAssertion] | None = None,
        claim: MockClaim | None = None,
        signature_bytes: bytes = b"sig",
        hard_binding: Any = None,
    ) -> None:
        self.label = label
        self.assertions = assertions or []
        self.claim = claim
        self.signature_bytes = signature_bytes
        self.hard_binding = hard_binding


class MockManifestStore:
    def __init__(
        self,
        manifests: list[MockManifest] | None = None,
        active_manifest: MockManifest | None = None,
    ) -> None:
        self.manifests = manifests or []
        self.active_manifest = active_manifest
        self.manifest_count = len(self.manifests)


# ---------------------------------------------------------------------------
# classify_status_code tests
# ---------------------------------------------------------------------------


class TestClassifyStatusCode:
    """Tests for classify_status_code covering all three outcome buckets."""

    # -- success codes --

    def test_data_hash_match(self) -> None:
        assert classify_status_code("assertion.dataHash.match") == "success"

    def test_claim_signature_validated(self) -> None:
        assert classify_status_code("claimSignature.validated") == "success"

    def test_signing_credential_trusted(self) -> None:
        assert classify_status_code("signingCredential.trusted") == "success"

    def test_claim_signature_inside_validity(self) -> None:
        assert classify_status_code("claimSignature.insideValidity") == "success"

    def test_ocsp_not_revoked(self) -> None:
        assert classify_status_code("signingCredential.ocsp.notRevoked") == "success"

    def test_algorithm_supported_exact(self) -> None:
        assert classify_status_code("algorithm.supported") == "success"

    # -- informational codes --

    def test_additional_exclusions_present(self) -> None:
        assert (
            classify_status_code("assertion.dataHash.additionalExclusionsPresent")
            == "informational"
        )

    def test_ocsp_inaccessible(self) -> None:
        assert classify_status_code("signingCredential.ocsp.inaccessible") == "informational"

    def test_algorithm_deprecated(self) -> None:
        assert classify_status_code("algorithm.deprecated") == "informational"

    def test_timestamp_malformed(self) -> None:
        assert classify_status_code("timeStamp.malformed") == "informational"

    # -- failure codes --

    def test_data_hash_mismatch(self) -> None:
        assert classify_status_code("assertion.dataHash.mismatch") == "failure"

    def test_claim_signature_missing(self) -> None:
        assert classify_status_code("claimSignature.missing") == "failure"

    def test_claim_malformed(self) -> None:
        assert classify_status_code("claim.malformed") == "failure"

    def test_empty_string(self) -> None:
        assert classify_status_code("") == "failure"

    def test_signing_credential_untrusted(self) -> None:
        assert classify_status_code("signingCredential.untrusted") == "failure"

    def test_unknown_code_is_failure(self) -> None:
        assert classify_status_code("completely.unknown.code") == "failure"


# ---------------------------------------------------------------------------
# _parse_rdn_string tests
# ---------------------------------------------------------------------------


class TestParseRdnString:
    """Tests for RFC 4514 DN parsing."""

    def test_simple_dn(self) -> None:
        result = _parse_rdn_string("CN=Pixel Camera,O=Google LLC,C=US")
        assert result == {"CN": "Pixel Camera", "O": "Google LLC", "C": "US"}

    def test_escaped_comma(self) -> None:
        result = _parse_rdn_string("CN=Foo\\,Bar,O=Org")
        assert result == {"CN": "Foo,Bar", "O": "Org"}

    def test_empty_string(self) -> None:
        assert _parse_rdn_string("") == {}

    def test_single_component(self) -> None:
        result = _parse_rdn_string("CN=Test User")
        assert result == {"CN": "Test User"}

    def test_unknown_attribute_ignored(self) -> None:
        # UNKNOWNATTR is not in _RDN_ATTRS, should be ignored
        result = _parse_rdn_string("CN=Alice,UNKNOWNATTR=ignored,O=Acme")
        assert "UNKNOWNATTR" not in result
        assert result["CN"] == "Alice"
        assert result["O"] == "Acme"

    def test_ou_attribute(self) -> None:
        result = _parse_rdn_string("CN=Device,OU=Engineering,O=Corp,C=DE")
        assert result["OU"] == "Engineering"
        assert result["C"] == "DE"

    def test_key_normalized_to_upper(self) -> None:
        # Keys in the parsed output are always uppercased
        result = _parse_rdn_string("CN=Test,O=Org")
        assert "CN" in result
        assert "O" in result

    def test_whitespace_around_separator(self) -> None:
        result = _parse_rdn_string("CN=Alice , O=Org")
        assert result.get("CN") == "Alice"
        assert result.get("O") == "Org"


# ---------------------------------------------------------------------------
# _encode_assertion_data tests
# ---------------------------------------------------------------------------


class TestEncodeAssertionData:
    """Tests for recursive bytes-to-b64 encoding."""

    def test_bytes_encoded_as_b64_string(self) -> None:
        raw = b"hello"
        encoded = _encode_assertion_data(raw)
        expected = "b64'" + base64.b64encode(b"hello").decode("ascii") + "'"
        assert encoded == expected

    def test_string_passthrough(self) -> None:
        assert _encode_assertion_data("hello") == "hello"

    def test_int_passthrough(self) -> None:
        assert _encode_assertion_data(42) == 42

    def test_none_passthrough(self) -> None:
        assert _encode_assertion_data(None) is None

    def test_dict_recursive(self) -> None:
        data = {"key": b"\x00\x01", "other": "plain"}
        result = _encode_assertion_data(data)
        assert result["other"] == "plain"
        assert result["key"].startswith("b64'")

    def test_list_recursive(self) -> None:
        data = [b"a", "b", 3]
        result = _encode_assertion_data(data)
        assert result[0].startswith("b64'")
        assert result[1] == "b"
        assert result[2] == 3

    def test_nested_structure(self) -> None:
        data = {"outer": {"inner": b"data"}}
        result = _encode_assertion_data(data)
        assert result["outer"]["inner"].startswith("b64'")


# ---------------------------------------------------------------------------
# _build_assertions_map tests
# ---------------------------------------------------------------------------


class TestBuildAssertionsMap:
    """Tests for assertion label keying and deduplication."""

    def test_single_assertion(self) -> None:
        assertions = [MockAssertion("c2pa.actions", {"actions": []})]
        result = _build_assertions_map(assertions)
        assert "c2pa.actions" in result
        assert result["c2pa.actions"] == {"actions": []}

    def test_duplicate_labels_disambiguated(self) -> None:
        assertions = [
            MockAssertion("c2pa.hash.data", {"hash": "aaa"}),
            MockAssertion("c2pa.hash.data", {"hash": "bbb"}),
        ]
        result = _build_assertions_map(assertions)
        assert "c2pa.hash.data" in result
        assert "c2pa.hash.data__1" in result
        assert result["c2pa.hash.data"]["hash"] == "aaa"
        assert result["c2pa.hash.data__1"]["hash"] == "bbb"

    def test_three_duplicates(self) -> None:
        assertions = [
            MockAssertion("label", {"n": 1}),
            MockAssertion("label", {"n": 2}),
            MockAssertion("label", {"n": 3}),
        ]
        result = _build_assertions_map(assertions)
        assert "label" in result
        assert "label__1" in result
        assert "label__2" in result

    def test_bytes_in_assertion_data_encoded(self) -> None:
        assertions = [MockAssertion("c2pa.hash.data", {"pad": b"\x00\x01"})]
        result = _build_assertions_map(assertions)
        assert result["c2pa.hash.data"]["pad"].startswith("b64'")

    def test_empty_assertions_list(self) -> None:
        assert _build_assertions_map([]) == {}


# ---------------------------------------------------------------------------
# serialize_to_crjson integration tests
# ---------------------------------------------------------------------------


class TestSerializeToCrjson:
    """Integration tests for the top-level serializer function."""

    def _make_report(self, results: list[EvalResult] | None = None) -> ConformanceReport:
        report = ConformanceReport(spec_version="2.4")
        if results:
            report.results = results
        return report

    def _make_store(
        self,
        label: str = "urn:c2pa:test-manifest",
        assertions: list[MockAssertion] | None = None,
        claim: MockClaim | None = None,
    ) -> MockManifestStore:
        manifest = MockManifest(
            label=label,
            assertions=assertions or [],
            claim=claim or MockClaim(),
        )
        return MockManifestStore(manifests=[manifest], active_manifest=manifest)

    def test_top_level_keys_present(self) -> None:
        store = self._make_store()
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        assert "@context" in result
        assert "manifests" in result
        assert "jsonGenerator" in result

    def test_json_generator_fields(self) -> None:
        store = self._make_store()
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        gen = result["jsonGenerator"]
        assert "name" in gen
        assert "version" in gen
        assert gen["name"] == "c2pa-conformance-suite"

    def test_manifest_entry_has_label(self) -> None:
        store = self._make_store(label="urn:c2pa:my-manifest")
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        manifest_entry = result["manifests"][0]
        assert manifest_entry["label"] == "urn:c2pa:my-manifest"

    def test_manifest_entry_has_assertions_key(self) -> None:
        store = self._make_store(assertions=[MockAssertion("c2pa.actions", {"actions": []})])
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        manifest_entry = result["manifests"][0]
        assert "assertions" in manifest_entry
        assert isinstance(manifest_entry["assertions"], dict)

    def test_assertions_keyed_by_label_not_array(self) -> None:
        assertions = [
            MockAssertion("c2pa.actions", {"actions": ["crop"]}),
            MockAssertion("c2pa.hash.data", {"alg": "sha256"}),
        ]
        store = self._make_store(assertions=assertions)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        assertions_out = result["manifests"][0]["assertions"]
        assert "c2pa.actions" in assertions_out
        assert "c2pa.hash.data" in assertions_out
        # Must be a dict, not a list
        assert not isinstance(assertions_out, list)

    def test_claim_v2_present_when_claim_provided(self) -> None:
        claim = MockClaim(data={"instanceID": "xmp:iid:test-123"})
        store = self._make_store(claim=claim)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        manifest_entry = result["manifests"][0]
        assert "claim.v2" in manifest_entry

    def test_validation_results_structure(self) -> None:
        store = self._make_store()
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        vr = result["manifests"][0]["validationResults"]
        assert "success" in vr
        assert "informational" in vr
        assert "failure" in vr
        assert isinstance(vr["success"], list)
        assert isinstance(vr["informational"], list)
        assert isinstance(vr["failure"], list)

    def test_skip_results_excluded_from_validation_results(self) -> None:
        skip_result = EvalResult(
            predicate_id="skip-pred",
            result=ResultType.SKIP,
            status_code="assertion.dataHash.match",
            message="skipped",
        )
        pass_result = EvalResult(
            predicate_id="pass-pred",
            result=ResultType.PASS,
            status_code="claimSignature.validated",
            message="ok",
        )
        store = self._make_store()
        report = self._make_report(results=[skip_result, pass_result])
        result = serialize_to_crjson(store, report, None, {})
        vr = result["manifests"][0]["validationResults"]
        # The SKIP result must not appear anywhere
        all_codes = (
            [e["code"] for e in vr["success"]]
            + [e["code"] for e in vr["informational"]]
            + [e["code"] for e in vr["failure"]]
        )
        # skip_result's status code won't appear from a SKIP result
        # pass_result's code should appear
        assert "claimSignature.validated" in all_codes
        # Total entries should be 1, not 2
        total = len(vr["success"]) + len(vr["informational"]) + len(vr["failure"])
        assert total == 1

    def test_bytes_in_assertion_data_encoded_as_b64(self) -> None:
        assertions = [MockAssertion("c2pa.hash.data", {"pad": b"\xde\xad\xbe\xef"})]
        store = self._make_store(assertions=assertions)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        pad_value = result["manifests"][0]["assertions"]["c2pa.hash.data"]["pad"]
        assert isinstance(pad_value, str)
        assert pad_value.startswith("b64'")
        assert pad_value.endswith("'")

    def test_fail_result_in_failure_list(self) -> None:
        fail_result = EvalResult(
            predicate_id="fail-pred",
            result=ResultType.FAIL,
            status_code="assertion.dataHash.mismatch",
            message="hash mismatch",
        )
        store = self._make_store()
        report = self._make_report(results=[fail_result])
        result = serialize_to_crjson(store, report, None, {})
        vr = result["manifests"][0]["validationResults"]
        assert len(vr["failure"]) == 1
        assert vr["failure"][0]["code"] == "assertion.dataHash.mismatch"

    def test_informational_result_in_informational_list(self) -> None:
        info_result = EvalResult(
            predicate_id="info-pred",
            result=ResultType.INFORMATIONAL,
            status_code="algorithm.deprecated",
            message="old algorithm",
        )
        store = self._make_store()
        report = self._make_report(results=[info_result])
        result = serialize_to_crjson(store, report, None, {})
        vr = result["manifests"][0]["validationResults"]
        assert len(vr["informational"]) == 1
        assert vr["informational"][0]["code"] == "algorithm.deprecated"

    def test_multiple_manifests_reversed_order(self) -> None:
        m1 = MockManifest(label="urn:c2pa:ingredient", assertions=[], claim=MockClaim())
        m2 = MockManifest(label="urn:c2pa:active", assertions=[], claim=MockClaim())
        store = MockManifestStore(manifests=[m1, m2], active_manifest=m2)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        # Active manifest (last in store) appears first in output
        assert result["manifests"][0]["label"] == "urn:c2pa:active"
        assert result["manifests"][1]["label"] == "urn:c2pa:ingredient"

    def test_generator_version_from_context(self) -> None:
        store = self._make_store()
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {"generator_version": "9.9.9"})
        assert result["jsonGenerator"]["version"] == "9.9.9"

    def test_spec_version_in_validation_results(self) -> None:
        store = self._make_store()
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {}, spec_version="2.1")
        vr = result["manifests"][0]["validationResults"]
        assert vr["specVersion"] == "2.1"

    def test_empty_store_produces_empty_manifests_list(self) -> None:
        store = MockManifestStore(manifests=[], active_manifest=None)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        assert result["manifests"] == []

    def test_no_claim_omits_claim_v2(self) -> None:
        manifest = MockManifest(label="urn:c2pa:no-claim", assertions=[], claim=None)
        store = MockManifestStore(manifests=[manifest], active_manifest=manifest)
        report = self._make_report()
        result = serialize_to_crjson(store, report, None, {})
        manifest_entry = result["manifests"][0]
        assert "claim.v2" not in manifest_entry


# ---------------------------------------------------------------------------
# parse_rubric tests
# ---------------------------------------------------------------------------


MINIMAL_RUBRIC_YAML = """\
rubric_metadata:
  name: Test Rubric
  version: 1.0.0
---
- id: test:check_one
  expression: "manifests[0].label != null"
  report_text:
    'true':
      en: Label exists
    'false':
      en: Missing label
"""


class TestParseRubric:
    """Tests for rubric YAML parsing."""

    def test_metadata_extracted(self, tmp_path: Path) -> None:
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)
        metadata, statements = parse_rubric(rubric_file)
        assert metadata["rubric_metadata"]["name"] == "Test Rubric"
        assert metadata["rubric_metadata"]["version"] == "1.0.0"

    def test_statements_extracted(self, tmp_path: Path) -> None:
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)
        _, statements = parse_rubric(rubric_file)
        assert len(statements) == 1
        assert statements[0]["id"] == "test:check_one"

    def test_statement_has_expression(self, tmp_path: Path) -> None:
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)
        _, statements = parse_rubric(rubric_file)
        assert statements[0]["expression"] == "manifests[0].label != null"

    def test_statement_has_report_text(self, tmp_path: Path) -> None:
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)
        _, statements = parse_rubric(rubric_file)
        rt = statements[0]["report_text"]
        assert "true" in rt
        assert rt["true"]["en"] == "Label exists"

    def test_empty_yaml_returns_empty(self, tmp_path: Path) -> None:
        rubric_file = tmp_path / "empty.yaml"
        rubric_file.write_text("")
        metadata, statements = parse_rubric(rubric_file)
        assert metadata == {}
        assert statements == []

    def test_multiple_statement_docs(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: Multi Doc
  version: 2.0.0
---
- id: check.one
  expression: "manifests[0].label"
  report_text:
    'true':
      en: "Label found"
    'false':
      en: "No label"
- id: check.two
  expression: "manifests[0].validationResults"
  report_text:
    'true':
      en: "Results found"
    'false':
      en: "No results"
"""
        rubric_file = tmp_path / "multi.yaml"
        rubric_file.write_text(yaml_content)
        metadata, statements = parse_rubric(rubric_file)
        assert metadata["rubric_metadata"]["name"] == "Multi Doc"
        assert len(statements) == 2
        assert statements[0]["id"] == "check.one"
        assert statements[1]["id"] == "check.two"


# ---------------------------------------------------------------------------
# evaluate_rubric tests
# ---------------------------------------------------------------------------

_SAMPLE_CRJSON: dict[str, Any] = {
    "manifests": [
        {
            "label": "urn:c2pa:test",
            "assertions": {},
            "claim.v2": {"instanceID": "test-id"},
            "signature": {"algorithm": "es256"},
            "validationResults": {
                "success": [{"code": "claimSignature.validated"}],
                "informational": [],
                "failure": [],
            },
        }
    ]
}


class TestEvaluateRubric:
    """Tests for rubric expression evaluation against crJSON data."""

    def test_truthy_expression_returns_true(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: True Test
  version: 1.0.0
---
- id: check.label_exists
  expression: "manifests[0].label"
  report_text:
    'true':
      en: "Label present"
    'false':
      en: "No label"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(_SAMPLE_CRJSON, rubric_path=rubric_file)
        assert len(report.results) == 1
        assert report.results[0].value is True
        assert report.results[0].report_text == "Label present"

    def test_falsy_expression_returns_false(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: False Test
  version: 1.0.0
---
- id: check.missing_field
  expression: "manifests[0].nonexistent_field"
  report_text:
    'true':
      en: "Field found"
    'false':
      en: "Field missing"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(_SAMPLE_CRJSON, rubric_path=rubric_file)
        assert report.results[0].value is False
        assert report.results[0].report_text == "Field missing"

    def test_fail_if_matched_empty_list_passes(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: FailIfMatched Test
  version: 1.0.0
---
- id: check.no_failures
  expression: "manifests[0].validationResults.failure"
  fail_if_matched: true
  report_text:
    'true':
      en: "No failures found"
    'false':
      en: "Failures detected: {{matches}}"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(_SAMPLE_CRJSON, rubric_path=rubric_file)
        # failure list is empty -> fail_if_matched -> value=True (no offenders)
        assert report.results[0].value is True

    def test_fail_if_matched_nonempty_list_fails(self, tmp_path: Path) -> None:
        crjson_with_failures: dict[str, Any] = {
            "manifests": [
                {
                    "label": "urn:c2pa:test",
                    "validationResults": {
                        "success": [],
                        "informational": [],
                        "failure": [
                            {"code": "assertion.dataHash.mismatch"},
                            {"code": "claim.malformed"},
                        ],
                    },
                }
            ]
        }
        yaml_content = """\
rubric_metadata:
  name: FailIfMatched NonEmpty
  version: 1.0.0
---
- id: check.failures
  expression: "manifests[0].validationResults.failure[].code"
  fail_if_matched: true
  report_text:
    'true':
      en: "No failures"
    'false':
      en: "Failures: {{matches}}"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(crjson_with_failures, rubric_path=rubric_file)
        assert report.results[0].value is False
        assert report.results[0].matches is not None
        assert len(report.results[0].matches) == 2

    def test_matches_interpolation_in_report_text(self, tmp_path: Path) -> None:
        crjson_with_failures: dict[str, Any] = {
            "manifests": [
                {
                    "label": "urn:c2pa:test",
                    "validationResults": {
                        "success": [],
                        "informational": [],
                        "failure": [{"code": "claim.malformed"}],
                    },
                }
            ]
        }
        yaml_content = """\
rubric_metadata:
  name: Interpolation Test
  version: 1.0.0
---
- id: check.failures
  expression: "manifests[0].validationResults.failure[].code"
  fail_if_matched: true
  report_text:
    'true':
      en: "All good"
    'false':
      en: "Found issues: {{matches}}"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(crjson_with_failures, rubric_path=rubric_file)
        assert report.results[0].value is False
        assert "claim.malformed" in report.results[0].report_text

    def test_jmespath_error_sets_error_field(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: Error Test
  version: 1.0.0
---
- id: check.bad_expr
  expression: "manifests[invalid syntax @#$"
  report_text:
    'true':
      en: "ok"
    'false':
      en: "fail"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(_SAMPLE_CRJSON, rubric_path=rubric_file)
        assert report.results[0].error is not None
        assert report.results[0].value is False

    def test_evaluate_with_statements_and_metadata_directly(self) -> None:
        metadata = {"rubric_metadata": {"name": "Direct", "version": "0.1.0"}}
        statements = [
            {
                "id": "direct.check",
                "expression": "manifests[0].label",
                "report_text": {"true": {"en": "found"}, "false": {"en": "missing"}},
            }
        ]
        report = evaluate_rubric(_SAMPLE_CRJSON, statements=statements, metadata=metadata)
        assert report.rubric_name == "Direct"
        assert report.results[0].value is True

    def test_multiple_statements_evaluated(self, tmp_path: Path) -> None:
        yaml_content = """\
rubric_metadata:
  name: Multi Check
  version: 1.0.0
---
- id: check.label
  expression: "manifests[0].label"
  report_text:
    'true':
      en: "Label found"
    'false':
      en: "No label"
- id: check.missing
  expression: "manifests[0].does_not_exist"
  report_text:
    'true':
      en: "Found"
    'false':
      en: "Missing"
"""
        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(yaml_content)
        report = evaluate_rubric(_SAMPLE_CRJSON, rubric_path=rubric_file)
        assert len(report.results) == 2
        assert report.results[0].value is True
        assert report.results[1].value is False


# ---------------------------------------------------------------------------
# RubricReport properties tests
# ---------------------------------------------------------------------------


class TestRubricReportProperties:
    """Tests for RubricReport pass_count and fail_count."""

    def test_pass_count_empty(self) -> None:
        report = RubricReport(rubric_name="Test", rubric_version="1.0")
        assert report.pass_count == 0

    def test_fail_count_empty(self) -> None:
        report = RubricReport(rubric_name="Test", rubric_version="1.0")
        assert report.fail_count == 0

    def test_pass_count(self) -> None:
        results = [
            RubricResult(id="a", description="", value=True, report_text="ok"),
            RubricResult(id="b", description="", value=True, report_text="ok"),
            RubricResult(id="c", description="", value=False, report_text="fail"),
        ]
        report = RubricReport(rubric_name="Test", rubric_version="1.0", results=results)
        assert report.pass_count == 2

    def test_fail_count(self) -> None:
        results = [
            RubricResult(id="a", description="", value=True, report_text="ok"),
            RubricResult(id="b", description="", value=False, report_text="fail"),
            RubricResult(id="c", description="", value=False, report_text="fail"),
        ]
        report = RubricReport(rubric_name="Test", rubric_version="1.0", results=results)
        assert report.fail_count == 2

    def test_pass_plus_fail_equals_total(self) -> None:
        results = [
            RubricResult(id="a", description="", value=True, report_text="ok"),
            RubricResult(id="b", description="", value=False, report_text="fail"),
            RubricResult(id="c", description="", value=True, report_text="ok"),
        ]
        report = RubricReport(rubric_name="Test", rubric_version="1.0", results=results)
        assert report.pass_count + report.fail_count == len(results)

    def test_to_dict_structure(self) -> None:
        results = [
            RubricResult(id="x", description="desc", value=True, report_text="yes"),
        ]
        report = RubricReport(rubric_name="MyRubric", rubric_version="3.0", results=results)
        d = report.to_dict()
        assert d["rubric_name"] == "MyRubric"
        assert d["rubric_version"] == "3.0"
        assert d["pass_count"] == 1
        assert d["fail_count"] == 0
        assert len(d["results"]) == 1

    def test_result_to_dict_includes_error_when_set(self) -> None:
        r = RubricResult(
            id="err",
            description="",
            value=False,
            report_text="",
            error="something went wrong",
        )
        d = r.to_dict()
        assert "error" in d
        assert d["error"] == "something went wrong"

    def test_result_to_dict_includes_matches_when_set(self) -> None:
        r = RubricResult(
            id="match",
            description="",
            value=False,
            report_text="",
            matches=["item1", "item2"],
        )
        d = r.to_dict()
        assert "matches" in d
        assert d["matches"] == ["item1", "item2"]

    def test_result_to_dict_omits_error_when_none(self) -> None:
        r = RubricResult(id="ok", description="", value=True, report_text="yes")
        d = r.to_dict()
        assert "error" not in d

    def test_result_to_dict_omits_matches_when_none(self) -> None:
        r = RubricResult(id="ok", description="", value=True, report_text="yes")
        d = r.to_dict()
        assert "matches" not in d


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestRubricCliIntegration:
    """Tests for the rubric CLI command."""

    def test_rubric_help_shows_expected_options(self) -> None:
        from click.testing import CliRunner

        from c2pa_conformance.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["rubric", "--help"])
        assert result.exit_code == 0
        output = result.output
        assert "--rubric" in output
        assert "--crjson-input" in output or "crjson" in output.lower()
        assert "--output" in output

    def test_rubric_command_with_crjson_input(self, tmp_path: Path) -> None:
        import json

        from click.testing import CliRunner

        from c2pa_conformance.cli import cli

        crjson_file = tmp_path / "input.crjson.json"
        crjson_file.write_text(json.dumps(_SAMPLE_CRJSON))

        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["rubric", "--rubric", str(rubric_file), "--crjson-input", str(crjson_file)],
        )
        assert result.exit_code == 0
        assert "Test Rubric" in result.output

    def test_rubric_command_json_format(self, tmp_path: Path) -> None:
        import json

        from click.testing import CliRunner

        from c2pa_conformance.cli import cli

        crjson_file = tmp_path / "input.crjson.json"
        crjson_file.write_text(json.dumps(_SAMPLE_CRJSON))

        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rubric",
                "--rubric",
                str(rubric_file),
                "--crjson-input",
                str(crjson_file),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        # The CLI may emit a status line before the JSON block; extract from first '{'
        json_start = result.output.index("{")
        parsed = json.loads(result.output[json_start:])
        assert "rubric_name" in parsed
        assert "results" in parsed

    def test_rubric_command_writes_output_file(self, tmp_path: Path) -> None:
        import json

        from click.testing import CliRunner

        from c2pa_conformance.cli import cli

        crjson_file = tmp_path / "input.crjson.json"
        crjson_file.write_text(json.dumps(_SAMPLE_CRJSON))

        rubric_file = tmp_path / "rubric.yaml"
        rubric_file.write_text(MINIMAL_RUBRIC_YAML)

        output_file = tmp_path / "report.json"

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "rubric",
                "--rubric",
                str(rubric_file),
                "--crjson-input",
                str(crjson_file),
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "rubric_name" in data
