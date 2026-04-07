"""Tests for c2pa-tool comparison runner, normalizer, and diff engine."""

from __future__ import annotations

from c2pa_conformance.compare.diff import ComparisonResult, DiffEntry, compare_results
from c2pa_conformance.compare.normalizer import (
    _FAIL_CODES,
    _PASS_CODES,
    NormalizedReport,
    NormalizedResult,
    _classify_status_code,
    normalize_c2pa_tool_output,
)
from c2pa_conformance.compare.report import format_report_text, generate_report
from c2pa_conformance.compare.runner import find_c2pa_tool, is_available

# ---------------------------------------------------------------------------
# Runner tests
# ---------------------------------------------------------------------------


class TestRunner:
    def test_is_available(self) -> None:
        result = is_available()
        assert isinstance(result, bool)

    def test_find_c2pa_tool(self) -> None:
        result = find_c2pa_tool()
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# Normalizer tests
# ---------------------------------------------------------------------------


class TestNormalizerEmpty:
    def test_normalize_empty(self) -> None:
        report = normalize_c2pa_tool_output(None)
        assert isinstance(report, NormalizedReport)
        assert report.manifest_count == 0
        assert report.active_manifest == ""
        assert report.results == []
        assert report.raw_validation_status == []

    def test_normalize_empty_dict(self) -> None:
        report = normalize_c2pa_tool_output({})
        assert report.manifest_count == 0
        assert report.results == []


class TestNormalizerValidOutput:
    def _make_output(
        self,
        label: str = "urn:uuid:test-manifest",
        validation_status: list | None = None,
    ) -> dict:
        if validation_status is None:
            validation_status = [
                {
                    "code": "assertion.dataHash.match",
                    "url": "self#jumbf=/c2pa/urn:uuid:test/c2pa.assertions/c2pa.hash.data",
                    "explanation": "Data hash validated successfully.",
                },
            ]
        return {
            "manifests": {
                label: {
                    "claim_generator": "test_tool/1.0",
                    "validation_status": validation_status,
                }
            },
            "active_manifest": label,
        }

    def test_normalize_valid_output(self) -> None:
        output = self._make_output()
        report = normalize_c2pa_tool_output(output)
        assert report.manifest_count == 1
        assert report.active_manifest == "urn:uuid:test-manifest"
        assert len(report.results) == 1
        result = report.results[0]
        assert result.status_code == "assertion.dataHash.match"
        assert result.result == "pass"
        assert "hash" in result.message.lower() or result.message != ""

    def test_normalize_multiple_status_codes(self) -> None:
        output = self._make_output(
            validation_status=[
                {"code": "assertion.dataHash.match", "explanation": "ok"},
                {"code": "claimSignature.validated", "explanation": "sig ok"},
                {"code": "assertion.dataHash.mismatch", "explanation": "bad hash"},
            ]
        )
        report = normalize_c2pa_tool_output(output)
        assert len(report.results) == 3
        codes = {r.status_code for r in report.results}
        assert "assertion.dataHash.match" in codes
        assert "claimSignature.validated" in codes
        assert "assertion.dataHash.mismatch" in codes

    def test_raw_validation_status_preserved(self) -> None:
        entries = [{"code": "claimSignature.validated", "explanation": "ok"}]
        output = self._make_output(validation_status=entries)
        report = normalize_c2pa_tool_output(output)
        assert report.raw_validation_status == entries

    def test_skips_non_dict_entries(self) -> None:
        output = self._make_output(
            validation_status=[
                "not-a-dict",
                {"code": "claimSignature.validated", "explanation": "ok"},
            ]
        )
        report = normalize_c2pa_tool_output(output)
        assert len(report.results) == 1

    def test_active_manifest_not_in_manifests(self) -> None:
        output = {
            "manifests": {},
            "active_manifest": "urn:uuid:missing",
        }
        report = normalize_c2pa_tool_output(output)
        assert report.results == []
        assert report.manifest_count == 0


class TestClassifyStatusCode:
    def test_classify_pass_codes(self) -> None:
        for code in _PASS_CODES:
            assert _classify_status_code(code) == "pass", f"Expected pass for {code}"

    def test_classify_fail_codes(self) -> None:
        for code in _FAIL_CODES:
            assert _classify_status_code(code) == "fail", f"Expected fail for {code}"

    def test_classify_unknown_code_informational(self) -> None:
        assert _classify_status_code("assertion.something.unknown") == "informational"

    def test_classify_heuristic_pass_match(self) -> None:
        assert _classify_status_code("some.custom.match") == "pass"

    def test_classify_heuristic_pass_validated(self) -> None:
        assert _classify_status_code("some.custom.validated") == "pass"

    def test_classify_heuristic_pass_trusted(self) -> None:
        assert _classify_status_code("custom.trusted") == "pass"

    def test_classify_heuristic_fail_mismatch(self) -> None:
        assert _classify_status_code("assertion.custom.mismatch") == "fail"

    def test_classify_heuristic_fail_missing(self) -> None:
        assert _classify_status_code("claim.missing") == "fail"

    def test_classify_heuristic_fail_invalid(self) -> None:
        assert _classify_status_code("cert.invalid") == "fail"

    def test_classify_heuristic_fail_revoked(self) -> None:
        assert _classify_status_code("cert.revoked") == "fail"

    def test_classify_heuristic_fail_malformed(self) -> None:
        assert _classify_status_code("data.malformed") == "fail"

    def test_classify_empty_string(self) -> None:
        assert _classify_status_code("") == "informational"


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


def _make_tool_report(
    entries: list[tuple[str, str]],
    asset_path: str = "test.jpg",
) -> NormalizedReport:
    """Build a NormalizedReport from (code, result) pairs."""
    report = NormalizedReport(asset_path=asset_path)
    for code, result in entries:
        report.results.append(NormalizedResult(status_code=code, result=result))
    return report


def _suite_result(code: str, result: str) -> dict:
    return {"status_code": code, "result": result}


class TestCompareResults:
    def test_compare_all_agree(self) -> None:
        suite = [
            _suite_result("assertion.dataHash.match", "pass"),
            _suite_result("claimSignature.validated", "pass"),
        ]
        tool_report = _make_tool_report(
            [
                ("assertion.dataHash.match", "pass"),
                ("claimSignature.validated", "pass"),
            ]
        )
        result = compare_results(suite, tool_report)
        assert result.total_codes == 2
        assert result.agreements == 2
        assert result.divergences == 0
        assert result.suite_only == 0
        assert result.tool_only == 0

    def test_compare_divergence(self) -> None:
        suite = [_suite_result("assertion.dataHash.match", "pass")]
        tool_report = _make_tool_report([("assertion.dataHash.match", "fail")])
        result = compare_results(suite, tool_report)
        assert result.divergences == 1
        assert result.agreements == 0
        entry = result.entries[0]
        assert entry.category == "divergence"
        assert entry.suite_result == "pass"
        assert entry.tool_result == "fail"

    def test_compare_suite_only(self) -> None:
        suite = [_suite_result("assertion.dataHash.match", "pass")]
        tool_report = _make_tool_report([])
        result = compare_results(suite, tool_report)
        assert result.suite_only == 1
        assert result.tool_only == 0
        assert result.divergences == 0
        entry = result.entries[0]
        assert entry.category == "suite_only"
        assert entry.tool_result == "not_reported"

    def test_compare_tool_only(self) -> None:
        suite: list[dict] = []
        tool_report = _make_tool_report([("claimSignature.validated", "pass")])
        result = compare_results(suite, tool_report)
        assert result.tool_only == 1
        assert result.suite_only == 0
        assert result.divergences == 0
        entry = result.entries[0]
        assert entry.category == "tool_only"
        assert entry.suite_result == "not_evaluated"

    def test_compare_mixed(self) -> None:
        suite = [
            _suite_result("assertion.dataHash.match", "pass"),  # agreement
            _suite_result("claimSignature.validated", "pass"),  # divergence (tool says fail)
            _suite_result("signingCredential.trusted", "pass"),  # suite_only (tool missing)
        ]
        tool_report = _make_tool_report(
            [
                ("assertion.dataHash.match", "pass"),  # agreement
                ("claimSignature.validated", "fail"),  # divergence
                ("timeStamp.trusted", "pass"),  # tool_only
            ]
        )
        result = compare_results(suite, tool_report)
        assert result.total_codes == 4
        assert result.agreements == 1
        assert result.divergences == 1
        assert result.suite_only == 1
        assert result.tool_only == 1

    def test_agreement_percentage_full(self) -> None:
        suite = [_suite_result("assertion.dataHash.match", "pass")]
        tool_report = _make_tool_report([("assertion.dataHash.match", "pass")])
        result = compare_results(suite, tool_report)
        assert result.agreement_pct == 100.0

    def test_agreement_percentage_half(self) -> None:
        suite = [
            _suite_result("assertion.dataHash.match", "pass"),
            _suite_result("claimSignature.validated", "pass"),
        ]
        tool_report = _make_tool_report(
            [
                ("assertion.dataHash.match", "pass"),
                ("claimSignature.validated", "fail"),
            ]
        )
        result = compare_results(suite, tool_report)
        assert result.agreement_pct == 50.0

    def test_agreement_percentage_no_codes(self) -> None:
        result = compare_results([], _make_tool_report([]))
        assert result.agreement_pct == 100.0

    def test_asset_path_propagated(self) -> None:
        tool_report = _make_tool_report([], asset_path="/path/to/file.jpg")
        result = compare_results([], tool_report)
        assert result.asset_path == "/path/to/file.jpg"

    def test_entries_sorted_by_code(self) -> None:
        suite = [
            _suite_result("z.code", "pass"),
            _suite_result("a.code", "pass"),
        ]
        tool_report = _make_tool_report([("z.code", "pass"), ("a.code", "pass")])
        result = compare_results(suite, tool_report)
        codes = [e.status_code for e in result.entries]
        assert codes == sorted(codes)


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------


def _make_comparison(
    asset_path: str = "sample.jpg",
    entries: list[DiffEntry] | None = None,
) -> ComparisonResult:
    if entries is None:
        entries = []
    c = ComparisonResult(asset_path=asset_path)
    c.entries = entries
    c.total_codes = len(entries)
    for e in entries:
        if e.category == "agreement":
            c.agreements += 1
        elif e.category == "divergence":
            c.divergences += 1
        elif e.category == "suite_only":
            c.suite_only += 1
        elif e.category == "tool_only":
            c.tool_only += 1
    return c


class TestGenerateReport:
    def test_generate_report_json_structure(self) -> None:
        comparison = _make_comparison()
        report = generate_report(comparison)
        assert "asset_path" in report
        assert "summary" in report
        assert "entries" in report
        summary = report["summary"]
        assert "total_codes" in summary
        assert "agreements" in summary
        assert "divergences" in summary
        assert "suite_only" in summary
        assert "tool_only" in summary
        assert "agreement_percentage" in summary

    def test_generate_report_values(self) -> None:
        entries = [
            DiffEntry(
                status_code="assertion.dataHash.match",
                suite_result="pass",
                tool_result="pass",
                category="agreement",
            ),
            DiffEntry(
                status_code="claimSignature.validated",
                suite_result="pass",
                tool_result="fail",
                category="divergence",
            ),
        ]
        comparison = _make_comparison(entries=entries)
        report = generate_report(comparison)
        assert report["asset_path"] == "sample.jpg"
        assert report["summary"]["total_codes"] == 2
        assert report["summary"]["agreements"] == 1
        assert report["summary"]["divergences"] == 1
        assert len(report["entries"]) == 2

    def test_generate_report_entry_fields(self) -> None:
        entries = [
            DiffEntry(
                status_code="assertion.dataHash.match",
                suite_result="pass",
                tool_result="pass",
                category="agreement",
                message="all good",
            )
        ]
        comparison = _make_comparison(entries=entries)
        report = generate_report(comparison)
        entry = report["entries"][0]
        assert entry["status_code"] == "assertion.dataHash.match"
        assert entry["suite_result"] == "pass"
        assert entry["tool_result"] == "pass"
        assert entry["category"] == "agreement"
        assert entry["message"] == "all good"

    def test_generate_report_agreement_pct_rounded(self) -> None:
        comparison = _make_comparison()
        report = generate_report(comparison)
        # Empty -> 100.0
        assert report["summary"]["agreement_percentage"] == 100.0


class TestFormatReportText:
    def test_format_report_text_contains_key_info(self) -> None:
        comparison = _make_comparison(asset_path="my_asset.jpg")
        text = format_report_text(comparison)
        assert "my_asset.jpg" in text
        assert "Total status codes" in text
        assert "Agreements" in text
        assert "Divergences" in text
        assert "Suite-only" in text
        assert "Tool-only" in text

    def test_format_report_with_divergences(self) -> None:
        entries = [
            DiffEntry(
                status_code="assertion.dataHash.match",
                suite_result="pass",
                tool_result="fail",
                category="divergence",
            )
        ]
        comparison = _make_comparison(entries=entries)
        text = format_report_text(comparison)
        assert "Divergences:" in text
        assert "assertion.dataHash.match" in text
        assert "suite=pass" in text
        assert "tool=fail" in text

    def test_format_report_no_divergences_section(self) -> None:
        entries = [
            DiffEntry(
                status_code="assertion.dataHash.match",
                suite_result="pass",
                tool_result="pass",
                category="agreement",
            )
        ]
        comparison = _make_comparison(entries=entries)
        text = format_report_text(comparison)
        # The summary line "Divergences: 0" is expected; the section header "Divergences:"
        # followed by a newline (no trailing digit on that line) must NOT appear.
        assert "\nDivergences:\n" not in text

    def test_format_report_agreement_percentage_in_text(self) -> None:
        entries = [
            DiffEntry(
                status_code="assertion.dataHash.match",
                suite_result="pass",
                tool_result="pass",
                category="agreement",
            )
        ]
        comparison = _make_comparison(entries=entries)
        text = format_report_text(comparison)
        assert "100.0%" in text
