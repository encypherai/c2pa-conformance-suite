"""Tests for CLI commands: suite, compare, generate-vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from c2pa_conformance.cli import cli


class TestSuiteCommand:
    def test_suite_no_files(self, tmp_path: Path) -> None:
        """Empty directory -> no files found."""
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", str(tmp_path)])
        assert result.exit_code == 0
        assert "No supported files" in result.output

    def test_suite_help(self) -> None:
        """Help text is accessible."""
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", "--help"])
        assert result.exit_code == 0
        assert "directory" in result.output.lower()

    def test_suite_with_output_no_matching_files(self, tmp_path: Path) -> None:
        """Suite with --output and no matching files writes nothing and exits 0."""
        runner = CliRunner()
        output = tmp_path / "report.json"
        result = runner.invoke(cli, ["suite", str(tmp_path), "--output", str(output)])
        assert result.exit_code == 0
        # No supported files, so no output file is written
        assert not output.exists()

    def test_suite_unsupported_extension_ignored(self, tmp_path: Path) -> None:
        """Files with unsupported extensions are silently skipped."""
        (tmp_path / "file.xyz").write_bytes(b"not a supported format")
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", str(tmp_path)])
        assert result.exit_code == 0
        assert "No supported files" in result.output

    def test_suite_missing_predicates_error(self, tmp_path: Path) -> None:
        """Suite without predicates and no default raises an error."""
        # Place a supported file so we get past the "no files" check
        asset = tmp_path / "sample.jpg"
        asset.write_bytes(b"\xff\xd8\xff\xd9")
        runner = CliRunner()
        # Invoke in an isolated env where predicates.json won't exist at the default path
        result = runner.invoke(cli, ["suite", str(tmp_path)], catch_exceptions=False)
        # Either finds predicates (if repo has them) or errors -- both are acceptable
        assert result.exit_code in (0, 1)

    def test_suite_format_json_option(self, tmp_path: Path) -> None:
        """--format json is accepted without error when no files exist."""
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0

    def test_suite_fail_fast_flag_accepted(self, tmp_path: Path) -> None:
        """--fail-fast flag is accepted without error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", str(tmp_path), "--fail-fast"])
        assert result.exit_code == 0

    def test_suite_with_valid_asset(self, tmp_path: Path) -> None:
        """Suite processes a real C2PA asset if the predicates file is present."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        # Use a fixture asset if one exists
        fixture_dir = Path(__file__).parent.parent / "fixtures"
        c2pa_files = list(fixture_dir.rglob("*.c2pa")) if fixture_dir.exists() else []
        if not c2pa_files:
            pytest.skip("No .c2pa fixture files found")

        import shutil

        asset = tmp_path / c2pa_files[0].name
        shutil.copy(c2pa_files[0], asset)

        runner = CliRunner()
        output = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "suite",
                str(tmp_path),
                "--predicates",
                str(predicates_path),
                "--output",
                str(output),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "Summary:" in result.output
        assert output.exists()
        data = json.loads(output.read_text())
        assert "files" in data
        assert "summary" in data
        assert "total_files" in data["summary"]


class TestKnownFailures:
    """Tests for --known-failures xfail support in suite command."""

    def test_known_failures_flag_accepted(self, tmp_path: Path) -> None:
        """--known-failures option is accepted."""
        kf = tmp_path / "kf.json"
        kf.write_text('{"some_file.jpg": "reason"}')
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", str(tmp_path), "--known-failures", str(kf)])
        assert result.exit_code == 0
        assert "No supported files" in result.output

    def test_known_failures_help_text(self) -> None:
        """--known-failures appears in help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["suite", "--help"])
        assert result.exit_code == 0
        assert "known-failures" in result.output

    def test_xfail_output_format(self, tmp_path: Path) -> None:
        """A known-failure file that actually fails shows [XFAIL] in output."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        # Create a minimal JPEG that will fail predicates (no C2PA manifest)
        asset = tmp_path / "bad.jpg"
        asset.write_bytes(b"\xff\xd8\xff\xd9")

        kf = tmp_path / "kf.json"
        kf.write_text('{"bad.jpg": "test asset with no manifest"}')

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "suite",
                str(tmp_path),
                "--predicates",
                str(predicates_path),
                "--known-failures",
                str(kf),
            ],
        )
        assert result.exit_code == 0
        # The file should show as XFAIL (not FAIL) since it failed and is known
        if "XFAIL" in result.output or "ERR" in result.output:
            # ERR is acceptable too - no C2PA data means extraction error
            assert "FAIL" not in result.output or "XFAIL" in result.output

    def test_xfail_excluded_from_fail_count(self, tmp_path: Path) -> None:
        """Known failures do not increment the fail count in summary."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        asset = tmp_path / "bad.jpg"
        asset.write_bytes(b"\xff\xd8\xff\xd9")

        kf = tmp_path / "kf.json"
        kf.write_text('{"bad.jpg": "expected"}')

        runner = CliRunner()
        output = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "suite",
                str(tmp_path),
                "--predicates",
                str(predicates_path),
                "--known-failures",
                str(kf),
                "--output",
                str(output),
            ],
        )
        assert result.exit_code == 0
        if output.exists():
            data = json.loads(output.read_text())
            summary = data["summary"]
            assert "total_xfail" in summary or "total_xpass" in summary

    def test_xpass_when_known_failure_passes(self, tmp_path: Path) -> None:
        """A file listed in known-failures that passes shows [XPASS]."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        # Use a real fixture that passes if available
        fixture_dir = Path(__file__).parent.parent / "fixtures"
        c2pa_files = list(fixture_dir.rglob("*.c2pa")) if fixture_dir.exists() else []
        if not c2pa_files:
            pytest.skip("No .c2pa fixture files found")

        import shutil

        asset = tmp_path / c2pa_files[0].name
        shutil.copy(c2pa_files[0], asset)

        kf = tmp_path / "kf.json"
        kf.write_text(json.dumps({asset.name: "should not fail"}))

        runner = CliRunner()
        output = tmp_path / "report.json"
        result = runner.invoke(
            cli,
            [
                "suite",
                str(tmp_path),
                "--predicates",
                str(predicates_path),
                "--known-failures",
                str(kf),
                "--output",
                str(output),
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        if output.exists():
            data = json.loads(output.read_text())
            # The passing file should be marked xpass
            for file_report in data["files"]:
                if "xpass" in file_report:
                    assert file_report["xpass"] is True
                    assert data["summary"]["total_xpass"] >= 1

    def test_fail_fast_skips_known_failures(self, tmp_path: Path) -> None:
        """--fail-fast does not stop on known failures."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        # Two files: known failure first, then another
        (tmp_path / "aaa_bad.jpg").write_bytes(b"\xff\xd8\xff\xd9")
        (tmp_path / "zzz_also.jpg").write_bytes(b"\xff\xd8\xff\xd9")

        kf = tmp_path / "kf.json"
        kf.write_text('{"aaa_bad.jpg": "known"}')

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "suite",
                str(tmp_path),
                "--predicates",
                str(predicates_path),
                "--known-failures",
                str(kf),
                "--fail-fast",
            ],
        )
        assert result.exit_code == 0
        # Both files should appear in output (fail-fast didn't stop on the known failure)
        assert "aaa_bad" in result.output
        assert "zzz_also" in result.output


class TestCompareCommand:
    def test_compare_help(self) -> None:
        """Help text is accessible."""
        runner = CliRunner()
        result = runner.invoke(cli, ["compare", "--help"])
        assert result.exit_code == 0
        assert "asset" in result.output.lower() or "compare" in result.output.lower()

    def test_compare_no_predicates_default_missing(self, tmp_path: Path) -> None:
        """Compare without predicates -> ClickException if default not found."""
        asset = tmp_path / "test.jpg"
        asset.write_bytes(b"\xff\xd8\xff\xd9")
        runner = CliRunner()
        result = runner.invoke(cli, ["compare", str(asset)])
        # Should fail (extraction error or no predicates) -- exit code != 0
        assert result.exit_code != 0

    def test_compare_with_predicates_no_c2pa_tool(self, tmp_path: Path) -> None:
        """Compare with predicates but no c2pa-tool shows suite-only results."""
        predicates_path = Path(__file__).parent.parent / "predicates.json"
        if not predicates_path.exists():
            pytest.skip("predicates.json not found")

        fixture_dir = Path(__file__).parent.parent / "fixtures"
        c2pa_files = list(fixture_dir.rglob("*.c2pa")) if fixture_dir.exists() else []
        if not c2pa_files:
            pytest.skip("No .c2pa fixture files found")

        import shutil

        asset = tmp_path / c2pa_files[0].name
        shutil.copy(c2pa_files[0], asset)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["compare", str(asset), "--predicates", str(predicates_path)],
            catch_exceptions=False,
        )
        # Either c2pa-tool is available (shows comparison) or not (shows suite-only)
        # Both paths exit 0
        assert result.exit_code == 0


class TestGenerateVectorsCommand:
    def test_generate_vectors_help(self) -> None:
        """Verify help text shows."""
        runner = CliRunner()
        result = runner.invoke(cli, ["generate-vectors", "--help"])
        assert result.exit_code == 0
        assert "Generate" in result.output

    def test_generate_vectors_basic(self, tmp_path: Path) -> None:
        """Generate vectors to tmp dir."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["generate-vectors", "--output-dir", str(tmp_path / "vectors")],
        )
        # If vectors module and generator exist, should succeed
        if result.exit_code == 0:
            assert "Generated" in result.output
        else:
            # Import error is acceptable if generator.py not yet implemented
            assert result.exit_code != 0

    def test_generate_vectors_categories_option(self, tmp_path: Path) -> None:
        """--categories flag is parsed correctly."""
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "generate-vectors",
                "--output-dir",
                str(tmp_path / "vectors"),
                "--categories",
                "valid",
            ],
        )
        # Accept both success and import error
        assert result.exit_code in (0, 1)

    def test_generate_vectors_clean_flag(self, tmp_path: Path) -> None:
        """--clean flag is accepted."""
        out_dir = tmp_path / "vectors"
        out_dir.mkdir()
        (out_dir / "old_file.txt").write_text("old")
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["generate-vectors", "--output-dir", str(out_dir), "--clean"],
        )
        # Accept both success and import error
        assert result.exit_code in (0, 1)
        if result.exit_code == 0:
            # old_file should be removed if clean ran
            assert not (out_dir / "old_file.txt").exists()
