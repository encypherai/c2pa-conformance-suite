"""CLI for the C2PA Conformance Suite.

Commands:
    validate          Validate a single asset against conformance predicates.
    suite             Batch validate all assets in a directory.
    compare           Side-by-side comparison with c2pa-tool.
    generate-vectors  Generate deterministic C2PA test vectors.
    generate-pki      Generate test PKI fixtures.
    report            Print a summary conformance report.
"""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.group()
def cli() -> None:
    """C2PA Conformance Suite - deterministic conformance testing."""


@cli.command("generate-pki")
@click.option(
    "--output-dir",
    default="fixtures/pki",
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory to write PKI fixtures.",
)
def generate_pki(output_dir: Path) -> None:
    """Generate test PKI certificate hierarchy."""
    from c2pa_conformance.crypto.pki import generate_test_pki

    click.echo(f"Generating test PKI in {output_dir} ...")
    certs = generate_test_pki(output_dir)
    for name, pair in certs.items():
        click.echo(f"  {name}: {pair.cert.subject}")
    click.echo(f"Done. {len(certs)} certificates generated.")


def _run_validation_pipeline(
    asset_path: Path,
    engine: object,
    trust_store_path: Path | None = None,
) -> tuple[object, dict]:
    """Run the full validation pipeline on a single asset.

    Returns (ConformanceReport, evaluation_context) tuple.
    Raises click.ClickException on extraction or parse failures.
    """
    from c2pa_conformance.crypto.trust import TrustAnchorStore
    from c2pa_conformance.crypto.verifier import (
        build_crypto_context,
        verify_manifest_binding,
        verify_manifest_signature,
    )
    from c2pa_conformance.extractors.base import ExtractionError, detect_and_extract
    from c2pa_conformance.parser.manifest import ManifestParseError, parse_manifest_store

    # Extract
    try:
        extraction = detect_and_extract(asset_path)
    except ExtractionError as exc:
        raise click.ClickException(f"Extraction failed: {exc}") from exc

    # Parse
    try:
        store = parse_manifest_store(extraction.jumbf_bytes)
    except ManifestParseError as exc:
        raise click.ClickException(f"Manifest parsing failed: {exc}") from exc

    # Crypto
    ts = TrustAnchorStore.from_pem_file(trust_store_path) if trust_store_path else None
    sig_result = None
    hash_result = None
    if store.active_manifest:
        sig_result = verify_manifest_signature(store.active_manifest, ts)
        asset_bytes = asset_path.read_bytes()
        hash_result = verify_manifest_binding(store.active_manifest, asset_bytes)

    # Build context
    context = _build_context(store, extraction)
    if sig_result:
        crypto_ctx = build_crypto_context(sig_result, hash_result)
        context.update(crypto_ctx)
    context["asset_bytes"] = asset_path.read_bytes()

    # Evaluate
    report = engine.evaluate_all(context)
    report.asset_path = str(asset_path)

    return report, context


@cli.command("validate")
@click.argument("asset_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--predicates",
    type=click.Path(exists=True, path_type=Path),
    help="Path to predicates.json.",
)
@click.option(
    "--binding",
    type=str,
    default=None,
    help="Filter to a specific binding mechanism (e.g., c2pa.hash.data).",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Write JSON report to file.",
)
@click.option(
    "--trust-store",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to PEM file containing trust anchor certificates.",
)
def validate(
    asset_path: Path,
    predicates: Path | None,
    binding: str | None,
    output: Path | None,
    trust_store: Path | None,
) -> None:
    """Validate a single asset against conformance predicates.

    Runs the full pipeline: extract JUMBF from container, parse manifest
    store, build evaluation context, and evaluate all predicates.
    """
    from c2pa_conformance.crypto.trust import TrustAnchorStore
    from c2pa_conformance.crypto.verifier import (
        build_crypto_context,
        verify_manifest_binding,
        verify_manifest_signature,
    )
    from c2pa_conformance.evaluator.engine import PredicateEngine
    from c2pa_conformance.extractors.base import ExtractionError, detect_and_extract
    from c2pa_conformance.parser.manifest import ManifestParseError, parse_manifest_store

    if predicates is None:
        default = Path(__file__).parent / "data" / "predicates.json"
        if not default.exists():
            raise click.ClickException(
                "No predicates.json found. Use --predicates to specify path."
            )
        predicates = default

    engine = PredicateEngine(predicates)
    click.echo(f"Loaded {engine.predicate_count} predicates for spec v{engine.spec_version}")

    # Step 1: Extract JUMBF from container
    try:
        extraction = detect_and_extract(asset_path)
    except ExtractionError as exc:
        raise click.ClickException(f"Extraction failed: {exc}") from exc

    click.echo(
        f"Extracted {extraction.jumbf_length} bytes of JUMBF "
        f"from {extraction.container_format} container"
    )

    # Step 2: Parse JUMBF into manifest store
    try:
        store = parse_manifest_store(extraction.jumbf_bytes)
    except ManifestParseError as exc:
        raise click.ClickException(f"Manifest parsing failed: {exc}") from exc

    click.echo(
        f"Parsed {store.manifest_count} manifest(s)"
        + (f", active: {store.active_manifest.label}" if store.active_manifest else "")
    )

    # Step 2.5: Crypto verification
    ts = TrustAnchorStore.from_pem_file(trust_store) if trust_store else None

    sig_result = None
    hash_result = None
    if store.active_manifest:
        sig_result = verify_manifest_signature(store.active_manifest, ts)
        click.echo(f"Signature: {sig_result.signature_status}")

        # Step 2.75: Content binding
        asset_bytes = asset_path.read_bytes()
        hash_result = verify_manifest_binding(store.active_manifest, asset_bytes)
        if hash_result.hash_valid is not None:
            click.echo(f"Content binding: {hash_result.hash_status}")

    # Step 3: Build evaluation context from parsed manifest
    context = _build_context(store, extraction)

    # Merge crypto context
    if sig_result:
        crypto_ctx = build_crypto_context(sig_result, hash_result)
        context.update(crypto_ctx)

    # Also add raw asset_bytes to context for operators that need it
    context["asset_bytes"] = asset_path.read_bytes()

    # Step 4: Evaluate predicates
    report = engine.evaluate_all(context, binding=binding)
    report.asset_path = str(asset_path)

    click.echo(
        f"\nResults: {report.pass_count} pass, "
        f"{report.fail_count} fail, "
        f"{report.skip_count} skip "
        f"(of {report.total_count} predicates)"
    )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w") as f:
            json.dump(report.to_dict(), f, indent=2)
            f.write("\n")
        click.echo(f"Report written to {output}")
    else:
        for r in report.results:
            if r.result.value == "fail":
                click.echo(f"  FAIL {r.predicate_id}: {r.status_code} {r.message}")


def _build_context(store: object, extraction: object) -> dict:
    """Build a predicate evaluation context from parsed manifest data.

    Maps the ManifestStore into the flat dict structure that predicates
    reference via dotted field paths.
    """

    context: dict = {
        "asset_path": extraction.container_format,
        "container_format": extraction.container_format,
        "manifest_store": {
            "manifest_count": store.manifest_count,
            "manifests": [],
        },
    }

    for manifest in store.manifests:
        m: dict = {
            "label": manifest.label,
            "assertions": [],
            "claim": {},
            "has_signature": len(manifest.signature_bytes) > 0,
            "signature_bytes_length": len(manifest.signature_bytes),
        }

        if manifest.claim:
            m["claim"] = {
                "claim_generator": manifest.claim.claim_generator,
                "claim_generator_info": manifest.claim.claim_generator_info,
                "signature_ref": manifest.claim.signature_ref,
                "assertion_refs": manifest.claim.assertion_refs,
                "is_update_manifest": manifest.claim.is_update_manifest,
                "data": manifest.claim.data,
            }

        for assertion in manifest.assertions:
            a = {
                "label": assertion.label,
                "data": assertion.data,
                "is_hard_binding": assertion.is_hard_binding,
                "has_raw_cbor": len(assertion.raw_cbor) > 0,
            }
            m["assertions"].append(a)

        context["manifest_store"]["manifests"].append(m)

    # Promote active manifest fields to top level for predicate access
    if store.active_manifest:
        am = store.active_manifest
        context["active_manifest"] = context["manifest_store"]["manifests"][-1]

        if am.claim:
            context["claim"] = context["active_manifest"]["claim"]
            context["claim_generator"] = am.claim.claim_generator
            context["claim_generator_info"] = am.claim.claim_generator_info

        # Collect hard binding info
        hb = am.hard_binding
        if hb:
            context["hard_binding"] = {
                "label": hb.label,
                "data": hb.data,
                "mechanism": hb.label,
            }

        # Assertion labels for quick predicate checks
        context["assertion_labels"] = [a.label for a in am.assertions]
        context["assertion_count"] = len(am.assertions)

    return context


# ---------------------------------------------------------------------------
# Supported file extensions for suite batch scanning
# ---------------------------------------------------------------------------
_SUPPORTED_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".jpe",
        ".png",
        ".mp4",
        ".m4a",
        ".m4v",
        ".mov",
        ".heif",
        ".heic",
        ".avif",
        ".3gp",
        ".wav",
        ".webp",
        ".avi",
        ".tif",
        ".tiff",
        ".dng",
        ".gif",
        ".svg",
        ".xml",
        ".jxl",
        ".pdf",
        ".txt",
        ".md",
        ".c2pa",
        ".mp3",
        ".flac",
        ".ogg",
        ".opus",
        ".ttf",
        ".otf",
        ".woff2",
        ".html",
        ".htm",
        ".zip",
        ".epub",
        ".docx",
        ".xlsx",
        ".pptx",
        ".odt",
    }
)


@cli.command("suite")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--predicates", type=click.Path(exists=True, path_type=Path))
@click.option("--trust-store", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write JSON report.")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text")
@click.option("--fail-fast", is_flag=True, help="Stop on first failure.")
def suite(
    directory: Path,
    predicates: Path | None,
    trust_store: Path | None,
    output: Path | None,
    fmt: str,
    fail_fast: bool,
) -> None:
    """Validate all assets in a directory against conformance predicates."""
    from c2pa_conformance.evaluator.engine import PredicateEngine

    # Find all supported files first so we can exit early without needing predicates
    files = sorted(
        f
        for f in directory.rglob("*")
        if f.is_file() and f.suffix.lower() in _SUPPORTED_EXTENSIONS
    )

    if not files:
        click.echo(f"No supported files found in {directory}")
        return

    if predicates is None:
        default = Path(__file__).parent / "data" / "predicates.json"
        if not default.exists():
            raise click.ClickException("No predicates.json found.")
        predicates = default

    engine = PredicateEngine(predicates)

    click.echo(
        f"Found {len(files)} assets, evaluating with {engine.predicate_count} predicates..."
    )

    all_reports: list[dict] = []
    total_pass = 0
    total_fail = 0
    errors = 0

    for asset_path in files:
        try:
            report, _ = _run_validation_pipeline(asset_path, engine, trust_store)
            all_reports.append(report.to_dict())
            total_pass += report.pass_count
            total_fail += report.fail_count

            if fmt == "text":
                status = "PASS" if report.fail_count == 0 else "FAIL"
                click.echo(
                    f"  [{status}] {asset_path.name}: {report.pass_count}P/{report.fail_count}F"
                )

            if fail_fast and report.fail_count > 0:
                click.echo("Stopping (--fail-fast)")
                break
        except Exception as exc:
            errors += 1
            all_reports.append({"asset_path": str(asset_path), "error": str(exc)})
            if fmt == "text":
                click.echo(f"  [ERR]  {asset_path.name}: {exc}")
            if fail_fast:
                break

    click.echo(
        f"\nSummary: {len(files)} files, {total_pass} pass, {total_fail} fail, {errors} errors"
    )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w") as f:
            json.dump(
                {
                    "files": all_reports,
                    "summary": {
                        "total_files": len(files),
                        "total_pass": total_pass,
                        "total_fail": total_fail,
                        "errors": errors,
                    },
                },
                f,
                indent=2,
            )
            f.write("\n")
        click.echo(f"Report written to {output}")


@cli.command("compare")
@click.argument("asset_path", type=click.Path(exists=True, path_type=Path))
@click.option("--predicates", type=click.Path(exists=True, path_type=Path))
@click.option("--trust-store", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None)
def compare(
    asset_path: Path,
    predicates: Path | None,
    trust_store: Path | None,
    output: Path | None,
) -> None:
    """Compare conformance suite results against c2pa-tool for an asset."""
    from c2pa_conformance.compare.diff import compare_results
    from c2pa_conformance.compare.normalizer import normalize_c2pa_tool_output
    from c2pa_conformance.compare.report import format_report_text, generate_report
    from c2pa_conformance.compare.runner import is_available, run_c2pa_tool
    from c2pa_conformance.evaluator.engine import PredicateEngine

    if predicates is None:
        default = Path(__file__).parent / "data" / "predicates.json"
        if not default.exists():
            raise click.ClickException("No predicates.json found.")
        predicates = default

    engine = PredicateEngine(predicates)

    # Run suite validation
    click.echo("Running conformance suite validation...")
    report, _ = _run_validation_pipeline(asset_path, engine, trust_store)
    suite_results = [r.to_dict() for r in report.results]

    # Run c2pa-tool
    if not is_available():
        click.echo("c2pa-tool not found in PATH. Showing suite results only.")
        for r in report.results:
            click.echo(f"  {r.result.value:4s} {r.status_code} {r.message}")
        return

    click.echo("Running c2pa-tool validation...")
    tool_result = run_c2pa_tool(asset_path)
    tool_report = normalize_c2pa_tool_output(tool_result.json_output)

    # Diff
    comparison = compare_results(suite_results, tool_report)

    # Output
    text = format_report_text(comparison)
    click.echo(text)

    if output:
        report_data = generate_report(comparison)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w") as f:
            json.dump(report_data, f, indent=2)
            f.write("\n")
        click.echo(f"Comparison report written to {output}")


@cli.command("generate-vectors")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=Path("fixtures/vectors"),
    help="Output directory for vectors.",
)
@click.option(
    "--categories",
    type=str,
    default=None,
    help="Comma-separated categories (default: all).",
)
@click.option("--clean", is_flag=True, help="Delete existing vectors first.")
def generate_vectors(output_dir: Path, categories: str | None, clean: bool) -> None:
    """Generate deterministic C2PA test vectors."""
    import shutil

    from c2pa_conformance.vectors.generator import generate_all_vectors

    if clean and output_dir.exists():
        shutil.rmtree(output_dir)

    cats = categories.split(",") if categories else None

    click.echo(f"Generating test vectors in {output_dir}...")
    results = generate_all_vectors(output_dir, categories=cats)

    successes = [r for r in results if "error" not in r]
    errors = [r for r in results if "error" in r]

    for r in successes:
        status = "PASS" if r["expected_pass"] else "FAIL"
        click.echo(f"  [{status}] {r['category']}/{r['name']} ({r['size_bytes']} bytes)")

    if errors:
        for r in errors:
            click.echo(f"  [ERR]  {r['category']}/{r['name']}: {r['error']}")

    click.echo(f"\nGenerated {len(successes)} vectors ({len(errors)} errors)")


@cli.command("report")
@click.argument("report_path", type=click.Path(exists=True, path_type=Path))
def report(report_path: Path) -> None:
    """Print a human-readable summary of a conformance report."""
    data = json.loads(report_path.read_text())
    summary = data.get("summary", {})

    click.echo(f"Conformance Report: {data.get('asset_path', 'unknown')}")
    click.echo(f"Spec Version: {data.get('spec_version', 'unknown')}")
    click.echo(f"Total: {summary.get('total', 0)}")
    click.echo(f"  Pass: {summary.get('pass', 0)}")
    click.echo(f"  Fail: {summary.get('fail', 0)}")
    click.echo(f"  Skip: {summary.get('skip', 0)}")

    results = data.get("results", [])
    failures = [r for r in results if r.get("result") == "fail"]
    if failures:
        click.echo(f"\nFailures ({len(failures)}):")
        for r in failures:
            click.echo(f"  {r['predicate_id']}: {r.get('status_code', '')} {r.get('message', '')}")


if __name__ == "__main__":
    cli()
