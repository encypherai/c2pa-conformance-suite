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
) -> tuple[object, dict, object, object]:
    """Run the full validation pipeline on a single asset.

    Returns (ConformanceReport, evaluation_context, ManifestStore, sig_result) tuple.
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

    # Read asset once for both binding verification and context
    asset_data = asset_path.read_bytes()

    # Crypto -- use bundled C2PA trust list when no explicit store supplied
    from c2pa_conformance.crypto.trust import default_trust_store

    if trust_store_path:
        ts = TrustAnchorStore.from_pem_file(trust_store_path)
    else:
        ts = default_trust_store()
    sig_result = None
    hash_result = None
    if store.active_manifest:
        sig_result = verify_manifest_signature(store.active_manifest, ts)
        hash_result = verify_manifest_binding(store.active_manifest, asset_data)

    # Build context (pass asset_data for BMFF xpath resolution)
    context = _build_context(store, extraction, asset_bytes=asset_data)
    if sig_result:
        crypto_ctx = build_crypto_context(sig_result, hash_result)
        context.update(crypto_ctx)
    context["asset_bytes"] = asset_data
    context["asset_size"] = len(asset_data)

    # Evaluate
    report = engine.evaluate_all(context, container_format=extraction.container_format)
    report.asset_path = str(asset_path)

    return report, context, store, sig_result


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
    "--output-format",
    "output_format",
    type=click.Choice(["json", "crjson"]),
    default="json",
    help="Output format: json (default predicate report) or crjson (C2PA conformance JSON).",
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
    output_format: str,
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

    # Step 2.5: Crypto verification (bundled trust list when none supplied)
    from c2pa_conformance.crypto.trust import default_trust_store

    ts = TrustAnchorStore.from_pem_file(trust_store) if trust_store else default_trust_store()

    # Read asset once for both binding verification and context
    asset_data = asset_path.read_bytes()

    sig_result = None
    hash_result = None
    if store.active_manifest:
        sig_result = verify_manifest_signature(store.active_manifest, ts)
        click.echo(f"Signature: {sig_result.signature_status}")

        # Step 2.75: Content binding
        hash_result = verify_manifest_binding(store.active_manifest, asset_data)
        if hash_result.hash_valid is not None:
            click.echo(f"Content binding: {hash_result.hash_status}")

    # Step 3: Build evaluation context from parsed manifest
    context = _build_context(store, extraction, asset_bytes=asset_data)

    # Merge crypto context
    if sig_result:
        crypto_ctx = build_crypto_context(sig_result, hash_result)
        context.update(crypto_ctx)

    context["asset_bytes"] = asset_data
    context["asset_size"] = len(asset_data)

    # Step 4: Evaluate predicates
    report = engine.evaluate_all(
        context, binding=binding, container_format=extraction.container_format
    )
    report.asset_path = str(asset_path)

    click.echo(
        f"\nResults: {report.pass_count} pass, "
        f"{report.fail_count} fail, "
        f"{report.skip_count} skip "
        f"(of {report.total_count} predicates)"
    )

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output_format == "crjson":
            from c2pa_conformance.serializer.crjson import serialize_to_crjson

            crjson_data = serialize_to_crjson(store, report, sig_result, context)
            with output.open("w") as f:
                json.dump(crjson_data, f, indent=2)
                f.write("\n")
        else:
            with output.open("w") as f:
                json.dump(report.to_dict(), f, indent=2)
                f.write("\n")
        click.echo(f"Report written to {output}")
    else:
        if output_format == "crjson":
            from c2pa_conformance.serializer.crjson import serialize_to_crjson

            crjson_data = serialize_to_crjson(store, report, sig_result, context)
            click.echo(json.dumps(crjson_data, indent=2))
        else:
            for r in report.results:
                if r.result.value == "fail":
                    click.echo(f"  FAIL {r.predicate_id}: {r.status_code} {r.message}")


def _build_context(store: object, extraction: object, asset_bytes: bytes | None = None) -> dict:
    """Build a predicate evaluation context from parsed manifest data.

    Maps the ManifestStore into the flat dict structure that predicates
    reference via dotted field paths. Promotes key fields to top level
    so predicate operators can resolve them directly.

    Args:
        store: Parsed ManifestStore.
        extraction: ExtractionResult from the container extractor.
        asset_bytes: Raw asset file bytes (needed for BMFF xpath resolution).
    """

    context: dict = {
        "asset_path": extraction.container_format,
        "container_format": extraction.container_format,
        "jumbf_offset": extraction.jumbf_offset,
        "jumbf_length": extraction.jumbf_length,
        "manifest_store": {
            "manifest_count": store.manifest_count,
            "manifests": [],
            "all_manifests": [],
        },
    }

    for manifest in store.manifests:
        m: dict = {
            "label": manifest.label,
            "identifier": manifest.label,
            "assertions": [],
            "claim": {},
            "has_signature": len(manifest.signature_bytes) > 0,
            "signature_bytes_length": len(manifest.signature_bytes),
        }

        if manifest.claim:
            claim_data = manifest.claim.data or {}
            m["claim"] = {
                "claim_generator": manifest.claim.claim_generator,
                "claim_generator_info": manifest.claim.claim_generator_info,
                "signature_ref": manifest.claim.signature_ref,
                "assertion_refs": manifest.claim.assertion_refs,
                "is_update_manifest": manifest.claim.is_update_manifest,
                "data": claim_data,
                # Structured claim fields for predicate access
                "assertions": manifest.claim.assertion_refs,
                "created_assertions": claim_data.get("created_assertions"),
                "gathered_assertions": claim_data.get("gathered_assertions"),
                "redacted_assertions": claim_data.get("redacted_assertions"),
            }

        for assertion in manifest.assertions:
            a = {
                "label": assertion.label,
                "uri": f"self#jumbf=/{manifest.label}/c2pa.assertions/{assertion.label}",
                "data": assertion.data,
                "is_hard_binding": assertion.is_hard_binding,
                "has_raw_cbor": len(assertion.raw_cbor) > 0,
                "raw_cbor_length": len(assertion.raw_cbor),
                "raw_cbor": assertion.raw_cbor,
            }
            if assertion.box:
                a["box"] = {
                    "offset": assertion.box.offset,
                    "size": assertion.box.size,
                }
            m["assertions"].append(a)

        context["manifest_store"]["manifests"].append(m)
        context["manifest_store"]["all_manifests"].append(m)

    # Promote active manifest fields to top level for predicate access
    if store.active_manifest:
        am = store.active_manifest
        # Look up active manifest context by label, not list position
        active_ctx = next(
            (m for m in context["manifest_store"]["manifests"] if m.get("label") == am.label),
            context["manifest_store"]["manifests"][-1],
        )
        context["active_manifest"] = active_ctx

        if am.claim:
            context["claim"] = active_ctx["claim"]
            context["claim_generator"] = am.claim.claim_generator
            context["claim_generator_info"] = am.claim.claim_generator_info
            context["claim_cbor_bytes"] = am.claim.raw_cbor

        # Hard binding with promoted exclusions
        hb = am.hard_binding
        if hb:
            binding_data = hb.data or {}
            context["hard_binding"] = {
                "label": hb.label,
                "data": binding_data,
                "mechanism": hb.label,
            }
            raw_exclusions = binding_data.get("exclusions", [])

            # Promote binding assertion data under its canonical predicate name
            if hb.is_hash_data:
                context["data_hash_assertion"] = binding_data
            elif hb.is_hash_bmff:
                context["bmff_hash_assertion"] = binding_data
            elif hb.is_hash_boxes:
                context["boxes_hash_assertion"] = binding_data
            elif hb.is_hash_multi_asset:
                context["multi_asset_hash_map"] = binding_data

            if raw_exclusions:
                # For BMFF bindings, resolve xpath exclusions to byte ranges
                if hb.is_hash_bmff and asset_bytes:
                    from c2pa_conformance.binding.bmff_parser import (
                        parse_bmff_boxes,
                        resolve_xpath_exclusions,
                    )

                    bmff_boxes = parse_bmff_boxes(asset_bytes)
                    context["exclusions"] = resolve_xpath_exclusions(bmff_boxes, raw_exclusions)
                else:
                    context["exclusions"] = raw_exclusions
            elif hb.is_hash_multi_asset:
                # Multi-asset bindings have no top-level exclusions. Set empty
                # list so PRED-IMG-002's for_each passes with zero iterations
                # instead of failing on a missing (None) collection.
                context["exclusions"] = []

        # Assertion labels and full assertion store
        assertion_labels = [a.label for a in am.assertions]
        context["assertion_labels"] = assertion_labels
        context["assertion_count"] = len(am.assertions)
        context["assertion_store"] = {"assertions": active_ctx["assertions"]}

        # claim.own_assertion_store: the set of assertion labels belonging
        # to this manifest's claim (used by PRED-INGR-002 self-redaction check)
        if "claim" in context and isinstance(context["claim"], dict):
            context["claim"]["own_assertion_store"] = assertion_labels

        # Ingredient manifests from ingredient assertions, enriched with
        # cross-manifest data from the ManifestStore when available.
        ingredient_assertions = [a for a in am.assertions if a.label.startswith("c2pa.ingredient")]
        if ingredient_assertions:
            # Build a label-to-manifest-context lookup for cross-manifest resolution
            manifest_by_label: dict[str, dict] = {}
            for m_ctx in context["manifest_store"]["manifests"]:
                manifest_by_label[m_ctx.get("label", "")] = m_ctx

            context["ingredient_manifests"] = []
            for ia in ingredient_assertions:
                ia_data = ia.data or {}
                # Parse redacted_assertions URIs into structured objects
                raw_redacted = ia_data.get("redacted_assertions", [])
                parsed_redacted = []
                for uri in raw_redacted:
                    parsed = _parse_jumbf_uri(uri) if isinstance(uri, str) else {}
                    parsed["uri"] = uri
                    parsed_redacted.append(parsed)

                entry: dict = {
                    "label": ia.label,
                    "data": ia_data,
                    "relationship": ia_data.get("relationship", ""),
                    "redacted_assertions": parsed_redacted,
                }

                # Resolve activeManifest reference to actual manifest context
                active_ref = ia_data.get("activeManifest")
                if isinstance(active_ref, dict):
                    ref_url = active_ref.get("url", "")
                    ref_parsed = _parse_jumbf_uri(ref_url)
                    ref_label = ref_parsed.get("manifest_label", "")
                    ref_manifest = manifest_by_label.get(ref_label)
                    if ref_manifest:
                        entry["manifest"] = ref_manifest
                        # Provide the ingredient manifest's own claim data
                        entry["claim"] = ref_manifest.get("claim", {})

                context["ingredient_manifests"].append(entry)

            context["manifest_by_label"] = manifest_by_label

        # Parse claim.redacted_assertions into structured objects
        if "claim" in context and isinstance(context["claim"], dict):
            raw_claim_redacted = context["claim"].get("redacted_assertions") or []
            if raw_claim_redacted:
                parsed_claim_redacted = []
                for uri in raw_claim_redacted:
                    parsed = _parse_jumbf_uri(uri) if isinstance(uri, str) else {}
                    parsed["uri"] = uri
                    parsed_claim_redacted.append(parsed)
                context["claim"]["redacted_assertions"] = parsed_claim_redacted

        # Standard assertion hashed-URI fields for integrity predicates
        std_assertions = [a for a in am.assertions if not a.is_hard_binding]
        hashed_uri_fields: list[dict] = []
        for sa in std_assertions:
            if isinstance(sa.data, dict):
                for key, val in sa.data.items():
                    if isinstance(val, dict) and ("url" in val or "hash" in val):
                        hashed_uri_fields.append(
                            {
                                "field_name": key,
                                "assertion_label": sa.label,
                                "field_type": "hashed_uri" if "hash" in val else "uri",
                                "data": val,
                            }
                        )
        if hashed_uri_fields:
            context["standard_assertions"] = {
                "hashed_uri_fields": hashed_uri_fields,
            }

    return context


def _parse_jumbf_uri(uri: str) -> dict[str, str]:
    """Parse a JUMBF URI into structured fields.

    E.g. "self#jumbf=/c2pa/manifest-label/c2pa.assertions/assertion-label"
    -> {"target_manifest": "manifest-label", "target_assertion": "assertion-label"}
    """
    result: dict[str, str] = {}
    # Strip the self#jumbf= prefix
    path = uri
    if "#jumbf=" in uri:
        path = uri.split("#jumbf=", 1)[1]
    parts = path.strip("/").split("/")
    # Expected: c2pa / manifest-label / c2pa.assertions / assertion-label
    if len(parts) >= 2:
        result["target_manifest"] = parts[1]
    if len(parts) >= 4:
        result["target_assertion"] = parts[3]
    return result


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


def _load_known_failures(path: Path | None) -> dict[str, str]:
    """Load a known-failures JSON file mapping filenames to reasons.

    Format: {"filename.ext": "reason string", ...}
    """
    if path is None:
        return {}
    with path.open() as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


@cli.command("suite")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--predicates", type=click.Path(exists=True, path_type=Path))
@click.option("--trust-store", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None, help="Write JSON report.")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text")
@click.option("--fail-fast", is_flag=True, help="Stop on first failure.")
@click.option(
    "--known-failures",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help='JSON file mapping filenames to expected-failure reasons (e.g. {"file.jpg": "reason"}).',
)
def suite(
    directory: Path,
    predicates: Path | None,
    trust_store: Path | None,
    output: Path | None,
    fmt: str,
    fail_fast: bool,
    known_failures: Path | None,
) -> None:
    """Validate all assets in a directory against conformance predicates."""
    from c2pa_conformance.evaluator.engine import PredicateEngine

    known = _load_known_failures(known_failures)

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
    total_xfail = 0
    total_xpass = 0
    errors = 0

    for asset_path in files:
        try:
            report, _ctx, _store, _sig = _run_validation_pipeline(asset_path, engine, trust_store)
            report_dict = report.to_dict()
            is_known = asset_path.name in known

            if report.fail_count == 0 and is_known:
                # Expected to fail but passed - unexpected pass
                total_xpass += 1
                total_pass += report.pass_count
                report_dict["xpass"] = True
                report_dict["known_failure_reason"] = known[asset_path.name]
                if fmt == "text":
                    click.echo(
                        f"  [XPASS] {asset_path.name}: {report.pass_count}P/{report.fail_count}F"
                        f" (expected failure: {known[asset_path.name]})"
                    )
            elif report.fail_count > 0 and is_known:
                # Expected failure - xfail
                total_xfail += 1
                total_pass += report.pass_count
                report_dict["xfail"] = True
                report_dict["known_failure_reason"] = known[asset_path.name]
                if fmt == "text":
                    click.echo(
                        f"  [XFAIL] {asset_path.name}: {report.pass_count}P/{report.fail_count}F"
                        f" ({known[asset_path.name]})"
                    )
            else:
                total_pass += report.pass_count
                total_fail += report.fail_count
                if fmt == "text":
                    status = "PASS" if report.fail_count == 0 else "FAIL"
                    click.echo(
                        f"  [{status}] {asset_path.name}:"
                        f" {report.pass_count}P/{report.fail_count}F"
                    )

            all_reports.append(report_dict)

            if fail_fast and report.fail_count > 0 and not is_known:
                click.echo("Stopping (--fail-fast)")
                break
        except Exception as exc:
            errors += 1
            all_reports.append({"asset_path": str(asset_path), "error": str(exc)})
            if fmt == "text":
                click.echo(f"  [ERR]  {asset_path.name}: {exc}")
            if fail_fast:
                break

    # Build summary line
    parts = [f"{len(files)} files", f"{total_pass} pass", f"{total_fail} fail"]
    if total_xfail:
        parts.append(f"{total_xfail} xfail")
    if total_xpass:
        parts.append(f"{total_xpass} xpass")
    parts.append(f"{errors} errors")
    click.echo(f"\nSummary: {', '.join(parts)}")

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
                        "total_xfail": total_xfail,
                        "total_xpass": total_xpass,
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
    report, _, _, _ = _run_validation_pipeline(asset_path, engine, trust_store)
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


@cli.command("rubric")
@click.argument("asset_path", type=click.Path(exists=True, path_type=Path), required=False)
@click.option(
    "--rubric",
    "rubric_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to rubric YAML file.",
)
@click.option(
    "--crjson-input",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to pre-generated crJSON file (skips asset validation).",
)
@click.option("--predicates", type=click.Path(exists=True, path_type=Path))
@click.option("--trust-store", type=click.Path(exists=True, path_type=Path), default=None)
@click.option(
    "--output", type=click.Path(path_type=Path), default=None, help="Write JSON results."
)
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text")
def rubric(
    asset_path: Path | None,
    rubric_path: Path,
    crjson_input: Path | None,
    predicates: Path | None,
    trust_store: Path | None,
    output: Path | None,
    fmt: str,
) -> None:
    """Evaluate a conformance rubric against an asset or crJSON file.

    Runs the validation pipeline on the asset, serializes results to crJSON,
    then evaluates the rubric's jmespath expressions against the crJSON output.

    Either ASSET_PATH or --crjson-input must be provided.
    """
    from c2pa_conformance.rubric.evaluator import evaluate_rubric

    if crjson_input is not None:
        crjson_data = json.loads(crjson_input.read_text())
        click.echo(f"Loaded crJSON from {crjson_input}")
    elif asset_path is not None:
        from c2pa_conformance.evaluator.engine import PredicateEngine
        from c2pa_conformance.serializer.crjson import serialize_to_crjson

        if predicates is None:
            default = Path(__file__).parent / "data" / "predicates.json"
            if not default.exists():
                raise click.ClickException("No predicates.json found.")
            predicates = default

        engine = PredicateEngine(predicates)
        report, context, store, sig_result = _run_validation_pipeline(
            asset_path, engine, trust_store
        )
        crjson_data = serialize_to_crjson(store, report, sig_result, context)
        click.echo(f"Validated {asset_path.name}: {report.pass_count}P/{report.fail_count}F")
    else:
        raise click.ClickException("Provide ASSET_PATH or --crjson-input.")

    rubric_report = evaluate_rubric(crjson_data, rubric_path=rubric_path)

    click.echo(f"Rubric: {rubric_report.rubric_name} v{rubric_report.rubric_version}")
    click.echo(f"Results: {rubric_report.pass_count} pass, {rubric_report.fail_count} fail")

    if fmt == "text":
        for r in rubric_report.results:
            status = "PASS" if r.value else "FAIL"
            click.echo(f"  [{status}] {r.id}: {r.report_text}")
            if r.error:
                click.echo(f"         Error: {r.error}")
    else:
        click.echo(json.dumps(rubric_report.to_dict(), indent=2))

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w") as f:
            json.dump(rubric_report.to_dict(), f, indent=2)
            f.write("\n")
        click.echo(f"Report written to {output}")


if __name__ == "__main__":
    cli()
