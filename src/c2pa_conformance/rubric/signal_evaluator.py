"""Signal rubric evaluator.

Evaluates signal rubrics against crJSON data on a per-manifest basis.
Signal rubrics differ from conformance rubrics: each statement is evaluated
against individual manifests in the provenance DAG (not the full crJSON
document), producing per-manifest inception and transformation signal results.

This mirrors the upstream ``c2pa_signals_rubric_evaluator.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from c2pa_conformance.rubric.composer import compose
from c2pa_conformance.rubric.jsonformula_engine import _build_engine
from c2pa_conformance.rubric.types import (
    ManifestSignals,
    SignalResult,
    SignalRubricReport,
)


def _create_index_mapping(data: dict[str, Any]) -> dict[str, str]:
    """Map manifest labels to their array index as strings."""
    mapping: dict[str, str] = {}
    for idx, manifest in enumerate(data.get("manifests", [])):
        label = manifest.get("label")
        if label:
            mapping[label] = str(idx)
    return mapping


def _build_provenance_dag(
    data: dict[str, Any],
    index_mapping: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Build a provenance DAG from crJSON manifests.

    Each node is keyed by its string index and contains the manifest data,
    edges (ingredient relationships), and an empty signals list to be
    populated during evaluation.
    """
    dag: dict[str, dict[str, Any]] = {}

    for manifest in data.get("manifests", []):
        label = manifest.get("label")
        if not label:
            continue

        node_id = index_mapping.get(label, "Unknown")
        dag[node_id] = {
            "urn": label,
            "manifest": manifest,
            "edges": [],
            "signals": [],
        }

        claim = manifest.get("claim.v2") or manifest.get("claim") or {}
        mime_type = claim.get("dc:format")
        if mime_type:
            dag[node_id]["mime_type"] = mime_type

    # Second pass: resolve ingredient edges
    for manifest in data.get("manifests", []):
        label = manifest.get("label")
        if not label:
            continue

        node_id = index_mapping.get(label, "Unknown")
        assertions = manifest.get("assertions", {})

        for key, value in assertions.items():
            if key.startswith("c2pa.ingredient"):
                active_manifest = value.get("activeManifest", {})
                url = active_manifest.get("url")
                relationship = value.get("relationship")

                if url:
                    parent_urn = url
                    if "urn:c2pa:" in url:
                        idx = url.find("urn:c2pa:")
                        parent_urn = url[idx:]
                        if "/" in parent_urn:
                            parent_urn = parent_urn.split("/")[0]

                    parent_id = index_mapping.get(parent_urn, parent_urn)
                    if node_id in dag:
                        dag[node_id]["edges"].append(
                            {"parent": parent_id, "relationship": relationship}
                        )

                    mime_type = value.get("dc:format")
                    if (
                        mime_type
                        and parent_id in dag
                        and "mime_type" not in dag[parent_id]
                    ):
                        dag[parent_id]["mime_type"] = mime_type

            elif key.startswith("c2pa.thumbnail"):
                mime_type = value.get("format")
                if mime_type and node_id in dag and "mime_type" not in dag[node_id]:
                    dag[node_id]["mime_type"] = mime_type

    return dag


def evaluate_signal_rubric(
    crjson_data: dict[str, Any],
    rubric_path: Path,
    language: str = "en",
) -> SignalRubricReport:
    """Evaluate a signal rubric against crJSON data.

    Signal rubrics evaluate each expression against individual manifests
    in the provenance chain (not the full document). Results are grouped
    into inception and transformation signals per manifest.

    Args:
        crjson_data: Full crJSON document with manifests array.
        rubric_path: Path to the signal rubric YAML (may be composable).
        language: Language code for report text resolution.

    Returns:
        A :class:`SignalRubricReport` with per-manifest signal results.
    """
    composed = compose(rubric_path)

    engine, var_scope = _build_engine(composed.variables, composed.expressions)

    index_mapping = _create_index_mapping(crjson_data)
    dag = _build_provenance_dag(crjson_data, index_mapping)

    # Evaluate each statement against each manifest individually
    for node_id, node in dag.items():
        manifest = node["manifest"]
        for stmt in composed.statements:
            expr = stmt.get("expression")
            trait = stmt.get("id")

            if not expr or not trait:
                continue

            try:
                val = engine.search(expr.strip(), manifest, globals=var_scope)

                bool_val = False
                is_multiple = False
                if isinstance(val, list):
                    bool_val = len(val) > 0
                    is_multiple = len(val) > 1
                elif isinstance(val, bool):
                    bool_val = val
                elif isinstance(val, (int, float)):
                    bool_val = val > 0
                elif val is not None:
                    bool_val = True

                if bool_val:
                    report_text_raw = stmt.get("reportText", {})
                    report_text = ""
                    if isinstance(report_text_raw, dict):
                        true_val = report_text_raw.get("true", {})
                        if isinstance(true_val, dict):
                            report_text = true_val.get(language, true_val.get("en", trait))
                        elif isinstance(true_val, str):
                            report_text = true_val
                    node["signals"].append(
                        {"trait": trait, "reportText": report_text, "multiple": is_multiple}
                    )
            except Exception:  # noqa: BLE001
                pass  # Signal evaluation failures are silently skipped

    # Build output
    manifests_out: list[ManifestSignals] = []
    for idx, orig_manifest in enumerate(crjson_data.get("manifests", [])):
        node_id = str(idx)
        dag_node = dag.get(node_id, {})

        subject = (
            orig_manifest.get("signature", {})
            .get("certificateInfo", {})
            .get("subject", {})
        )
        cn = subject.get("CN", "Unknown CN")
        o = subject.get("O", "Unknown O")
        ou = subject.get("OU")

        asserted_by: dict[str, str] = {"CN": cn, "O": o}
        if ou:
            asserted_by["OU"] = ou

        # Check allActionsIncluded
        all_actions_included = True
        actions_found = False
        assertions = orig_manifest.get("assertions", {})
        for _label, assertion in assertions.items():
            if isinstance(assertion, dict) and "actions" in assertion:
                actions_found = True
                if assertion.get("allActionsIncluded") is not True:
                    all_actions_included = False
                    break
        if not actions_found:
            all_actions_included = False

        local_inceptions: list[SignalResult] = []
        local_transformations: list[SignalResult] = []

        for sig in dag_node.get("signals", []):
            trait_str = sig.get("trait", "")
            sr = SignalResult(
                trait=trait_str,
                report_text=sig.get("reportText", ""),
                multiple=sig.get("multiple", False),
            )
            if trait_str.startswith("inception:"):
                local_inceptions.append(sr)
            elif trait_str.startswith("transformation:"):
                local_transformations.append(sr)

        # Build ingredients list
        ingredients: list[dict[str, Any]] = []
        for edge in dag_node.get("edges", []):
            parent_id_str = edge.get("parent")
            relationship = edge.get("relationship")
            try:
                parent_idx = int(parent_id_str)
                ingredients.append({"index": parent_idx, "relationship": relationship})
            except (ValueError, TypeError):
                pass

        manifests_out.append(
            ManifestSignals(
                asserted_by=asserted_by,
                mime_type=dag_node.get("mime_type"),
                local_inceptions=local_inceptions,
                local_transformations=local_transformations,
                all_actions_included=all_actions_included,
                ingredients=ingredients,
            )
        )

    return SignalRubricReport(
        rubric_name=composed.rubric_name,
        rubric_version=composed.rubric_version,
        manifests=manifests_out,
    )
