#!/usr/bin/env python3
"""Generate C2PA conformance test vectors.

Usage:
    python scripts/generate_vectors.py [--output-dir fixtures/vectors] [--categories valid,crypto]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add src to path for direct script execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from c2pa_conformance.vectors.generator import generate_all_vectors


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate C2PA test vectors")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("fixtures/vectors"),
        help="Output directory (default: fixtures/vectors)",
    )
    parser.add_argument(
        "--categories",
        type=str,
        default=None,
        help="Comma-separated categories to generate (default: all)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete existing vectors before generating",
    )
    args = parser.parse_args()

    if args.clean and args.output_dir.exists():
        import shutil

        shutil.rmtree(args.output_dir)

    categories = args.categories.split(",") if args.categories else None

    results = generate_all_vectors(args.output_dir, categories=categories)

    successes = [r for r in results if "error" not in r]
    errors = [r for r in results if "error" in r]

    print(f"Generated {len(successes)} vectors in {args.output_dir}")
    for r in successes:
        status = "PASS" if r["expected_pass"] else "FAIL"
        print(f"  [{status}] {r['category']}/{r['name']} ({r['size_bytes']} bytes)")

    if errors:
        print(f"\n{len(errors)} errors:")
        for r in errors:
            print(f"  {r['category']}/{r['name']}: {r['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
