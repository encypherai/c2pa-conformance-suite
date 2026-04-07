"""Test vector generation for C2PA conformance testing.

Provides deterministic signed C2PA test vectors using the existing
builder and embedder infrastructure.
"""

from c2pa_conformance.vectors.assets import minimal_jpeg, minimal_png
from c2pa_conformance.vectors.definitions import VectorDefinition, get_all_definitions
from c2pa_conformance.vectors.generator import generate_all_vectors

__all__ = [
    "VectorDefinition",
    "generate_all_vectors",
    "get_all_definitions",
    "minimal_jpeg",
    "minimal_png",
]
