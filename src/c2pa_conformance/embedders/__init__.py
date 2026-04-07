"""Container embedders for C2PA JUMBF manifest stores."""

from c2pa_conformance.embedders.jpeg import embed_jpeg
from c2pa_conformance.embedders.png import embed_png
from c2pa_conformance.embedders.sidecar import embed_sidecar

__all__ = ["embed_jpeg", "embed_png", "embed_sidecar"]
