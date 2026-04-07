"""Container format extractors for C2PA manifest store JUMBF bytes.

Importing this module auto-registers all extractors with the base registry.
Use detect_and_extract() for auto-detection, or import specific extractors.
"""

# Import all extractors to trigger @register decorators
from c2pa_conformance.extractors import bmff as _bmff  # noqa: F401
from c2pa_conformance.extractors import flac as _flac  # noqa: F401
from c2pa_conformance.extractors import font as _font  # noqa: F401
from c2pa_conformance.extractors import gif as _gif  # noqa: F401
from c2pa_conformance.extractors import html as _html  # noqa: F401
from c2pa_conformance.extractors import id3 as _id3  # noqa: F401
from c2pa_conformance.extractors import jpeg as _jpeg  # noqa: F401
from c2pa_conformance.extractors import jxl as _jxl  # noqa: F401
from c2pa_conformance.extractors import ogg as _ogg  # noqa: F401
from c2pa_conformance.extractors import pdf as _pdf  # noqa: F401
from c2pa_conformance.extractors import png as _png  # noqa: F401
from c2pa_conformance.extractors import riff as _riff  # noqa: F401
from c2pa_conformance.extractors import svg as _svg  # noqa: F401
from c2pa_conformance.extractors import text as _text  # noqa: F401
from c2pa_conformance.extractors import tiff as _tiff  # noqa: F401
from c2pa_conformance.extractors import zip as _zip  # noqa: F401
from c2pa_conformance.extractors.base import (  # noqa: F401
    ExtractionError,
    ExtractionResult,
    Extractor,
    detect_and_extract,
)
