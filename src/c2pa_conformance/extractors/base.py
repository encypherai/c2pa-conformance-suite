"""Base extractor protocol and registry.

Each container format extractor locates C2PA manifest store JUMBF bytes
within a specific file format. The extractors are intentionally thin:
all they do is find and return raw JUMBF bytes. Everything downstream
(JUMBF parsing, manifest decoding, predicate evaluation) is format-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


class ExtractionError(Exception):
    """Raised when JUMBF extraction from a container fails."""


@dataclass
class ExtractionResult:
    """Result of extracting JUMBF from a container format.

    Attributes:
        jumbf_bytes: Raw JUMBF manifest store bytes.
        container_format: Identifier for the container format (e.g., "jpeg", "png").
        jumbf_offset: Byte offset of the JUMBF data within the source file.
        jumbf_length: Length of the JUMBF data in bytes.
    """

    jumbf_bytes: bytes
    container_format: str
    jumbf_offset: int = 0
    jumbf_length: int = 0


@runtime_checkable
class Extractor(Protocol):
    """Protocol for container format extractors."""

    @staticmethod
    def can_handle(data: bytes, suffix: str) -> bool:
        """Return True if this extractor can handle the given data/suffix."""
        ...

    @staticmethod
    def extract(data: bytes) -> ExtractionResult:
        """Extract JUMBF manifest store bytes from container data."""
        ...


# Global registry of extractors, ordered by priority
_REGISTRY: list[type[Extractor]] = []


def register(cls: type[Extractor]) -> type[Extractor]:
    """Decorator to register an extractor class."""
    _REGISTRY.append(cls)
    return cls


def detect_and_extract(path: Path) -> ExtractionResult:
    """Auto-detect format and extract JUMBF from a file.

    Tries each registered extractor in order until one succeeds.

    Args:
        path: Path to the asset file.

    Returns:
        ExtractionResult with raw JUMBF bytes.

    Raises:
        ExtractionError: If no extractor can handle the file.
    """
    data = path.read_bytes()
    suffix = path.suffix.lower()

    # Sidecar .c2pa files are just raw JUMBF
    if suffix == ".c2pa":
        return ExtractionResult(
            jumbf_bytes=data,
            container_format="sidecar",
            jumbf_offset=0,
            jumbf_length=len(data),
        )

    for extractor_cls in _REGISTRY:
        if extractor_cls.can_handle(data, suffix):
            return extractor_cls.extract(data)

    raise ExtractionError(
        f"No extractor found for {path.name} "
        f"(suffix={suffix}, {len(data)} bytes, "
        f"magic={data[:4].hex() if len(data) >= 4 else 'too short'})"
    )
