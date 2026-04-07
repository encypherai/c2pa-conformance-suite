"""Sidecar .c2pa file writer."""

from __future__ import annotations


def embed_sidecar(jumbf_bytes: bytes) -> bytes:
    """Return raw JUMBF bytes as-is for sidecar .c2pa files.

    Sidecar files are just raw JUMBF manifest store bytes
    with no container wrapping.
    """
    return jumbf_bytes
