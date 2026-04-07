"""Execute c2pa-tool on assets and capture validation output."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class C2paToolNotFound(Exception):
    """Raised when c2pa-tool is not available."""


@dataclass
class C2paToolResult:
    """Raw result from running c2pa-tool."""

    exit_code: int
    stdout: str
    stderr: str
    json_output: dict | None = None
    asset_path: str = ""


def find_c2pa_tool() -> str | None:
    """Find c2pa-tool in PATH. Returns path or None."""
    return shutil.which("c2pa-tool") or shutil.which("c2patool")


def is_available() -> bool:
    """Check if c2pa-tool is installed and accessible."""
    return find_c2pa_tool() is not None


def run_c2pa_tool(
    asset_path: Path,
    timeout: int = 30,
) -> C2paToolResult:
    """Run c2pa-tool on a single asset and capture JSON output.

    Args:
        asset_path: Path to the asset file.
        timeout: Maximum execution time in seconds.

    Returns:
        C2paToolResult with captured output.

    Raises:
        C2paToolNotFound: If c2pa-tool is not installed.
    """
    tool = find_c2pa_tool()
    if not tool:
        raise C2paToolNotFound(
            "c2pa-tool not found in PATH. Install it from https://github.com/contentauth/c2pa-rs"
        )

    cmd = [tool, str(asset_path), "--detailed"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return C2paToolResult(
            exit_code=-1,
            stdout="",
            stderr=f"c2pa-tool timed out after {timeout}s",
            asset_path=str(asset_path),
        )
    except OSError as exc:
        return C2paToolResult(
            exit_code=-1,
            stdout="",
            stderr=str(exc),
            asset_path=str(asset_path),
        )

    json_output = None
    if proc.stdout.strip():
        try:
            json_output = json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass

    return C2paToolResult(
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        json_output=json_output,
        asset_path=str(asset_path),
    )
