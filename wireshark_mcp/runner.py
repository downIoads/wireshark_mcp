"""Subprocess helper for Wireshark CLI tools with bounded execution."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

BIN_DIR = os.environ.get("WIRESHARK_MCP_BIN_DIR")
CAPTURE_DIR = Path(
    os.environ.get("WIRESHARK_MCP_CAPTURE_DIR")
    or Path.home() / ".wireshark-mcp" / "captures"
).resolve()
MAX_OUTPUT_BYTES = int(os.environ.get("WIRESHARK_MCP_MAX_OUTPUT", 5 * 1024 * 1024))
DEFAULT_TIMEOUT = 60


class ToolError(RuntimeError):
    """Raised when a wrapped CLI tool fails or is misused."""


@dataclass
class CmdResult:
    stdout: str
    stderr: str
    returncode: int
    truncated: bool


def _resolve_binary(name: str) -> str:
    if BIN_DIR:
        candidate = Path(BIN_DIR) / name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if not found:
        raise ToolError(f"{name} not found on PATH (set WIRESHARK_MCP_BIN_DIR if needed)")
    return found


def ensure_capture_dir() -> Path:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    return CAPTURE_DIR


def safe_output_path(filename: str) -> Path:
    """Resolve `filename` inside the sandbox capture dir, rejecting traversal."""
    base = ensure_capture_dir()
    target = (base / filename).resolve()
    if base not in target.parents and target != base:
        raise ToolError(f"output path escapes sandbox: {filename}")
    return target


def safe_input_path(path: str) -> Path:
    """Validate a user-supplied pcap path exists and is a regular file."""
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise ToolError(f"input file does not exist: {path}")
    return p


def run(tool: str, args: list[str], *, timeout: int = DEFAULT_TIMEOUT) -> CmdResult:
    binary = _resolve_binary(tool)
    # Force POSIX locale so tshark/capinfos emit numbers with a `.` decimal
    # mark and no thousands separators. Without this, on a European-locale
    # host you get "7.253 bytes" (= 7253) and "0,1536" (= 0.1536), which
    # breaks anything trying to parse the output back to floats.
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        raise ToolError(f"{tool} timed out after {timeout}s") from e

    truncated = False
    out = proc.stdout
    if len(out) > MAX_OUTPUT_BYTES:
        out = out[:MAX_OUTPUT_BYTES]
        truncated = True

    if proc.returncode != 0:
        raise ToolError(
            f"{tool} exited {proc.returncode}: {proc.stderr.strip() or '<no stderr>'}"
        )
    return CmdResult(out, proc.stderr, proc.returncode, truncated)
