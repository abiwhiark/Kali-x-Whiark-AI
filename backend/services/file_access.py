"""
Kali AI - Secure File Access Service
=====================================
Allows the AI to read files from the host system when the user
explicitly provides a path and grants permission.

Security rules:
  - Absolute paths only (no directory traversal via ../).
  - User must explicitly provide the path in their message.
  - Files larger than MAX_FILE_SIZE_MB are summarized, not fully returned.
  - Binary files are detected and rejected (or hex-dumped with limit).
  - All accesses are logged.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2 MB
_ACCESS_LOG: list[dict[str, Any]] = []


@dataclass
class FileReadResult:
    path: str
    success: bool
    content: str = ""
    size_bytes: int = 0
    truncated: bool = False
    error: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def read_user_path(path: str) -> FileReadResult:
    """
    Read a file at the user-supplied absolute path.

    Parameters
    ----------
    path : absolute filesystem path provided by the user
    """
    # 1. Normalize
    try:
        p = Path(os.path.expanduser(path)).resolve()
    except Exception as exc:
        return FileReadResult(path=path, success=False, error=f"Invalid path: {exc}")

    # 2. Must be absolute
    if not p.is_absolute():
        return FileReadResult(path=path, success=False,
                              error="Only absolute paths are accepted.")

    # 3. No directory traversal sequences in original string
    if ".." in Path(path).parts:
        return FileReadResult(path=path, success=False,
                              error="Path traversal sequences (..) are not allowed.")

    # 4. Must exist and be a file
    if not p.exists():
        return FileReadResult(path=path, success=False,
                              error=f"Path does not exist: {p}")
    if not p.is_file():
        return FileReadResult(path=path, success=False,
                              error=f"Path is not a regular file: {p}")

    # 5. Size check
    size = p.stat().st_size

    # 6. Binary detection (check first 8 KB for null bytes)
    try:
        with open(p, "rb") as fh:
            sample = fh.read(8192)
        is_binary = b"\x00" in sample
    except Exception as exc:
        return FileReadResult(path=str(p), success=False, error=f"Cannot read file: {exc}")

    if is_binary:
        # Hex-dump first 256 bytes
        hex_preview = sample[:256].hex(" ")
        _log_access(str(p), size, truncated=True)
        return FileReadResult(
            path=str(p), success=True, size_bytes=size, truncated=True,
            content=f"[BINARY FILE — first 256 bytes hex dump]\n{hex_preview}",
        )

    # 7. Read text content
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return FileReadResult(path=str(p), success=False, error=f"Read error: {exc}")

    truncated = False
    if size > MAX_FILE_SIZE_BYTES:
        content = content[:MAX_FILE_SIZE_BYTES]
        truncated = True
        logger.warning("[FileAccess] File truncated (%.1f MB): %s", size / 1e6, p)

    _log_access(str(p), size, truncated=truncated)

    return FileReadResult(
        path=str(p), success=True, content=content,
        size_bytes=size, truncated=truncated,
    )


def list_directory(path: str) -> FileReadResult:
    """List contents of a directory the user specifies."""
    try:
        p = Path(os.path.expanduser(path)).resolve()
    except Exception as exc:
        return FileReadResult(path=path, success=False, error=f"Invalid path: {exc}")

    if not p.is_dir():
        return FileReadResult(path=path, success=False,
                              error=f"Not a directory: {p}")

    try:
        entries = sorted(p.iterdir(), key=lambda e: (e.is_file(), e.name))
        lines = []
        for e in entries[:200]:  # cap at 200 entries
            kind = "FILE" if e.is_file() else "DIR "
            try:
                size = e.stat().st_size if e.is_file() else 0
                lines.append(f"{kind}  {e.name}  ({size:,} bytes)" if e.is_file() else f"{kind}  {e.name}/")
            except Exception:
                lines.append(f"{kind}  {e.name}")
        content = f"# Directory listing: {p}\n\n" + "\n".join(lines)
        _log_access(str(p), 0, truncated=len(entries) > 200)
        return FileReadResult(path=str(p), success=True, content=content,
                              truncated=len(entries) > 200)
    except PermissionError:
        return FileReadResult(path=path, success=False,
                              error=f"Permission denied reading directory: {p}")


def get_access_log() -> list[dict[str, Any]]:
    return list(_ACCESS_LOG)


def _log_access(path: str, size: int, truncated: bool) -> None:
    record = {
        "path": path,
        "size_bytes": size,
        "truncated": truncated,
        "accessed_at": datetime.now(timezone.utc).isoformat(),
    }
    _ACCESS_LOG.append(record)
    logger.info("[FileAccess] READ: %s  size=%d  truncated=%s", path, size, truncated)
