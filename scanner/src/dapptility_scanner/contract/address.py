"""Address helpers for contract scans."""

from __future__ import annotations

import re

_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def normalize_address(value: str) -> str:
    text = (value or "").strip()
    if not _ADDR_RE.match(text):
        raise ValueError(f"Invalid EVM address: {value!r}")
    return text.lower()


def is_empty_code(code: str | None) -> bool:
    if code is None:
        return True
    cleaned = code.strip().lower()
    return cleaned in {"", "0x", "0x0"}
