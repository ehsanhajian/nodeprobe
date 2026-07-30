"""Bytecode opcode heuristics (presence-only, no symbolic execution)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpcodeHit:
    name: str
    opcode: str
    count: int


# Single-byte opcodes of interest. Presence is informational / low-severity —
# many legitimate contracts use DELEGATECALL (proxies) and rarely SELFDESTRUCT.
_INTERESTING = {
    "f4": "DELEGATECALL",
    "ff": "SELFDESTRUCT",
    "f1": "CALL",
    "f2": "CALLCODE",
    "55": "SSTORE",
}


def analyze_bytecode(code_hex: str) -> list[OpcodeHit]:
    raw = code_hex.lower().removeprefix("0x")
    if len(raw) % 2:
        raw = raw[:-1]
    counts: dict[str, int] = {k: 0 for k in _INTERESTING}
    i = 0
    while i < len(raw) - 1:
        op = raw[i : i + 2]
        # PUSH1..PUSH32 skip immediate data
        try:
            op_int = int(op, 16)
        except ValueError:
            i += 2
            continue
        if 0x60 <= op_int <= 0x7F:
            n = op_int - 0x5F
            i += 2 + (n * 2)
            continue
        if op in counts:
            counts[op] += 1
        i += 2
    return [
        OpcodeHit(name=_INTERESTING[op], opcode="0x" + op, count=count)
        for op, count in counts.items()
        if count > 0
    ]


def extract_selectors(code_hex: str) -> set[str]:
    """Best-effort 4-byte selector harvest from PUSH4 immediates."""
    raw = code_hex.lower().removeprefix("0x")
    selectors: set[str] = set()
    i = 0
    while i < len(raw) - 1:
        op = raw[i : i + 2]
        try:
            op_int = int(op, 16)
        except ValueError:
            i += 2
            continue
        if op_int == 0x63:  # PUSH4
            sel = raw[i + 2 : i + 10]
            if len(sel) == 8:
                selectors.add("0x" + sel)
            i += 10
            continue
        if 0x60 <= op_int <= 0x7F:
            n = op_int - 0x5F
            i += 2 + (n * 2)
            continue
        i += 2
    return selectors
