"""Proxy pattern detection from bytecode and storage slots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

# EIP-1967 implementation slot = bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
# EIP-1967 admin slot
EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
# EIP-1967 beacon slot
EIP1967_BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)
# EIP-1822 PROXIABLE slot = keccak256("PROXIABLE")
EIP1822_PROXIABLE_SLOT = (
    "0xc5f16f0fcc639fa48a6944975350c47a61a78878520df88e849511b813ca39a7"
)

# EIP-1167 minimal proxy runtime bytecode pattern
_EIP1167_PREFIX = "363d3d373d3d3d363d73"
_EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"


@dataclass
class ProxyHint:
    kind: str
    implementation: str | None = None
    admin: str | None = None
    beacon: str | None = None
    evidence: dict[str, Any] | None = None


def _slot_to_address(value: str | None) -> str | None:
    if not value or value in {"0x", "0x0"}:
        return None
    hexdata = value[2:] if value.startswith("0x") else value
    hexdata = hexdata.rjust(64, "0")[-40:]
    if int(hexdata, 16) == 0:
        return None
    return "0x" + hexdata.lower()


def detect_eip1167(code_hex: str) -> ProxyHint | None:
    raw = code_hex.lower().removeprefix("0x")
    idx = raw.find(_EIP1167_PREFIX)
    if idx < 0:
        return None
    start = idx + len(_EIP1167_PREFIX)
    impl = raw[start : start + 40]
    if len(impl) != 40:
        return None
    # Prefer exact suffix match when present
    rest = raw[start + 40 :]
    if not rest.startswith(_EIP1167_SUFFIX) and _EIP1167_SUFFIX not in rest[:64]:
        # Still accept common variants that keep the 20-byte address placement
        if len(impl) != 40:
            return None
    return ProxyHint(
        kind="eip1167",
        implementation="0x" + impl,
        evidence={"pattern": "EIP-1167", "bytecode_offset": idx},
    )


def detect_proxies_from_slots(
    *,
    get_storage: Callable[[str], str | None],
) -> list[ProxyHint]:
    hints: list[ProxyHint] = []

    impl = _slot_to_address(get_storage(EIP1967_IMPLEMENTATION_SLOT))
    admin = _slot_to_address(get_storage(EIP1967_ADMIN_SLOT))
    beacon = _slot_to_address(get_storage(EIP1967_BEACON_SLOT))
    if impl or admin or beacon:
        hints.append(
            ProxyHint(
                kind="eip1967",
                implementation=impl,
                admin=admin,
                beacon=beacon,
                evidence={
                    "implementation_slot": EIP1967_IMPLEMENTATION_SLOT,
                    "admin_slot": EIP1967_ADMIN_SLOT,
                    "beacon_slot": EIP1967_BEACON_SLOT,
                },
            )
        )

    proxiable = _slot_to_address(get_storage(EIP1822_PROXIABLE_SLOT))
    if proxiable:
        hints.append(
            ProxyHint(
                kind="eip1822",
                implementation=proxiable,
                evidence={"proxiable_slot": EIP1822_PROXIABLE_SLOT},
            )
        )
    return hints
