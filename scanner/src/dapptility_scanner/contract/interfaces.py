"""Common interface hints from selectors or ABI."""

from __future__ import annotations

from typing import Any

# function selector -> interface label
SELECTOR_HINTS: dict[str, str] = {
    # ERC-20
    "0x70a08231": "ERC-20",  # balanceOf
    "0xa9059cbb": "ERC-20",  # transfer
    "0x23b872dd": "ERC-20",  # transferFrom
    "0x095ea7b3": "ERC-20",  # approve
    "0x18160ddd": "ERC-20",  # totalSupply
    # ERC-721
    "0x6352211e": "ERC-721",  # ownerOf
    "0x42842e0e": "ERC-721",  # safeTransferFrom(address,address,uint256)
    "0xb88d4fde": "ERC-721",  # safeTransferFrom(+data)
    # ERC-1155
    "0xf242432a": "ERC-1155",  # safeTransferFrom
    "0x2eb2c2d6": "ERC-1155",  # safeBatchTransferFrom
    # Ownable
    "0x8da5cb5b": "Ownable",  # owner()
    "0xf2fde38b": "Ownable",  # transferOwnership
    "0x715018a6": "Ownable",  # renounceOwnership
    # AccessControl
    "0x91d14854": "AccessControl",  # hasRole
    "0x2f2ff15d": "AccessControl",  # grantRole
    "0xd547741f": "AccessControl",  # revokeRole
    # UUPS
    "0x3659cfe6": "UUPS",  # upgradeTo
    "0x4f1ef286": "UUPS",  # upgradeToAndCall
    # Transparent-ish
    "0x8f283970": "TransparentProxy",  # changeAdmin
    "0xf851a440": "TransparentProxy",  # admin()
    "0x5c60da1b": "TransparentProxy",  # implementation()
}


def interfaces_from_selectors(selectors: set[str]) -> list[str]:
    found: set[str] = set()
    for sel in selectors:
        label = SELECTOR_HINTS.get(sel.lower())
        if label:
            found.add(label)
    return sorted(found)


def interfaces_from_abi(abi: list[dict[str, Any]] | None) -> list[str]:
    if not abi:
        return []
    names = {
        item.get("name", "").lower()
        for item in abi
        if isinstance(item, dict) and item.get("type") == "function"
    }
    found: set[str] = set()
    if {"balanceof", "transfer", "approve"} & names:
        found.add("ERC-20")
    if {"ownerof", "safetransferfrom"} & names:
        found.add("ERC-721")
    if {"safebatchtransferfrom"} & names:
        found.add("ERC-1155")
    if {"owner", "transferownership"} & names:
        found.add("Ownable")
    if {"hasrole", "grantrole"} & names:
        found.add("AccessControl")
    if {"upgradeto", "upgradetoandcall"} & names:
        found.add("UUPS")
    if {"implementation", "admin", "changeadmin"} & names:
        found.add("TransparentProxy")
    return sorted(found)
