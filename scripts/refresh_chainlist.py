#!/usr/bin/env python3
"""Regenerate Nodeprobe's compact EVM chain-name registry.

The authoritative source is ethereum-lists/chains via chainid.network.
Only display metadata is stored; unknown chain IDs remain scannable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_SOURCE = "https://chainid.network/chains.json"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "scanner"
    / "src"
    / "nodeprobe"
    / "data"
    / "chains_mini.json"
)

_TESTNET_PATTERN = re.compile(
    r"(?:"
    r"\btestnet\b|\btest network\b|\btest chain\b|\bdevnet\b|"
    r"\bsepolia\b|\bgoerli\b|\bgörli\b|\bholesky\b|"
    r"\brinkeby\b|\bropsten\b|\bkovan\b|\bmumbai\b|"
    r"\bamoy\b|\bfuji\b|\bchiado\b|\bkotti\b"
    r")",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="Source URL or local JSON path (default: chainid.network/chains.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output registry path",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when regenerated content differs; do not write",
    )
    return parser.parse_args()


def load_json(source: str) -> Any:
    if source.startswith(("https://", "http://")):
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "Nodeprobe-Chainlist-Refresh/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.load(response)
    with Path(source).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_existing(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Existing registry must be an object: {path}")
    return payload


def infer_testnet(name: str) -> bool:
    return bool(_TESTNET_PATTERN.search(name))


def build_registry(
    payload: Any,
    *,
    existing: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, list):
        raise ValueError("Chainlist source must be a JSON array")

    previous = existing or {}
    records: dict[int, dict[str, Any]] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("Every Chainlist entry must be an object")
        chain_id = item.get("chainId")
        name = item.get("name")
        if not isinstance(chain_id, int) or chain_id < 0:
            raise ValueError(f"Invalid chainId: {chain_id!r}")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Missing name for chainId {chain_id}")
        if chain_id in records:
            raise ValueError(f"Duplicate chainId: {chain_id}")

        short_name = item.get("shortName")
        if not isinstance(short_name, str) or not short_name.strip():
            short_name = f"chain-{chain_id}"

        old = previous.get(str(chain_id)) or {}
        old_testnet = old.get("is_testnet")
        is_testnet = (
            old_testnet
            if isinstance(old_testnet, bool)
            else infer_testnet(name)
        )
        records[chain_id] = {
            "name": name.strip(),
            "short_name": short_name.strip(),
            "is_testnet": is_testnet,
        }

    return {str(chain_id): records[chain_id] for chain_id in sorted(records)}


def serialize_registry(registry: dict[str, dict[str, Any]]) -> str:
    return json.dumps(
        registry,
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


def validate_registry(registry: dict[str, dict[str, Any]]) -> None:
    """Reject obviously truncated or poisoned upstream snapshots."""
    if len(registry) < 2_000:
        raise ValueError(
            f"Refusing suspiciously small Chainlist snapshot: {len(registry)} entries"
        )
    ethereum = registry.get("1")
    if not ethereum or ethereum.get("name") != "Ethereum Mainnet":
        raise ValueError("Chainlist snapshot is missing the canonical Ethereum entry")


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    args = parse_args()
    existing = load_existing(args.output)
    payload = load_json(args.source)
    registry = build_registry(payload, existing=existing)
    validate_registry(registry)
    content = serialize_registry(registry)
    current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""

    changed = content != current
    print(
        f"Chainlist entries: {len(registry)}; "
        f"output: {args.output}; changed: {str(changed).lower()}"
    )
    if args.check:
        return 1 if changed else 0
    if changed:
        write_atomic(args.output, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
