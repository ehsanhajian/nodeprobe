"""Sourcify verified-source enrichment (read-only HTTP)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

SOURCIFY_FILES_URL = (
    "https://sourcify.dev/server/v2/contract/{chain_id}/{address}"
)


@dataclass
class SourcifyMatch:
    status: str  # exact_match | match | partial | not_found | error
    chain_id: int
    address: str
    abi: list[dict[str, Any]] | None = None
    contract_name: str | None = None
    compiler: str | None = None
    raw: dict[str, Any] | None = None


def fetch_sourcify(
    chain_id: int,
    address: str,
    *,
    client: httpx.Client | None = None,
    timeout: float = 15.0,
) -> SourcifyMatch:
    url = SOURCIFY_FILES_URL.format(chain_id=chain_id, address=address)
    owns = client is None
    http = client or httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "DapptilityScanner/0.1 (+https://dapptility.com)"},
    )
    try:
        response = http.get(url, params={"fields": "abi,metadata,compilation"})
        if response.status_code == 404:
            return SourcifyMatch(
                status="not_found",
                chain_id=chain_id,
                address=address,
            )
        if response.status_code >= 400:
            return SourcifyMatch(
                status="error",
                chain_id=chain_id,
                address=address,
                raw={"status_code": response.status_code, "body": response.text[:500]},
            )
        data = response.json()
        # v2 responses vary; normalize best-effort
        match_status = str(data.get("match") or data.get("status") or "match").lower()
        if match_status in {"exact_match", "perfect"}:
            status = "exact_match"
        elif match_status in {"match", "partial_match", "partial"}:
            status = "partial" if "partial" in match_status else "match"
        else:
            status = match_status or "match"

        abi = data.get("abi")
        if abi is None and isinstance(data.get("metadata"), dict):
            output = data["metadata"].get("output") or {}
            abi = output.get("abi")
        compilation = data.get("compilation") or {}
        name = (
            data.get("name")
            or compilation.get("name")
            or (data.get("metadata") or {}).get("settings", {}).get("compilationTarget")
        )
        if isinstance(name, dict) and name:
            name = next(iter(name.values()), None)
        compiler = compilation.get("compiler") or (data.get("metadata") or {}).get(
            "compiler", {}
        ).get("version")
        return SourcifyMatch(
            status=status,
            chain_id=chain_id,
            address=address,
            abi=abi if isinstance(abi, list) else None,
            contract_name=str(name) if name else None,
            compiler=str(compiler) if compiler else None,
            raw={"keys": sorted(data.keys())},
        )
    except Exception as exc:  # noqa: BLE001
        return SourcifyMatch(
            status="error",
            chain_id=chain_id,
            address=address,
            raw={"error": str(exc)},
        )
    finally:
        if owns:
            http.close()
