from __future__ import annotations

from typing import Any

import httpx

from dapptility_app.config import settings
from dapptility_app.services.discovery.utils import RpcCandidate, normalize_rpc_url


def fetch_chainlist_candidates(
    *,
    client: httpx.Client | None = None,
    url: str | None = None,
) -> list[RpcCandidate]:
    source_url = url or settings.chainlist_url
    owns_client = client is None
    http = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        response = http.get(source_url)
        response.raise_for_status()
        chains: list[dict[str, Any]] = response.json()
    finally:
        if owns_client:
            http.close()

    candidates: list[RpcCandidate] = []
    seen: set[str] = set()

    for chain in chains:
        chain_id = chain.get("chainId")
        if chain_id is None:
            continue
        name = str(chain.get("name") or f"Chain {chain_id}")
        short_name = chain.get("shortName")
        info_url = chain.get("infoURL")
        testnet = bool(
            chain.get("testnet")
            or "test" in name.lower()
            or (short_name and "test" in str(short_name).lower())
        )
        rpc_entries = chain.get("rpc") or []
        for entry in rpc_entries:
            rpc_url = _rpc_url_from_entry(entry)
            if not rpc_url:
                continue
            normalized = normalize_rpc_url(rpc_url)
            if normalized in seen:
                continue
            seen.add(normalized)
            candidates.append(
                RpcCandidate(
                    chain_id=int(chain_id),
                    chain_name=name,
                    short_name=str(short_name) if short_name else None,
                    website=str(info_url) if info_url else None,
                    rpc_url=rpc_url,
                    is_testnet=testnet,
                )
            )
    return candidates


def _rpc_url_from_entry(entry: Any) -> str | None:
    if isinstance(entry, str):
        url = entry.strip()
    elif isinstance(entry, dict):
        if entry.get("tracking") == "yes":
            return None
        url = str(entry.get("url") or "").strip()
    else:
        return None
    if not url.startswith(("http://", "https://")):
        return None
    if "${" in url:
        return None
    return url
