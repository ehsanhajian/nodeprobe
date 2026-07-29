from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class RpcCandidate:
    chain_id: int
    chain_name: str
    short_name: str | None
    website: str | None
    rpc_url: str
    is_testnet: bool
    source: str = "chainlist"


def normalize_rpc_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path.rstrip("/") or ""
    scheme = parsed.scheme.lower()
    netloc = host
    if port and port not in {80, 443}:
        netloc = f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


def extract_domain(url: str) -> str | None:
    host = urlparse(url).hostname
    return host.lower() if host else None
