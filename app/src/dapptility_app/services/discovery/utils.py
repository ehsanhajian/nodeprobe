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


def probe_rpc(url: str, *, timeout: float = 5.0) -> bool:
    """Check that an RPC URL resolves to a public IP and responds to a JSON-RPC call."""
    import ipaddress
    import socket

    import httpx

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    try:
        ip_str = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)[0][4][0]
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return False
    except (socket.gaierror, IndexError, ValueError):
        return False

    try:
        resp = httpx.post(
            url,
            json={"jsonrpc": "2.0", "method": "net_version", "params": [], "id": 1},
            timeout=timeout,
            follow_redirects=True,
        )
        if resp.status_code >= 500:
            return False
        ct = (resp.headers.get("content-type") or "").lower()
        if "json" in ct:
            return True
        if resp.status_code < 400:
            return True
        return False
    except (httpx.HTTPError, Exception):
        return False
