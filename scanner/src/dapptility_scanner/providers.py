"""Third-party RPC provider detection for outbound safety."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProviderMatch:
    provider: str
    reason: str


PROVIDER_HOST_SUFFIXES: dict[str, tuple[str, ...]] = {
    "Alchemy": ("alchemy.com", "alchemyapi.io"),
    "Ankr": ("ankr.com",),
    "Infura": ("infura.io",),
    "QuickNode": ("quiknode.pro", "quicknode.com"),
    "LlamaNodes": ("llamarpc.com",),
    "BlastAPI": ("blastapi.io",),
    "PublicNode": ("publicnode.com",),
    "DRPC": ("drpc.org",),
}


def detect_provider(url: str) -> ProviderMatch | None:
    hostname = (urlparse(url).hostname or "").lower()
    if not hostname:
        return None
    for provider, suffixes in PROVIDER_HOST_SUFFIXES.items():
        for suffix in suffixes:
            if hostname == suffix or hostname.endswith("." + suffix):
                return ProviderMatch(
                    provider=provider,
                    reason=(
                        f"Endpoint hostname '{hostname}' matches known "
                        f"{provider} infrastructure"
                    ),
                )
    return None
